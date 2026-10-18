// Package mcpserver exposes whodis lookups as a Model Context Protocol server
// over stateless Streamable HTTP.
package mcpserver

import (
	"context"
	"crypto/subtle"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"gitfield.org/fsky/whodis/internal/forwarded"
	"gitfield.org/fsky/whodis/internal/lookup"
)

// Path is where the MCP endpoint is mounted. Path + "/<token>" authenticates
// clients that can only be configured with a URL, such as claude.ai and
// ChatGPT; other clients can send "Authorization: Bearer <token>" instead.
const Path = "/mcp"

// Config controls access to the MCP endpoint.
type Config struct {
	// Limiter admits cache misses of requests without a valid token, per
	// client IP. Nil disables rate limiting.
	Limiter *lookup.RateLimiter
	// Tokens authenticate clients. Authenticated requests are never rate
	// limited.
	Tokens []string
	// RequireToken rejects requests without a valid token.
	RequireToken      bool
	TrustProxyHeaders bool
	// WebUI adds a link to the web UI rendering of each lookup.
	WebUI bool
}

// Server serves the MCP endpoint.
type Server struct {
	service *lookup.Service
	config  Config
	tokens  [][]byte
	impl    *mcp.Implementation
	schemas *mcp.SchemaCache
	handler http.Handler
}

type callKey struct{}

// call is the per-request state the tool handler needs.
type call struct {
	limiter *lookup.RateLimiter
	client  string
	// baseURL is the public origin of the web UI, or empty when it is disabled.
	baseURL string
}

// New returns a Server that performs lookups through service.
func New(service *lookup.Service, config Config) *Server {
	s := &Server{
		service: service,
		config:  config,
		impl:    &mcp.Implementation{Name: "whodis", Title: "who dis?", Version: version()},
		schemas: mcp.NewSchemaCache(),
	}
	for _, token := range config.Tokens {
		s.tokens = append(s.tokens, []byte(token))
	}
	s.handler = mcp.NewStreamableHTTPHandler(s.newServer, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
		// The SDK rejects requests whose Host is not loopback when the
		// listener is, which is exactly how a same-host reverse proxy connects.
		// The endpoint only serves public registration data.
		DisableLocalhostProtection: true,
		CrossOriginProtection:      http.NewCrossOriginProtection(),
		MaxRequestBodyBytes:        64 << 10,
	})
	return s
}

// Register mounts the endpoint and its token-in-path variant on mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.Handle(Path, s)
	mux.Handle(Path+"/{token}", s)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authenticated := false
	if pathToken := r.PathValue("token"); pathToken != "" {
		// An unknown token path is indistinguishable from any other missing page.
		if !s.validToken(pathToken) {
			http.NotFound(w, r)
			return
		}
		authenticated = true
	} else if headerToken, ok := bearerToken(r); ok && len(s.tokens) > 0 {
		if !s.validToken(headerToken) {
			unauthorized(w)
			return
		}
		authenticated = true
	}
	if !authenticated && s.config.RequireToken {
		unauthorized(w)
		return
	}

	c := call{client: forwarded.ClientIP(r, s.config.TrustProxyHeaders)}
	if !authenticated {
		c.limiter = s.config.Limiter
	}
	if s.config.WebUI {
		c.baseURL = forwarded.BaseURL(r, s.config.TrustProxyHeaders)
	}
	s.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callKey{}, c)))
}

// newServer builds the MCP server for one stateless request, binding the
// request's rate-limit and link state into the tool handler.
func (s *Server) newServer(r *http.Request) *mcp.Server {
	c, _ := r.Context().Value(callKey{}).(call)
	server := mcp.NewServer(s.impl, &mcp.ServerOptions{SchemaCache: s.schemas})
	mcp.AddTool(server, lookupTool, func(ctx context.Context, _ *mcp.CallToolRequest, args lookupArgs) (*mcp.CallToolResult, any, error) {
		return s.lookup(ctx, c, args), nil, nil
	})
	return server
}

// validToken compares token against every configured token in constant time.
func (s *Server) validToken(token string) bool {
	match := 0
	for _, candidate := range s.tokens {
		match |= subtle.ConstantTimeCompare([]byte(token), candidate)
	}
	return match == 1
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="whodis"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}
