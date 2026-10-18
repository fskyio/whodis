package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"gitfield.org/fsky/whodis/internal/lookup"
)

// maxBodyBytes caps each hop body sent to the model. Typical RDAP and WHOIS
// responses are a few KiB; the cap only bounds outliers such as RIPE aut-num
// objects with full routing policy.
const maxBodyBytes = 32 << 10

// omittedRDAPMembers are dropped from RDAP documents unless raw output is
// requested. They carry terms of service, navigation links and extension
// identifiers rather than registration data.
var omittedRDAPMembers = map[string]bool{"notices": true, "links": true, "rdapConformance": true}

type lookupArgs struct {
	Query    string `json:"query"`
	Protocol string `json:"protocol"`
	Raw      bool   `json:"raw"`
}

var lookupTool = &mcp.Tool{
	Name:  "lookup",
	Title: "Registration data lookup",
	Description: `Look up registration data for a domain name, TLD, IP address, CIDR prefix, autonomous system number (e.g. AS15169) or registry handle, using RDAP and WHOIS.

Auto mode queries RDAP, follows registry-to-registrar referrals, and falls back to WHOIS only when RDAP is unavailable. Prefer it: WHOIS output is unstructured, and some registries return very large WHOIS records.

The result is JSON. "hops" lists every server queried, in order. RDAP bodies are JSON objects with the notices, links and rdapConformance members removed (set raw to keep them); WHOIS bodies are text. A body over 32 KiB is cut off and marked "truncated", and a body identical to an earlier hop's is replaced by "same_as_hop". "error" summarizes a failed lookup and "notice" explains a WHOIS fallback. Results can come from a cache; "fetched_at" is when the data was retrieved. "web_url", when present, opens the complete result in a browser.`,
	InputSchema: &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"query": {
				Type:        "string",
				Description: "Domain name, TLD, IPv4 or IPv6 address, CIDR prefix, AS number, or registry handle.",
				MinLength:   jsonschema.Ptr(1),
				MaxLength:   jsonschema.Ptr(lookup.MaxQueryBytes),
			},
			"protocol": {
				Type:        "string",
				Description: "auto (RDAP with WHOIS fallback), rdap, or whois.",
				Enum:        []any{string(lookup.Auto), string(lookup.RDAP), string(lookup.WHOIS)},
				Default:     json.RawMessage(`"auto"`),
			},
			"raw": {
				Type:        "boolean",
				Description: "Keep the RDAP notices, links and rdapConformance members.",
				Default:     json.RawMessage(`false`),
			},
		},
		Required: []string{"query"},
	},
	Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		IdempotentHint:  true,
		DestructiveHint: jsonschema.Ptr(false),
		OpenWorldHint:   jsonschema.Ptr(true),
	},
}

type envelope struct {
	Query     string `json:"query"`
	Protocol  string `json:"protocol"`
	FetchedAt string `json:"fetched_at"`
	CacheHit  bool   `json:"cache_hit"`
	Notice    string `json:"notice,omitempty"`
	Error     string `json:"error,omitempty"`
	WebURL    string `json:"web_url,omitempty"`
	Hops      []hop  `json:"hops"`
}

type hop struct {
	Protocol   string `json:"protocol"`
	Source     string `json:"source,omitempty"`
	Status     int    `json:"status,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	Warning    string `json:"warning,omitempty"`
	SameAsHop  int    `json:"same_as_hop,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	// BodyBytes is the size of a truncated body before it was cut off.
	BodyBytes int `json:"body_bytes,omitempty"`
	// Body is an RDAP JSON document, or a JSON string for WHOIS text and
	// truncated or invalid RDAP bodies.
	Body json.RawMessage `json:"body,omitempty"`
}

func (s *Server) lookup(ctx context.Context, c call, args lookupArgs) *mcp.CallToolResult {
	protocol, err := lookup.ParseProtocol(args.Protocol)
	if err != nil {
		return errorResult(err.Error())
	}
	query := strings.TrimSpace(args.Query)
	outcome, err := s.service.Lookup(ctx, lookup.Request{Query: query, Protocol: protocol, Limiter: c.limiter, Client: c.client})
	if err != nil {
		return errorResult(describeError(ctx, err))
	}
	text, err := marshal(newEnvelope(query, protocol, outcome, args.Raw, c.baseURL))
	if err != nil {
		return errorResult("encode result: " + err.Error())
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(text)}}}
}

func describeError(ctx context.Context, err error) string {
	var rateLimitErr *lookup.RateLimitError
	switch {
	case errors.As(err, &rateLimitErr):
		return fmt.Sprintf("Rate limit exceeded; retry in %d seconds.", max(1, int(math.Ceil(rateLimitErr.RetryAfter.Seconds()))))
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
		return "The lookup timed out."
	default:
		return err.Error()
	}
}

func errorResult(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: message}}}
}

func newEnvelope(query string, protocol lookup.Protocol, outcome lookup.Outcome, raw bool, baseURL string) envelope {
	result := outcome.Result
	output := envelope{
		Query:     query,
		Protocol:  string(protocol),
		FetchedAt: outcome.FetchedAt.UTC().Format(time.RFC3339),
		CacheHit:  outcome.CacheHit,
		Notice:    result.Notice,
		Error:     result.Error,
		Hops:      make([]hop, 0, len(result.Items)),
	}
	if baseURL != "" {
		output.WebURL = baseURL + "/lookup?" + url.Values{"q": {query}, "protocol": {string(protocol)}}.Encode()
	}
	for _, item := range result.Items {
		entry := hop{
			Protocol:   string(item.Protocol),
			Source:     item.Source,
			Status:     item.StatusCode,
			DurationMS: item.Duration.Milliseconds(),
			Error:      item.Error,
			Warning:    item.Warning,
		}
		entry.Body, entry.Truncated, entry.BodyBytes = encodeBody(item, raw)
		for index, earlier := range output.Hops {
			if entry.Body != nil && bytes.Equal(earlier.Body, entry.Body) {
				entry.SameAsHop = index + 1
				entry.Body, entry.Truncated, entry.BodyBytes = nil, false, 0
				break
			}
		}
		output.Hops = append(output.Hops, entry)
	}
	return output
}

// encodeBody returns the JSON encoding of an item's body, whether it was
// truncated, and its size before truncation.
func encodeBody(item lookup.Item, raw bool) (json.RawMessage, bool, int) {
	if len(item.Body) == 0 {
		return nil, false, 0
	}
	if item.Protocol == lookup.RDAP && item.JSON {
		document := item.Body
		if !raw {
			if trimmed, err := trimRDAP(item.Body); err == nil {
				document = trimmed
			}
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, document); err == nil {
			if compact.Len() <= maxBodyBytes {
				return compact.Bytes(), false, 0
			}
			return quote(truncate(compact.String())), true, compact.Len()
		}
	}
	text := strings.ToValidUTF8(string(item.Body), "\uFFFD")
	if len(text) <= maxBodyBytes {
		return quote(text), false, 0
	}
	return quote(truncate(text)), true, len(text)
}

func trimRDAP(body []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	return marshal(stripRDAPMembers(document))
}

func stripRDAPMembers(value any) any {
	switch value := value.(type) {
	case map[string]any:
		for key, member := range value {
			if omittedRDAPMembers[key] {
				delete(value, key)
				continue
			}
			value[key] = stripRDAPMembers(member)
		}
	case []any:
		for index, element := range value {
			value[index] = stripRDAPMembers(element)
		}
	}
	return value
}

// truncate cuts text to maxBodyBytes without splitting a UTF-8 sequence.
func truncate(text string) string {
	cut := maxBodyBytes
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

func quote(text string) json.RawMessage {
	encoded, _ := marshal(text)
	return encoded
}

// marshal encodes value as compact JSON without escaping HTML characters,
// which would only cost tokens.
func marshal(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}
