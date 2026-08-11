package rdap

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const (
	defaultOperationTimeout = 30 * time.Second
	defaultIdleTimeout      = 10 * time.Second
	defaultMaxHops          = 5
	defaultMaxRedirects     = 5
	defaultMaxQueryBytes    = 4 * 1024
	defaultMaxResponseBytes = 2 * 1024 * 1024
)

// Endpoint identifies an HTTP(S) service for endpoint-policy decisions.
type Endpoint struct {
	// Host is the URL hostname as advertised or supplied by the caller.
	Host string
	// Port is the effective URL port (80 for HTTP or 443 for HTTPS when the
	// URL does not specify one).
	Port uint16
}

// Response contains the untouched logical HTTP response returned by an RDAP
// service. Body is never reformatted or decoded by the client.
type Response struct {
	// URL is the final URL after redirects.
	URL string
	// Duration is the time spent completing this logical HTTP exchange,
	// including redirects, DNS, connection setup, and reading the body.
	Duration time.Duration
	// Error is the error encountered while completing the exchange, if any.
	// The same error is also returned by Query or Lookup.
	Error error
	// StatusCode is the upstream HTTP status code.
	StatusCode int
	// Header is a clone of the upstream response headers.
	Header http.Header
	// Body contains the exact bytes read from the logical response body.
	Body []byte
	// Referral is the next recognized RDAP endpoint, if any.
	Referral string
	// Truncated reports that Body reached MaxResponseBytes.
	Truncated bool
}

// Result contains a normalized resource query and every completed lookup hop.
type Result struct {
	// Query is the normalized resource passed to automatic lookup.
	Query string
	// Responses contains completed exchanges in traversal order. It may be
	// non-empty when Lookup also returns an error from a later hop.
	Responses []Response
	// Response is the last retained response. Deprecated: use Responses.
	Response Response
}

// Limits bounds HTTP operations and in-memory responses. Zero-valued fields
// passed to WithLimits retain their defaults.
type Limits struct {
	OperationTimeout time.Duration
	IdleTimeout      time.Duration
	MaxHops          int
	MaxRedirects     int
	MaxQueryBytes    int
	MaxResponseBytes int64
}

// Resolver is implemented by net.Resolver.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer is implemented by net.Dialer. Addresses passed to a Dialer contain a
// validated IP literal rather than an unresolved hostname.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// EndpointPolicy decides whether a service may be contacted at a resolved
// address. It is evaluated for every resolved address, redirect, and referral.
type EndpointPolicy func(endpoint Endpoint, address netip.Addr) bool

// Option configures a Client.
type Option func(*Client)

// Client performs direct and automatically discovered RDAP requests. Clients
// are safe for concurrent use after construction.
type Client struct {
	resolver     Resolver
	dialer       Dialer
	directPolicy EndpointPolicy
	lookupPolicy EndpointPolicy
	limits       Limits
}

// NewClient returns an RDAP client with bounded defaults. Direct Query calls
// may contact any HTTP(S) address. Lookup only contacts publicly routable
// services unless its policy is replaced.
func NewClient(options ...Option) *Client {
	c := &Client{
		resolver:     net.DefaultResolver,
		dialer:       &net.Dialer{},
		directPolicy: AllowAnyEndpoint,
		lookupPolicy: PublicRDAPEndpoint,
		limits: Limits{
			OperationTimeout: defaultOperationTimeout,
			IdleTimeout:      defaultIdleTimeout,
			MaxHops:          defaultMaxHops,
			MaxRedirects:     defaultMaxRedirects,
			MaxQueryBytes:    defaultMaxQueryBytes,
			MaxResponseBytes: defaultMaxResponseBytes,
		},
	}
	for _, option := range options {
		if option != nil {
			option(c)
		}
	}
	return c
}

// WithResolver replaces DNS resolution for all requests.
func WithResolver(resolver Resolver) Option {
	return func(c *Client) {
		if resolver != nil {
			c.resolver = resolver
		}
	}
}

// WithDialer replaces network dialing for all requests.
func WithDialer(dialer Dialer) Option {
	return func(c *Client) {
		if dialer != nil {
			c.dialer = dialer
		}
	}
}

// WithDirectEndpointPolicy replaces the policy used by Query.
func WithDirectEndpointPolicy(policy EndpointPolicy) Option {
	return func(c *Client) {
		if policy != nil {
			c.directPolicy = policy
		}
	}
}

// WithLookupEndpointPolicy replaces the policy used by Lookup and its
// redirects and referrals.
func WithLookupEndpointPolicy(policy EndpointPolicy) Option {
	return func(c *Client) {
		if policy != nil {
			c.lookupPolicy = policy
		}
	}
}

// WithLimits replaces non-zero default limits.
func WithLimits(limits Limits) Option {
	return func(c *Client) {
		if limits.OperationTimeout > 0 {
			c.limits.OperationTimeout = limits.OperationTimeout
		}
		if limits.IdleTimeout > 0 {
			c.limits.IdleTimeout = limits.IdleTimeout
		}
		if limits.MaxHops > 0 {
			c.limits.MaxHops = limits.MaxHops
		}
		if limits.MaxRedirects > 0 {
			c.limits.MaxRedirects = limits.MaxRedirects
		}
		if limits.MaxQueryBytes > 0 {
			c.limits.MaxQueryBytes = limits.MaxQueryBytes
		}
		if limits.MaxResponseBytes > 0 {
			c.limits.MaxResponseBytes = limits.MaxResponseBytes
		}
	}
}

func (c *Client) withOperationTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.limits.OperationTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.limits.OperationTimeout)
}
