package whois

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const defaultPort uint16 = 43

const (
	defaultOperationTimeout = 30 * time.Second
	defaultIdleTimeout      = 10 * time.Second
	defaultMaxHops          = 5
	defaultMaxQueryBytes    = 4 * 1024
	defaultMaxResponseBytes = 2 * 1024 * 1024
)

// Endpoint identifies a WHOIS-compatible TCP service. A zero Port means 43.
type Endpoint struct {
	// Host is a DNS name, IPv4 address, or IPv6 address. Brackets around an
	// IPv6 literal are accepted but are not required.
	Host string
	// Port is the TCP port. Zero selects the standard WHOIS port, 43.
	Port uint16
}

// String returns the endpoint in host:port form.
func (e Endpoint) String() string {
	port := e.Port
	if port == 0 {
		port = defaultPort
	}
	host := e.Host
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// Response describes one request and response in a WHOIS lookup.
// Body contains the bytes received from the server without decoding or
// newline normalization.
type Response struct {
	// Endpoint is the normalized server that produced this response.
	Endpoint Endpoint
	// Duration is the time spent completing this logical TCP exchange,
	// including DNS, connection setup, writing the query, and reading the body.
	Duration time.Duration
	// Error is the error encountered while completing the exchange, if any.
	// The same error is also returned by Query or Lookup.
	Error error
	// Query is the exact query sent before the terminating CRLF.
	Query string
	// Body contains the bytes received before EOF or an error.
	Body []byte
	// Referral is the next recognized WHOIS or RWhois endpoint, if any.
	Referral *Endpoint
	// Truncated reports that Body reached MaxResponseBytes.
	Truncated bool
}

// Result contains the normalized query and every completed lookup hop.
type Result struct {
	// Query is the normalized resource passed to automatic lookup.
	Query string
	// Responses contains completed exchanges in traversal order. It may be
	// non-empty when Lookup also returns an error from a later hop.
	Responses []Response
}

// Limits bounds network operations and in-memory responses. Zero-valued
// fields passed to WithLimits retain their defaults.
type Limits struct {
	// OperationTimeout bounds a complete Query or Lookup call.
	OperationTimeout time.Duration
	// IdleTimeout bounds connection establishment and each individual read or
	// write operation.
	IdleTimeout time.Duration
	// MaxHops bounds the total number of endpoints contacted by Lookup.
	MaxHops int
	// MaxQueryBytes bounds a query before the terminating CRLF is added.
	MaxQueryBytes int
	// MaxResponseBytes bounds the body retained for each endpoint.
	MaxResponseBytes int64
}

// Resolver is implemented by net.Resolver.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer is implemented by net.Dialer. Addresses passed to a Dialer contain
// an IP literal rather than an unresolved hostname.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// EndpointPolicy decides whether an endpoint may be contacted at a resolved
// address. It is evaluated separately for every resolved address.
type EndpointPolicy func(endpoint Endpoint, address netip.Addr) bool

// Option configures a Client.
type Option func(*Client)

// Client performs direct and automatically routed WHOIS queries. Clients are
// safe for concurrent use after construction.
type Client struct {
	resolver     Resolver
	dialer       Dialer
	directPolicy EndpointPolicy
	lookupPolicy EndpointPolicy
	limits       Limits
}

// NewClient returns a WHOIS client with bounded, safe defaults. Direct Query
// calls may contact any address. Lookup only contacts publicly routable WHOIS
// and RWhois endpoints unless its policy is replaced.
func NewClient(options ...Option) *Client {
	c := &Client{
		resolver:     net.DefaultResolver,
		dialer:       &net.Dialer{},
		directPolicy: AllowAnyEndpoint,
		lookupPolicy: PublicWHOISEndpoint,
		limits: Limits{
			OperationTimeout: defaultOperationTimeout,
			IdleTimeout:      defaultIdleTimeout,
			MaxHops:          defaultMaxHops,
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

// WithResolver replaces DNS resolution for all queries.
func WithResolver(resolver Resolver) Option {
	return func(c *Client) {
		if resolver != nil {
			c.resolver = resolver
		}
	}
}

// WithDialer replaces TCP dialing for all queries.
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

// WithLookupEndpointPolicy replaces the policy used by Lookup.
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
