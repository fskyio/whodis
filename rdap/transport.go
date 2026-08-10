package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Query fetches an exact caller-selected HTTP(S) URL. Private and nonstandard
// endpoints are permitted by default. Successful 2xx bodies must be valid
// JSON; error responses and oversized bodies are returned together with their
// typed error whenever available.
func (c *Client) Query(ctx context.Context, rawURL string) (Response, error) {
	ctx, cancel := c.withOperationTimeout(ctx)
	defer cancel()
	return c.query(ctx, rawURL, c.directPolicy, false)
}

func (c *Client) query(ctx context.Context, rawURL string, policy EndpointPolicy, rejectDowngrade bool) (Response, error) {
	response := Response{URL: rawURL}
	parsed, err := validateURL(rawURL)
	if err != nil {
		return response, &OpError{Op: "validate URL", URL: rawURL, Err: err}
	}
	if len(rawURL) > c.limits.MaxQueryBytes {
		return response, &OpError{Op: "validate URL", URL: rawURL, Err: fmt.Errorf("%w: URL is longer than %d bytes", ErrInvalidQuery, c.limits.MaxQueryBytes)}
	}

	transport := &http.Transport{
		DialContext:           c.policyDialContext(policy),
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: c.limits.IdleTimeout,
		TLSHandshakeTimeout:   c.limits.IdleTimeout,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: redirectChecker(c.limits.MaxRedirects, rejectDowngrade),
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), http.NoBody)
	if err != nil {
		return response, &OpError{Op: "create request", URL: rawURL, Err: err}
	}
	request.Header.Set("Accept", "application/rdap+json, application/json")
	request.Header.Set("User-Agent", "whodis-rdap/1 (+https://foundry.fsky.io/fsky/whodis)")

	httpResponse, err := client.Do(request)
	if err != nil {
		return response, &OpError{Op: "request", URL: rawURL, Err: contextAwareError(ctx, err)}
	}
	defer httpResponse.Body.Close()
	response.URL = httpResponse.Request.URL.String()
	response.StatusCode = httpResponse.StatusCode
	response.Header = httpResponse.Header.Clone()

	body, truncated, readErr := readBody(httpResponse.Body, c.limits.MaxResponseBytes)
	response.Body = body
	response.Truncated = truncated
	if readErr != nil {
		return response, &OpError{Op: "read", URL: response.URL, Err: contextAwareError(ctx, readErr)}
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return response, &HTTPError{StatusCode: httpResponse.StatusCode, Status: httpResponse.Status}
	}
	if !json.Valid(body) {
		return response, &OpError{Op: "validate response", URL: response.URL, Err: ErrInvalidResponse}
	}
	return response, nil
}

func redirectChecker(maxRedirects int, rejectDowngrade bool) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return ErrTooManyRedirects
		}
		if _, err := validateURL(request.URL.String()); err != nil {
			return err
		}
		if rejectDowngrade && len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && request.URL.Scheme == "http" {
			return ErrInsecureRedirect
		}
		request.Header.Set("Accept", "application/rdap+json, application/json")
		request.Header.Set("User-Agent", "whodis-rdap/1 (+https://foundry.fsky.io/fsky/whodis)")
		return nil
	}
}

func validateURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDisallowedEndpoint, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme must be HTTP or HTTPS", ErrDisallowedEndpoint)
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: malformed URL", ErrDisallowedEndpoint)
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return nil, fmt.Errorf("%w: invalid port", ErrDisallowedEndpoint)
		}
	}
	return parsed, nil
}

func (c *Client) policyDialContext(policy EndpointPolicy) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		portValue, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return nil, err
		}
		endpoint := Endpoint{Host: host, Port: uint16(portValue)}
		addresses, err := c.resolve(ctx, host)
		if err != nil {
			return nil, err
		}

		allowed := false
		var dialErrors []error
		for _, candidate := range addresses {
			if policy != nil && !policy(endpoint, candidate) {
				continue
			}
			allowed = true
			target := net.JoinHostPort(candidate.String(), portText)
			dialCtx := ctx
			cancel := func() {}
			if c.limits.IdleTimeout > 0 {
				dialCtx, cancel = context.WithTimeout(ctx, c.limits.IdleTimeout)
			}
			connection, dialErr := c.dialer.DialContext(dialCtx, network, target)
			cancel()
			if dialErr == nil && connection != nil {
				return connection, nil
			}
			if connection != nil {
				_ = connection.Close()
			}
			if dialErr == nil {
				dialErr = errors.New("dialer returned a nil connection")
			}
			dialErrors = append(dialErrors, dialErr)
		}
		if !allowed {
			return nil, ErrDisallowedEndpoint
		}
		return nil, errors.Join(dialErrors...)
	}
}

func (c *Client) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(host, ".")
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address.Unmap()}, nil
	}
	addresses, err := c.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("host resolved to no addresses")
	}
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	return result, nil
}

func readBody(reader io.Reader, limit int64) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return body, false, err
	}
	if int64(len(body)) > limit {
		return body[:limit], true, ErrResponseTooLarge
	}
	return body, false, nil
}

func contextAwareError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}
