package whois

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Query sends query unchanged, followed by CRLF, to endpoint. It performs a
// single request and never follows a referral.
func (c *Client) Query(ctx context.Context, endpoint Endpoint, query string) (Response, error) {
	ctx, cancel := c.withOperationTimeout(ctx)
	defer cancel()

	response, err := c.query(ctx, endpoint, query, c.directPolicy)
	if len(response.Body) > 0 {
		response.Referral = findReferral(response.Endpoint, referralGeneric, response.Body)
	}
	return response, err
}

func (c *Client) query(ctx context.Context, endpoint Endpoint, query string, policy EndpointPolicy) (Response, error) {
	response := Response{Query: query}
	if err := validateQuery(query, c.limits.MaxQueryBytes); err != nil {
		return response, &OpError{Op: "validate", Endpoint: endpoint, Err: err}
	}

	normalizedEndpoint, err := normalizeEndpoint(endpoint)
	if err != nil {
		return response, &OpError{Op: "validate endpoint", Endpoint: endpoint, Err: err}
	}
	endpoint = normalizedEndpoint
	response.Endpoint = endpoint

	addresses, err := c.resolve(ctx, endpoint.Host)
	if err != nil {
		return response, &OpError{Op: "resolve", Endpoint: endpoint, Err: err}
	}

	var conn net.Conn
	var dialErrors []error
	allowed := false
	for _, address := range addresses {
		if policy != nil && !policy(endpoint, address) {
			continue
		}
		allowed = true
		target := net.JoinHostPort(address.String(), strconv.Itoa(int(endpoint.Port)))
		dialCtx := ctx
		cancelDial := func() {}
		if c.limits.IdleTimeout > 0 {
			dialCtx, cancelDial = context.WithTimeout(ctx, c.limits.IdleTimeout)
		}
		candidate, dialErr := c.dialer.DialContext(dialCtx, "tcp", target)
		cancelDial()
		if dialErr == nil && candidate != nil {
			conn = candidate
			break
		}
		if candidate != nil {
			_ = candidate.Close()
		}
		if dialErr == nil {
			dialErr = errors.New("dialer returned a nil connection")
		}
		dialErrors = append(dialErrors, dialErr)
	}
	if conn == nil {
		if !allowed {
			return response, &OpError{Op: "dial", Endpoint: endpoint, Err: ErrDisallowedEndpoint}
		}
		return response, &OpError{Op: "dial", Endpoint: endpoint, Err: errors.Join(dialErrors...)}
	}
	defer conn.Close()

	stopCancelWatch := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancelWatch()

	request := append([]byte(query), '\r', '\n')
	if err := c.setWriteDeadline(conn); err != nil {
		return response, &OpError{Op: "set write deadline", Endpoint: endpoint, Err: err}
	}
	if _, err := writeAll(conn, request); err != nil {
		return response, &OpError{Op: "write", Endpoint: endpoint, Err: contextAwareError(ctx, err)}
	}

	body, truncated, err := c.readResponse(conn)
	response.Body = body
	response.Truncated = truncated
	if err != nil {
		return response, &OpError{Op: "read", Endpoint: endpoint, Err: contextAwareError(ctx, err)}
	}
	return response, nil
}

func validateQuery(query string, maxBytes int) error {
	if query == "" {
		return fmt.Errorf("%w: query is empty", ErrInvalidQuery)
	}
	if len(query) > maxBytes {
		return fmt.Errorf("%w: query is longer than %d bytes", ErrInvalidQuery, maxBytes)
	}
	if strings.ContainsAny(query, "\r\n\x00") {
		return fmt.Errorf("%w: query contains a line break or NUL", ErrInvalidQuery)
	}
	return nil
}

func normalizeEndpoint(endpoint Endpoint) (Endpoint, error) {
	host := strings.TrimSpace(endpoint.Host)
	if host == "" {
		return Endpoint{}, fmt.Errorf("%w: host is empty", ErrDisallowedEndpoint)
	}
	if strings.ContainsAny(host, "\x00\r\n/\\@") {
		return Endpoint{}, fmt.Errorf("%w: malformed host", ErrDisallowedEndpoint)
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		host = address.Unmap().String()
	} else {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if host == "" || len(host) > 253 {
			return Endpoint{}, fmt.Errorf("%w: malformed host", ErrDisallowedEndpoint)
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Endpoint{}, fmt.Errorf("%w: malformed host", ErrDisallowedEndpoint)
			}
			for _, ch := range label {
				if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' {
					return Endpoint{}, fmt.Errorf("%w: malformed host", ErrDisallowedEndpoint)
				}
			}
		}
	}
	if endpoint.Port == 0 {
		endpoint.Port = defaultPort
	}
	endpoint.Host = host
	return endpoint, nil
}

func (c *Client) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address.Unmap()}, nil
	}
	addresses, err := c.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("host resolved to no addresses")
	}
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	return result, nil
}

func (c *Client) readResponse(conn net.Conn) ([]byte, bool, error) {
	var body bytes.Buffer
	buffer := make([]byte, 32*1024)
	for {
		if err := c.setReadDeadline(conn); err != nil {
			return body.Bytes(), false, err
		}
		n, err := conn.Read(buffer)
		if n > 0 {
			remaining := c.limits.MaxResponseBytes - int64(body.Len())
			if int64(n) > remaining {
				if remaining > 0 {
					_, _ = body.Write(buffer[:remaining])
				}
				return body.Bytes(), true, ErrResponseTooLarge
			}
			_, _ = body.Write(buffer[:n])
		}
		if errors.Is(err, io.EOF) {
			return body.Bytes(), false, nil
		}
		if err != nil {
			return body.Bytes(), false, err
		}
	}
}

func (c *Client) setReadDeadline(conn net.Conn) error {
	if c.limits.IdleTimeout <= 0 {
		return nil
	}
	return conn.SetReadDeadline(time.Now().Add(c.limits.IdleTimeout))
}

func (c *Client) setWriteDeadline(conn net.Conn) error {
	if c.limits.IdleTimeout <= 0 {
		return nil
	}
	return conn.SetWriteDeadline(time.Now().Add(c.limits.IdleTimeout))
}

func writeAll(writer io.Writer, value []byte) (int, error) {
	written := 0
	for written < len(value) {
		n, err := writer.Write(value[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrUnexpectedEOF
		}
	}
	return written, nil
}

func contextAwareError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}
