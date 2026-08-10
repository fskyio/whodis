package rdap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"foundry.fsky.io/fsky/whodis/internal/target"
)

const ianaRDAPBase = "https://rdap.iana.org/"

// Lookup classifies a registration resource, discovers its service from the
// compiled IANA bootstrap snapshot, tries advertised alternatives, follows
// safe redirects, and validates successful responses as JSON.
func (c *Client) Lookup(ctx context.Context, query string) (Result, error) {
	parsed, err := target.Parse(query, c.limits.MaxQueryBytes)
	result := Result{Query: parsed.Normalized}
	if err != nil {
		return result, &OpError{Op: "classify", Err: fmt.Errorf("%w: %v", ErrInvalidQuery, err)}
	}

	urls, normalized, err := lookupURLs(parsed)
	result.Query = normalized
	if err != nil {
		return result, err
	}

	ctx, cancel := c.withOperationTimeout(ctx)
	defer cancel()

	var attemptErrors []error
	for _, rawURL := range urls {
		response, queryErr := c.query(ctx, rawURL, c.lookupPolicy, true)
		if response.URL != "" || len(response.Body) > 0 {
			result.Response = response
		}
		if queryErr == nil {
			return result, nil
		}
		attemptErrors = append(attemptErrors, queryErr)
		if ctx.Err() != nil || !retryAnotherService(queryErr) {
			return result, queryErr
		}
	}
	return result, &OpError{Op: "lookup", Err: errors.Join(attemptErrors...)}
}

func lookupURLs(parsed target.Target) ([]string, string, error) {
	normalized := parsed.Normalized
	var bases []string
	var resourcePath string

	switch parsed.Kind {
	case target.Address:
		bases = findNetworkURLs(parsed.Address)
		resourcePath = "ip/" + parsed.Query
	case target.Prefix:
		bases = findNetworkURLs(parsed.Address)
		resourcePath = "ip/" + parsed.Query
	case target.Reverse:
		bases = findNetworkURLs(parsed.Address)
		resourcePath = "domain/" + escapePathSegment(parsed.Query)
	case target.ASN:
		bases = findASNURLs(parsed.ASN)
		resourcePath = "autnum/" + strconv.FormatUint(uint64(parsed.ASN), 10)
	case target.Name:
		if parsed.NameASCII != "" && generatedTLDs[parsed.NameASCII] {
			bases = []string{ianaRDAPBase}
			normalized = parsed.NameASCII
			resourcePath = "domain/" + escapePathSegment(parsed.NameASCII)
		} else if strings.Contains(parsed.NameASCII, ".") {
			bases = findDomainURLs(parsed.NameASCII)
			normalized = parsed.NameASCII
			resourcePath = "domain/" + escapePathSegment(parsed.NameASCII)
		} else {
			bases = findObjectTagURLs(parsed.Query)
			resourcePath = "entity/" + escapePathSegment(parsed.Query)
		}
	default:
		return nil, normalized, &NoServiceError{Query: normalized}
	}
	if len(bases) == 0 {
		return nil, normalized, &NoServiceError{Query: normalized}
	}

	urls := make([]string, 0, len(bases))
	for _, base := range bases {
		baseURL, err := url.Parse(base)
		if err != nil {
			continue
		}
		reference, err := url.Parse(resourcePath)
		if err != nil {
			continue
		}
		urls = append(urls, baseURL.ResolveReference(reference).String())
	}
	if len(urls) == 0 {
		return nil, normalized, &NoServiceError{Query: normalized}
	}
	return urls, normalized, nil
}

func escapePathSegment(value string) string {
	return url.PathEscape(value)
}

func retryAnotherService(err error) bool {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= http.StatusInternalServerError || httpErr.StatusCode >= 300 && httpErr.StatusCode < 400
	}
	return true
}
