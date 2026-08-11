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
// safe redirects and domain referrals, and validates successful responses as
// JSON. A non-empty Result may be returned with an error if a later hop fails.
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
		result.Response = response
		if queryErr == nil {
			result.appendResponse(response)
			return c.followReferrals(ctx, result, rawURL)
		}
		attemptErrors = append(attemptErrors, queryErr)
		if ctx.Err() != nil || !retryAnotherService(queryErr) {
			result.appendFailedResponse(response)
			return result, queryErr
		}
	}
	result.appendFailedResponse(result.Response)
	return result, &OpError{Op: "lookup", Err: errors.Join(attemptErrors...)}
}

func (c *Client) followReferrals(ctx context.Context, result Result, initialURL string) (Result, error) {
	seen := make(map[string]struct{}, c.limits.MaxHops*2)
	current := &result.Responses[len(result.Responses)-1]
	addSeenURL(seen, initialURL)
	addSeenURL(seen, current.URL)

	for len(result.Responses) <= c.limits.MaxHops {
		referral, err := findReferral(current.URL, current.Body)
		if err != nil {
			return result, &OpError{Op: "follow referral", URL: current.URL, Err: err}
		}
		if referral == "" {
			return result, nil
		}
		current.Referral = referral
		result.Response = *current
		referralKey, keyErr := referralURLKey(referral)
		if keyErr != nil {
			return result, &OpError{Op: "follow referral", URL: referral, Err: keyErr}
		}
		if _, exists := seen[referralKey]; exists {
			return result, &OpError{Op: "follow referral", URL: referral, Err: ErrReferralLoop}
		}
		if len(result.Responses) == c.limits.MaxHops {
			return result, &OpError{Op: "follow referral", URL: referral, Err: ErrTooManyReferrals}
		}

		response, queryErr := c.query(ctx, referral, c.lookupPolicy, true)
		seen[referralKey] = struct{}{}
		if key, keyErr := referralURLKey(response.URL); keyErr == nil {
			if key != referralKey {
				if _, exists := seen[key]; exists {
					return result, &OpError{Op: "follow referral", URL: response.URL, Err: ErrReferralLoop}
				}
				seen[key] = struct{}{}
			}
		}
		if queryErr != nil {
			result.appendFailedResponse(response)
			return result, queryErr
		}
		result.appendResponse(response)
		current = &result.Responses[len(result.Responses)-1]
	}
	return result, nil
}

func (r *Result) appendResponse(response Response) {
	r.Responses = append(r.Responses, response)
	r.Response = response
}

func (r *Result) appendFailedResponse(response Response) {
	if response.Error != nil || response.URL != "" || len(response.Body) > 0 || response.StatusCode != 0 || response.Truncated {
		r.appendResponse(response)
	}
}

func addSeenURL(seen map[string]struct{}, rawURL string) {
	if key, err := referralURLKey(rawURL); err == nil {
		seen[key] = struct{}{}
	}
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
