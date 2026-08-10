package whois

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidQuery indicates an empty, malformed, multiline, or oversized
	// query.
	ErrInvalidQuery = errors.New("invalid WHOIS query")
	// ErrNoServer indicates that automatic routing has no WHOIS endpoint for
	// the resource. The returned error may be a *NoServerError.
	ErrNoServer = errors.New("no WHOIS server known")
	// ErrDisallowedEndpoint indicates that an endpoint policy rejected every
	// resolved address or the requested port.
	ErrDisallowedEndpoint = errors.New("WHOIS endpoint is not allowed")
	// ErrResponseTooLarge indicates that a server exceeded MaxResponseBytes.
	// The returned Response contains the retained prefix and has Truncated set.
	ErrResponseTooLarge = errors.New("WHOIS response exceeds the configured limit")
	// ErrReferralLoop indicates that a referral revisited an endpoint.
	ErrReferralLoop = errors.New("WHOIS referral loop")
	// ErrTooManyReferrals indicates that traversal reached MaxHops while
	// another referral remained.
	ErrTooManyReferrals = errors.New("too many WHOIS referrals")
)

// NoServerError reports a resource for which no WHOIS endpoint is known.
// WebURL may identify a registry-provided browser lookup instead.
type NoServerError struct {
	// Query is the normalized resource for which no server is known.
	Query string
	// WebURL is an optional registry-provided browser lookup URL.
	WebURL string
}

func (e *NoServerError) Error() string {
	if e.WebURL != "" {
		return fmt.Sprintf("%s for %q; registry lookup: %s", ErrNoServer, e.Query, e.WebURL)
	}
	return fmt.Sprintf("%s for %q", ErrNoServer, e.Query)
}

func (e *NoServerError) Unwrap() error { return ErrNoServer }

// OpError adds operation and endpoint context to a lookup failure.
type OpError struct {
	// Op describes the operation that failed, such as resolve, dial, or read.
	Op string
	// Endpoint identifies the relevant server when one had been selected.
	Endpoint Endpoint
	// Err is the underlying error.
	Err error
}

func (e *OpError) Error() string {
	if e.Endpoint.Host == "" {
		return fmt.Sprintf("whois %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("whois %s %s: %v", e.Op, e.Endpoint.String(), e.Err)
}

func (e *OpError) Unwrap() error { return e.Err }
