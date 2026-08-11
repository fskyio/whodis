package rdap

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidQuery reports malformed or oversized lookup input.
	ErrInvalidQuery = errors.New("invalid RDAP query")
	// ErrNoService reports that no bootstrap service covers the resource.
	ErrNoService = errors.New("no RDAP service known")
	// ErrDisallowedEndpoint reports an endpoint rejected by URL validation or
	// the configured address policy.
	ErrDisallowedEndpoint = errors.New("RDAP endpoint is not allowed")
	// ErrResponseTooLarge reports a body larger than MaxResponseBytes.
	ErrResponseTooLarge = errors.New("RDAP response exceeds the configured limit")
	// ErrInvalidResponse reports invalid JSON in a successful response.
	ErrInvalidResponse = errors.New("invalid RDAP JSON response")
	// ErrReferralLoop indicates that a referral revisited an RDAP URL.
	ErrReferralLoop = errors.New("RDAP referral loop")
	// ErrTooManyReferrals indicates that traversal reached MaxHops while
	// another referral remained.
	ErrTooManyReferrals = errors.New("too many RDAP referrals")
	// ErrTooManyRedirects reports a redirect limit violation.
	ErrTooManyRedirects = errors.New("too many RDAP redirects")
	// ErrInsecureRedirect reports an automatic HTTPS-to-HTTP downgrade.
	ErrInsecureRedirect = errors.New("RDAP HTTPS redirect downgraded to HTTP")
	// ErrInsecureReferral reports an automatic HTTPS-to-HTTP referral.
	ErrInsecureReferral = errors.New("RDAP HTTPS referral downgraded to HTTP")
)

// NoServiceError records the resource for which discovery failed.
type NoServiceError struct {
	Query string
}

func (e *NoServiceError) Error() string {
	return fmt.Sprintf("%s for %q", ErrNoService, e.Query)
}

func (e *NoServiceError) Unwrap() error { return ErrNoService }

// HTTPError reports a non-2xx upstream status.
type HTTPError struct {
	StatusCode int
	Status     string
}

func (e *HTTPError) Error() string {
	if e.Status != "" {
		return "rdap server returned " + e.Status
	}
	return fmt.Sprintf("rdap server returned HTTP %d", e.StatusCode)
}

// OpError adds operation and URL context to a lower-level error.
type OpError struct {
	Op  string
	URL string
	Err error
}

func (e *OpError) Error() string {
	if e.URL == "" {
		return fmt.Sprintf("rdap %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("rdap %s %s: %v", e.Op, e.URL, e.Err)
}

func (e *OpError) Unwrap() error { return e.Err }
