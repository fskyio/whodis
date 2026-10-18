package lookup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitfield.org/fsky/whodis/internal/target"
)

// MaxQueryBytes bounds the length of a lookup query.
const MaxQueryBytes = 256

var (
	// ErrQueryTooLong reports a query longer than MaxQueryBytes.
	ErrQueryTooLong = fmt.Errorf("query is longer than %d bytes", MaxQueryBytes)
	// ErrInvalidTarget reports a query that is not a lookup target.
	ErrInvalidTarget = target.ErrInvalid
)

// RateLimitError reports a cache miss rejected by the request's limiter.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return "rate limit exceeded"
}

// Config bounds lookups and their caching.
type Config struct {
	// CacheTTL caps how long successful results are cached.
	CacheTTL time.Duration
	// LookupTimeout bounds a whole lookup, including any WHOIS fallback.
	LookupTimeout time.Duration
	// RDAPAutoTimeout bounds the RDAP attempt of an Auto lookup.
	RDAPAutoTimeout time.Duration
	// Now overrides the clock used for caching; nil uses time.Now.
	Now func() time.Time
}

// Service performs lookups through a cache shared by every caller.
type Service struct {
	config Config
	whois  WHOISClient
	rdap   RDAPClient
	cache  *cacheStore
	now    func() time.Time
}

// Request describes one lookup.
type Request struct {
	Query    string
	Protocol Protocol
	// Limiter admits cache misses for Client; nil admits every request.
	Limiter *RateLimiter
	Client  string
}

// Outcome is a lookup result together with its cache state.
type Outcome struct {
	Result    Result
	FetchedAt time.Time
	CacheHit  bool
	// MaxAge is the remaining cache lifetime. It is zero for results that were
	// not cached.
	MaxAge time.Duration
}

// NewService returns a Service that queries the given clients.
func NewService(config Config, whoisClient WHOISClient, rdapClient RDAPClient) (*Service, error) {
	if whoisClient == nil || rdapClient == nil {
		return nil, errors.New("lookup clients must not be nil")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Service{config: config, whois: whoisClient, rdap: rdapClient, cache: newCache(now), now: now}, nil
}

// Lookup validates the query, serves it from cache when possible, and
// otherwise admits it through the request's limiter and queries upstream.
//
// Errors are ErrQueryTooLong, errors wrapping ErrInvalidTarget, a
// *RateLimitError, or the context error when the lookup was cancelled or
// exceeded LookupTimeout. Upstream failures are reported in the Result.
func (s *Service) Lookup(ctx context.Context, request Request) (Outcome, error) {
	query := strings.TrimSpace(request.Query)
	if len(query) > MaxQueryBytes {
		return Outcome{}, ErrQueryTooLong
	}
	if _, err := target.Parse(query, MaxQueryBytes); err != nil {
		return Outcome{}, err
	}

	key := normalizedCacheKey(request.Protocol, query)
	if entry, found := s.cache.Get(key); found {
		return Outcome{Result: entry.Result, FetchedAt: entry.FetchedAt, CacheHit: true, MaxAge: entry.ExpiresAt.Sub(s.now())}, nil
	}
	if retryAfter, allowed := request.Limiter.Allow(request.Client); !allowed {
		return Outcome{}, &RateLimitError{RetryAfter: retryAfter}
	}

	started := time.Now()
	lookupCtx, cancel := context.WithTimeout(ctx, s.config.LookupTimeout)
	result, err := s.perform(lookupCtx, query, request.Protocol)
	cancel()
	if err != nil {
		return Outcome{}, err
	}
	result.Duration = time.Since(started)

	outcome := Outcome{Result: result, FetchedAt: s.now()}
	if result.Cacheable && result.TTL > 0 {
		s.cache.Set(key, cacheEntry{Result: result, FetchedAt: outcome.FetchedAt, ExpiresAt: outcome.FetchedAt.Add(result.TTL)})
		outcome.MaxAge = result.TTL
	}
	return outcome, nil
}

// RunMaintenance evicts expired cache entries and idle rate-limit buckets
// until ctx is done.
func (s *Service) RunMaintenance(ctx context.Context, limiters ...*RateLimiter) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cache.Cleanup()
			for _, limiter := range limiters {
				limiter.Cleanup(time.Hour)
			}
		}
	}
}
