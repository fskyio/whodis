package lookup

import (
	"sync"
	"time"
)

// RateLimiter is a per-key token bucket. A nil *RateLimiter admits every
// request, so callers can pass one unconditionally.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rpm     float64
	burst   int
	now     func() time.Time
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

// NewRateLimiter returns a limiter that refills perMinute tokens per minute up
// to burst tokens for each key.
func NewRateLimiter(perMinute float64, burst int) *RateLimiter {
	return &RateLimiter{buckets: make(map[string]*tokenBucket), rpm: perMinute, burst: burst, now: time.Now}
}

// Allow consumes a token for key. When none is available it reports false and
// how long until the next token.
func (r *RateLimiter) Allow(key string) (time.Duration, bool) {
	if r == nil {
		return 0, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	bucket, ok := r.buckets[key]
	if !ok {
		bucket = &tokenBucket{tokens: float64(r.burst), lastRefill: now}
		r.buckets[key] = bucket
	}
	bucket.tokens += now.Sub(bucket.lastRefill).Seconds() * (r.rpm / 60)
	if bucket.tokens > float64(r.burst) {
		bucket.tokens = float64(r.burst)
	}
	bucket.lastRefill = now
	if bucket.tokens < 1 {
		return time.Duration((1 - bucket.tokens) / (r.rpm / 60) * float64(time.Second)), false
	}
	bucket.tokens--
	return 0, true
}

// Cleanup forgets keys that have not been seen for maxAge.
func (r *RateLimiter) Cleanup(maxAge time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-maxAge)
	for key, bucket := range r.buckets {
		if bucket.lastRefill.Before(cutoff) {
			delete(r.buckets, key)
		}
	}
}
