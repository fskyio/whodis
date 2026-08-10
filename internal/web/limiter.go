package web

import (
	"sync"
	"time"
)

type rateLimiter struct {
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

func newRateLimiter(rpm float64, burst int, now func() time.Time) *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*tokenBucket), rpm: rpm, burst: burst, now: now}
}

func (r *rateLimiter) Allow(key string) bool {
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
		return false
	}
	bucket.tokens--
	return true
}

func (r *rateLimiter) Cleanup(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-maxAge)
	for key, bucket := range r.buckets {
		if bucket.lastRefill.Before(cutoff) {
			delete(r.buckets, key)
		}
	}
}
