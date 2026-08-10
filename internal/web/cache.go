package web

import (
	"sync"
	"time"
)

type cacheEntry struct {
	Result    lookupResult
	ExpiresAt time.Time
	FetchedAt time.Time
}

type cacheStore struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
	now   func() time.Time
}

func newCache(now func() time.Time) *cacheStore {
	return &cacheStore{items: make(map[string]cacheEntry), now: now}
}

func (c *cacheStore) Get(key string) (cacheEntry, bool) {
	c.mu.RLock()
	entry, found := c.items[key]
	c.mu.RUnlock()
	if !found || !c.now().Before(entry.ExpiresAt) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *cacheStore) Set(key string, entry cacheEntry) {
	c.mu.Lock()
	c.items[key] = entry
	c.mu.Unlock()
}

func (c *cacheStore) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for key, entry := range c.items {
		if !now.Before(entry.ExpiresAt) {
			delete(c.items, key)
		}
	}
}
