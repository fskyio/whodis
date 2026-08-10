package main

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/whodis/whois"
)

func TestHandleWhoisCachesNativeLookup(t *testing.T) {
	client := &fakeLookupClient{result: whois.Result{
		Query: "example.com",
		Responses: []whois.Response{
			{Endpoint: whois.Endpoint{Host: "registry.test", Port: 43}, Body: []byte("registry\r\n")},
			{Endpoint: whois.Endpoint{Host: "registrar.test", Port: 4343}, Body: []byte("registrar \xff\r\n")},
		},
	}}
	restore := configureHandlerTest(t, client)
	defer restore()

	first := httptest.NewRecorder()
	handleWhois(first, httptest.NewRequest(http.MethodGet, "/whois?q=Example.COM", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("status = %d", first.Code)
	}
	if first.Header().Get("Whodis-Cache") != "MISS" {
		t.Fatalf("cache header = %q", first.Header().Get("Whodis-Cache"))
	}
	for _, want := range []string{"registry.test", "registrar.test:4343", "registrar �"} {
		if !strings.Contains(first.Body.String(), want) {
			t.Errorf("body does not contain %q", want)
		}
	}

	second := httptest.NewRecorder()
	handleWhois(second, httptest.NewRequest(http.MethodGet, "/whois?q=example.com", nil))
	if second.Header().Get("Whodis-Cache") != "HIT" {
		t.Fatalf("cache header = %q", second.Header().Get("Whodis-Cache"))
	}
	if client.calls != 1 {
		t.Fatalf("Lookup() calls = %d, want 1", client.calls)
	}
}

func TestHandleWhoisCachesPartialFailureBriefly(t *testing.T) {
	client := &fakeLookupClient{
		result: whois.Result{Responses: []whois.Response{{
			Endpoint: whois.Endpoint{Host: "registry.test", Port: 43},
			Body:     []byte("partial response"),
		}}},
		err: errors.New("registrar unavailable"),
	}
	restore := configureHandlerTest(t, client)
	defer restore()

	recorder := httptest.NewRecorder()
	handleWhois(recorder, httptest.NewRequest(http.MethodGet, "/whois?q=example.com", nil))
	if !strings.Contains(recorder.Body.String(), "partial response") || !strings.Contains(recorder.Body.String(), "registrar unavailable") {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	entry, ok := cache.Get("example.com")
	if !ok || !entry.IsError || len(entry.Responses) != 1 {
		t.Fatalf("cache entry = %#v, found %v", entry, ok)
	}
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 4*time.Minute || remaining > 5*time.Minute+time.Second {
		t.Fatalf("partial failure TTL = %v", remaining)
	}
}

func TestHandleWhoisDoesNotCacheCancellation(t *testing.T) {
	client := &fakeLookupClient{err: context.Canceled}
	restore := configureHandlerTest(t, client)
	defer restore()

	recorder := httptest.NewRecorder()
	handleWhois(recorder, httptest.NewRequest(http.MethodGet, "/whois?q=example.com", nil))
	if len(cache.items) != 0 {
		t.Fatalf("cached items = %#v", cache.items)
	}
}

func TestDisplayEndpoint(t *testing.T) {
	if got := displayEndpoint(whois.Endpoint{Host: "whois.example", Port: 43}); got != "whois.example" {
		t.Fatalf("displayEndpoint() = %q", got)
	}
	if got := displayEndpoint(whois.Endpoint{Host: "2001:db8::1", Port: 4321}); got != "[2001:db8::1]:4321" {
		t.Fatalf("displayEndpoint() = %q", got)
	}
}

type fakeLookupClient struct {
	result whois.Result
	err    error
	calls  int
}

func (c *fakeLookupClient) Lookup(_ context.Context, _ string) (whois.Result, error) {
	c.calls++
	return c.result, c.err
}

func configureHandlerTest(t *testing.T, client lookupClient) func() {
	t.Helper()
	oldClient := whoisClient
	oldCache := cache
	oldTTL := cacheTTL
	oldLimiter := limiter
	oldTemplate := tmpl

	whoisClient = client
	cache = &CacheStore{items: make(map[string]CacheEntry)}
	cacheTTL = 24 * time.Hour
	limiter = nil
	var err error
	tmpl, err = template.ParseFS(content, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}

	return func() {
		whoisClient = oldClient
		cache = oldCache
		cacheTTL = oldTTL
		limiter = oldLimiter
		tmpl = oldTemplate
	}
}
