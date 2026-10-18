package lookup

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"gitfield.org/fsky/whodis/internal/lookup/lookuptest"
	"gitfield.org/fsky/whodis/rdap"
	"gitfield.org/fsky/whodis/whois"
)

func TestParseProtocol(t *testing.T) {
	for input, want := range map[string]Protocol{"": Auto, "auto": Auto, " RDAP ": RDAP, "WHOIS": WHOIS} {
		got, err := ParseProtocol(input)
		if err != nil || got != want {
			t.Errorf("ParseProtocol(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := ParseProtocol("dns"); err == nil {
		t.Fatal("unknown protocol was accepted")
	}
}

func TestShouldFallbackRDAP(t *testing.T) {
	for status := 400; status < 500; status++ {
		if shouldFallbackRDAP(&rdap.HTTPError{StatusCode: status}) {
			t.Errorf("HTTP %d should not fall back", status)
		}
	}
	for _, err := range []error{
		&rdap.NoServiceError{Query: "example.test"},
		context.DeadlineExceeded,
		rdap.ErrInvalidResponse,
		rdap.ErrResponseTooLarge,
		&rdap.HTTPError{StatusCode: 500},
	} {
		if !shouldFallbackRDAP(err) {
			t.Errorf("%v should fall back", err)
		}
	}
}

func TestRDAPFreshness(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	capTTL := time.Hour
	tests := []struct {
		name      string
		header    http.Header
		wantTTL   time.Duration
		cacheable bool
	}{
		{"s-maxage before max-age", http.Header{"Cache-Control": {"max-age=600, s-maxage=120"}, "Age": {"20"}}, 100 * time.Second, true},
		{"max-age capped", http.Header{"Cache-Control": {"max-age=7200"}}, capTTL, true},
		{"expires relative to date", http.Header{"Date": {now.Format(http.TimeFormat)}, "Expires": {now.Add(10 * time.Minute).Format(http.TimeFormat)}, "Age": {"60"}}, 9 * time.Minute, true},
		{"default", make(http.Header), capTTL, true},
		{"expired", http.Header{"Cache-Control": {"max-age=10"}, "Age": {"10"}}, 0, false},
		{"no-store", http.Header{"Cache-Control": {"public, no-store, max-age=60"}}, 0, false},
		{"private", http.Header{"Cache-Control": {"private"}}, 0, false},
		{"no-cache", http.Header{"Cache-Control": {"no-cache"}}, 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotTTL, gotCacheable := rdapFreshness(test.header, capTTL, now)
			if gotTTL != test.wantTTL || gotCacheable != test.cacheable {
				t.Fatalf("rdapFreshness() = %v, %v; want %v, %v", gotTTL, gotCacheable, test.wantTTL, test.cacheable)
			}
		})
	}
}

func TestRDAPResponseChainUsesMostRestrictiveFreshness(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	responses := []rdap.Response{
		{Header: http.Header{"Cache-Control": {"max-age=600"}}},
		{Header: http.Header{"Cache-Control": {"max-age=120"}, "Age": {"20"}}},
	}
	if ttl, cacheable := rdapResponsesFreshness(responses, time.Hour, now); ttl != 100*time.Second || !cacheable {
		t.Fatalf("rdapResponsesFreshness() = %v, %v; want 100s, true", ttl, cacheable)
	}
	responses[1].Header.Set("Cache-Control", "private")
	if ttl, cacheable := rdapResponsesFreshness(responses, time.Hour, now); ttl != 0 || cacheable {
		t.Fatalf("private response freshness = %v, %v; want 0, false", ttl, cacheable)
	}
}

func TestAutoCancellationDoesNotFallBack(t *testing.T) {
	rdapClient := &lookuptest.RDAPClient{LookupFunc: func(ctx context.Context, _ string) (rdap.Result, error) {
		<-ctx.Done()
		return rdap.Result{}, ctx.Err()
	}}
	whoisClient := &lookuptest.WHOISClient{}
	service := newTestService(t, whoisClient, rdapClient)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.perform(ctx, "example.com", Auto)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if whoisClient.Calls() != 0 {
		t.Fatalf("WHOIS calls = %d", whoisClient.Calls())
	}
}

func TestAutoRDAPBudgetExpirationFallsBack(t *testing.T) {
	rdapClient := &lookuptest.RDAPClient{LookupFunc: func(ctx context.Context, _ string) (rdap.Result, error) {
		<-ctx.Done()
		return rdap.Result{}, ctx.Err()
	}}
	whoisClient := &lookuptest.WHOISClient{Result: whois.Result{Responses: []whois.Response{{Endpoint: whois.Endpoint{Host: "whois.example"}, Body: []byte("fallback")}}}}
	service := newTestService(t, whoisClient, rdapClient)
	service.config.RDAPAutoTimeout = 10 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := service.perform(ctx, "example.com", Auto)
	if err != nil {
		t.Fatal(err)
	}
	if whoisClient.Calls() != 1 || len(result.Items) != 1 || result.Items[0].Protocol != WHOIS {
		t.Fatalf("result = %#v, WHOIS calls = %d", result, whoisClient.Calls())
	}
}

func TestRateLimiterReportsTimeUntilNextToken(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	limiter := NewRateLimiter(60, 1)
	limiter.now = func() time.Time { return now }
	if _, allowed := limiter.Allow("client"); !allowed {
		t.Fatal("first request was rejected")
	}
	now = now.Add(250 * time.Millisecond)
	if retryAfter, allowed := limiter.Allow("client"); allowed || retryAfter != 750*time.Millisecond {
		t.Fatalf("Allow() = %v, %v; want 750ms, false", retryAfter, allowed)
	}
	if _, allowed := limiter.Allow("other"); !allowed {
		t.Fatal("independent key was rejected")
	}
	var disabled *RateLimiter
	if _, allowed := disabled.Allow("client"); !allowed {
		t.Fatal("nil limiter rejected a request")
	}
}

func newTestService(t *testing.T, whoisClient WHOISClient, rdapClient RDAPClient) *Service {
	t.Helper()
	service, err := NewService(Config{
		CacheTTL:        time.Hour,
		LookupTimeout:   time.Second,
		RDAPAutoTimeout: 100 * time.Millisecond,
	}, whoisClient, rdapClient)
	if err != nil {
		t.Fatal(err)
	}
	return service
}
