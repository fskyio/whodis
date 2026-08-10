package web

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"foundry.fsky.io/fsky/whodis/rdap"
	"foundry.fsky.io/fsky/whodis/whois"
)

func TestParseProtocol(t *testing.T) {
	for input, want := range map[string]protocol{"": protocolAuto, "auto": protocolAuto, " RDAP ": protocolRDAP, "WHOIS": protocolWHOIS} {
		got, err := parseProtocol(input)
		if err != nil || got != want {
			t.Errorf("parseProtocol(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := parseProtocol("dns"); err == nil {
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

func TestAutoCancellationDoesNotFallBack(t *testing.T) {
	rdapClient := &fakeRDAPClient{lookup: func(ctx context.Context, _ string) (rdap.Result, error) {
		<-ctx.Done()
		return rdap.Result{}, ctx.Err()
	}}
	whoisClient := &fakeWHOISClient{}
	app := newTestApp(t, whoisClient, rdapClient)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := app.performLookup(ctx, "example.com", protocolAuto)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if whoisClient.calls != 0 {
		t.Fatalf("WHOIS calls = %d", whoisClient.calls)
	}
}

func TestAutoRDAPBudgetExpirationFallsBack(t *testing.T) {
	rdapClient := &fakeRDAPClient{lookup: func(ctx context.Context, _ string) (rdap.Result, error) {
		<-ctx.Done()
		return rdap.Result{}, ctx.Err()
	}}
	whoisClient := &fakeWHOISClient{result: whois.Result{Responses: []whois.Response{{Endpoint: whois.Endpoint{Host: "whois.example"}, Body: []byte("fallback")}}}}
	app := newTestApp(t, whoisClient, rdapClient)
	app.config.RDAPAutoTimeout = 10 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := app.performLookup(ctx, "example.com", protocolAuto)
	if err != nil {
		t.Fatal(err)
	}
	if whoisClient.calls != 1 || len(result.Items) != 1 || result.Items[0].Protocol != protocolWHOIS {
		t.Fatalf("result = %#v, WHOIS calls = %d", result, whoisClient.calls)
	}
}

type fakeRDAPClient struct {
	result rdap.Result
	err    error
	lookup func(context.Context, string) (rdap.Result, error)
	calls  int
}

func (c *fakeRDAPClient) Lookup(ctx context.Context, query string) (rdap.Result, error) {
	c.calls++
	if c.lookup != nil {
		return c.lookup(ctx, query)
	}
	return c.result, c.err
}

type fakeWHOISClient struct {
	result whois.Result
	err    error
	lookup func(context.Context, string) (whois.Result, error)
	calls  int
}

func (c *fakeWHOISClient) Lookup(ctx context.Context, query string) (whois.Result, error) {
	c.calls++
	if c.lookup != nil {
		return c.lookup(ctx, query)
	}
	return c.result, c.err
}

func newTestApp(t *testing.T, whoisClient whoisLookupClient, rdapClient rdapLookupClient) *App {
	t.Helper()
	config := Config{
		CacheTTL:        time.Hour,
		LookupTimeout:   time.Second,
		RDAPAutoTimeout: 100 * time.Millisecond,
	}
	app, err := New(config, whoisClient, rdapClient)
	if err != nil {
		t.Fatal(err)
	}
	app.logf = t.Logf
	return app
}
