package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"gitfield.org/fsky/whodis/internal/lookup"
	"gitfield.org/fsky/whodis/internal/lookup/lookuptest"
	"gitfield.org/fsky/whodis/rdap"
	"gitfield.org/fsky/whodis/whois"
)

const testToken = "0123456789abcdef0123456789abcdef"

func TestLookupStatusDistinguishesMissingPartialAndFailedLookups(t *testing.T) {
	registry := rdap.Response{URL: "https://rdap.example/domain/example.com", StatusCode: http.StatusOK, Body: []byte(`{"handle":"REGISTRY"}`)}
	for _, test := range []struct {
		name  string
		rdap  *lookuptest.RDAPClient
		whois *lookuptest.WHOISClient
		want  string
	}{
		{"found", &lookuptest.RDAPClient{Result: rdap.Result{Responses: []rdap.Response{registry}}}, &lookuptest.WHOISClient{}, statusOK},
		{"registry has no such object", &lookuptest.RDAPClient{
			Result: rdap.Result{Responses: []rdap.Response{{URL: "https://rdap.example/domain/missing.com", StatusCode: http.StatusNotFound, Body: []byte(`{"errorCode":404}`)}}},
			Err:    &rdap.HTTPError{StatusCode: http.StatusNotFound, Status: "404 Not Found"},
		}, &lookuptest.WHOISClient{}, statusNotFound},
		{"registrar referral failed", &lookuptest.RDAPClient{
			Result: rdap.Result{Responses: []rdap.Response{registry, {URL: "https://registrar.example/domain/example.com", StatusCode: http.StatusNotFound, Body: []byte(`{"errorCode":404}`)}}},
			Err:    &rdap.HTTPError{StatusCode: http.StatusNotFound, Status: "404 Not Found"},
		}, &lookuptest.WHOISClient{}, statusPartial},
		{"WHOIS registrar refused", &lookuptest.RDAPClient{Err: rdap.ErrNoService}, &lookuptest.WHOISClient{
			Result: whois.Result{Responses: []whois.Response{
				{Endpoint: whois.Endpoint{Host: "whois.registry.test"}, Body: []byte("Registrar WHOIS Server: whois.registrar.test")},
				{Endpoint: whois.Endpoint{Host: "whois.registrar.test"}, Error: errors.New("connection refused")},
			}},
			Err: errors.New("connection refused"),
		}, statusPartial},
		{"nothing answered", &lookuptest.RDAPClient{Err: rdap.ErrNoService}, &lookuptest.WHOISClient{Err: errors.New("connection refused")}, statusFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t, test.rdap, test.whois, Config{})
			if result := callLookup(t, server.URL+Path, nil, map[string]any{"query": "example.com"}); result.Status != test.want {
				t.Fatalf("status = %q, want %q; result = %+v", result.Status, test.want, result)
			}
		})
	}
}

func TestLookupTrimsRDAPBoilerplateUnlessRawIsRequested(t *testing.T) {
	rdapClient := &lookuptest.RDAPClient{Result: rdap.Result{Query: "example.com", Responses: []rdap.Response{{
		URL:        "https://rdap.example/domain/example.com",
		StatusCode: http.StatusOK,
		Body: []byte(`{
			"rdapConformance": ["rdap_level_0"],
			"notices": [{"title": "Terms of Use", "description": ["<b>long</b> legal text"]}],
			"links": [{"href": "https://rdap.example/domain/example.com", "rel": "self"}],
			"handle": "EXAMPLE",
			"redacted": [{"name": {"type": "Registrant Name"}}],
			"entities": [{"handle": "R1", "roles": ["registrar"], "links": [{"href": "https://registrar.example"}], "remarks": [{"description": ["kept"]}]}],
			"port43": 43.0
		}`),
	}}}}
	server := newTestServer(t, rdapClient, &lookuptest.WHOISClient{}, Config{WebUI: true})

	result := callLookup(t, server.URL+Path, nil, map[string]any{"query": " Example.com "})
	if result.Protocol != "auto" || result.CacheHit || result.WebURL != server.URL+"/lookup?protocol=auto&q=Example.com" || len(result.Hops) != 1 {
		t.Fatalf("result = %+v", result)
	}
	trimmed := string(result.Hops[0].Body)
	for _, removed := range []string{"rdapConformance", "notices", "links", "Terms of Use"} {
		if strings.Contains(trimmed, removed) {
			t.Errorf("trimmed body still contains %q: %s", removed, trimmed)
		}
	}
	for _, kept := range []string{`"handle":"EXAMPLE"`, `"redacted"`, `"remarks"`, `"port43":43.0`} {
		if !strings.Contains(trimmed, kept) {
			t.Errorf("trimmed body lost %q: %s", kept, trimmed)
		}
	}

	raw := callLookup(t, server.URL+Path, nil, map[string]any{"query": "example.com", "raw": true})
	rawBody := string(raw.Hops[0].Body)
	if !raw.CacheHit || rdapClient.Calls() != 1 {
		t.Fatalf("raw request was not served from cache: cache hit = %v, RDAP calls = %d", raw.CacheHit, rdapClient.Calls())
	}
	for _, kept := range []string{`"rdapConformance"`, `"notices"`, `"links"`, `<b>long</b>`} {
		if !strings.Contains(rawBody, kept) {
			t.Errorf("raw body lost %q: %s", kept, rawBody)
		}
	}
}

func TestLookupTruncatesLargeBodiesAndCollapsesRepeats(t *testing.T) {
	large := strings.Repeat("a", maxBodyBytes-1) + "é" + strings.Repeat("b", 100)
	whoisClient := &lookuptest.WHOISClient{Result: whois.Result{Responses: []whois.Response{
		{Endpoint: whois.Endpoint{Host: "whois.registry.test"}, Body: []byte(large)},
		{Endpoint: whois.Endpoint{Host: "whois.registrar.test"}, Body: []byte(large)},
		{Endpoint: whois.Endpoint{Host: "whois.reseller.test"}, Body: []byte("Registrar: Example")},
	}}}
	server := newTestServer(t, &lookuptest.RDAPClient{}, whoisClient, Config{})

	result := callLookup(t, server.URL+Path, nil, map[string]any{"query": "example.com", "protocol": "whois"})
	if result.WebURL != "" || len(result.Hops) != 3 {
		t.Fatalf("result = %+v", result)
	}
	first, second, third := result.Hops[0], result.Hops[1], result.Hops[2]
	var text string
	if err := json.Unmarshal(first.Body, &text); err != nil {
		t.Fatal(err)
	}
	if !first.Truncated || first.BodyBytes != len(large) || len(text) != maxBodyBytes-1 || !utf8.ValidString(text) {
		t.Fatalf("first hop: truncated = %v, body bytes = %d, text bytes = %d", first.Truncated, first.BodyBytes, len(text))
	}
	if second.SameAsHop != 1 || second.Body != nil || second.Truncated || second.Source != "whois.registrar.test" {
		t.Fatalf("second hop = %+v", second)
	}
	if third.SameAsHop != 0 || string(third.Body) != `"Registrar: Example"` {
		t.Fatalf("third hop = %+v", third)
	}
}

func TestTokensBypassRateLimitAndCanBeRequired(t *testing.T) {
	whoisClient := &lookuptest.WHOISClient{Result: whois.Result{Responses: []whois.Response{{Endpoint: whois.Endpoint{Host: "whois.test"}, Body: []byte("record")}}}}
	config := Config{Limiter: lookup.NewRateLimiter(1, 1), Tokens: []string{testToken}}
	server := newTestServer(t, &lookuptest.RDAPClient{}, whoisClient, config)
	bearer := http.Header{"Authorization": {"Bearer " + testToken}}

	callLookup(t, server.URL+Path, nil, map[string]any{"query": "one.example", "protocol": "whois"})
	if message := callLookupError(t, server.URL+Path, nil, map[string]any{"query": "two.example", "protocol": "whois"}); !strings.Contains(message, "Rate limit exceeded; retry in") {
		t.Fatalf("anonymous error = %q", message)
	}
	callLookup(t, server.URL+Path+"/"+testToken, nil, map[string]any{"query": "three.example", "protocol": "whois"})
	callLookup(t, server.URL+Path, bearer, map[string]any{"query": "four.example", "protocol": "whois"})
	if whoisClient.Calls() != 3 {
		t.Fatalf("WHOIS calls = %d, want 3", whoisClient.Calls())
	}

	for _, test := range []struct {
		name   string
		path   string
		header http.Header
		want   int
	}{
		{"unknown path token", Path + "/" + strings.Repeat("x", len(testToken)), nil, http.StatusNotFound},
		{"wrong bearer token", Path, http.Header{"Authorization": {"Bearer " + strings.Repeat("x", len(testToken))}}, http.StatusUnauthorized},
	} {
		if got := postInitialize(t, server.URL+test.path, test.header); got != test.want {
			t.Errorf("%s: status = %d, want %d", test.name, got, test.want)
		}
	}

	config.RequireToken = true
	private := newTestServer(t, &lookuptest.RDAPClient{}, whoisClient, config)
	if got := postInitialize(t, private.URL+Path, nil); got != http.StatusUnauthorized {
		t.Fatalf("anonymous request to private endpoint: status = %d", got)
	}
	callLookup(t, private.URL+Path+"/"+testToken, nil, map[string]any{"query": "five.example", "protocol": "whois"})
}

func TestPathTokensAreRejectedWhenNoneAreConfigured(t *testing.T) {
	server := newTestServer(t, &lookuptest.RDAPClient{}, &lookuptest.WHOISClient{}, Config{})
	if got := postInitialize(t, server.URL+Path+"/"+testToken, nil); got != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", got)
	}
}

func TestLookupReportsInvalidInputAsToolErrors(t *testing.T) {
	rdapClient := &lookuptest.RDAPClient{}
	whoisClient := &lookuptest.WHOISClient{}
	server := newTestServer(t, rdapClient, whoisClient, Config{})
	if message := callLookupError(t, server.URL+Path, nil, map[string]any{"query": "two resources"}); !strings.Contains(message, "invalid lookup target") {
		t.Errorf("error = %q", message)
	}
	for _, arguments := range []map[string]any{
		{"query": strings.Repeat("a", lookup.MaxQueryBytes+1)},
		{"query": "example.com", "protocol": "dns"},
		{"query": ""},
	} {
		callLookupError(t, server.URL+Path, nil, arguments)
	}
	if rdapClient.Calls() != 0 || whoisClient.Calls() != 0 {
		t.Fatalf("RDAP calls = %d, WHOIS calls = %d", rdapClient.Calls(), whoisClient.Calls())
	}
}

func newTestServer(t *testing.T, rdapClient lookup.RDAPClient, whoisClient lookup.WHOISClient, config Config) *httptest.Server {
	t.Helper()
	service, err := lookup.NewService(lookup.Config{CacheTTL: time.Hour, LookupTimeout: time.Second, RDAPAutoTimeout: 100 * time.Millisecond}, whoisClient, rdapClient)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(service, config).Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func callTool(t *testing.T, endpoint string, header http.Header, arguments map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	httpClient := &http.Client{Transport: headerTransport{header: header}}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: httpClient, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatalf("connect to %s: %v", endpoint, err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "lookup", Arguments: arguments})
	if err != nil {
		t.Fatalf("call lookup: %v", err)
	}
	return result
}

func callLookup(t *testing.T, endpoint string, header http.Header, arguments map[string]any) envelope {
	t.Helper()
	result := callTool(t, endpoint, header, arguments)
	text := result.Content[0].(*mcp.TextContent).Text
	if result.IsError {
		t.Fatalf("lookup %v failed: %s", arguments, text)
	}
	var output envelope
	if err := json.Unmarshal([]byte(text), &output); err != nil {
		t.Fatalf("decode %s: %v", text, err)
	}
	return output
}

func callLookupError(t *testing.T, endpoint string, header http.Header, arguments map[string]any) string {
	t.Helper()
	result := callTool(t, endpoint, header, arguments)
	text := result.Content[0].(*mcp.TextContent).Text
	if !result.IsError {
		t.Fatalf("lookup %v succeeded: %s", arguments, text)
	}
	return text
}

func postInitialize(t *testing.T, endpoint string, header http.Header) int {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response.StatusCode
}

type headerTransport struct {
	header http.Header
}

func (h headerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	for name, values := range h.header {
		request.Header[name] = values
	}
	return http.DefaultTransport.RoundTrip(request)
}
