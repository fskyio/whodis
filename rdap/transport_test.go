package rdap

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestQueryPreservesJSONAndMetadata(t *testing.T) {
	body := "{\"z\":1,\"extension\":{\"value\":true}}\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/rdap+json, application/json" {
			t.Errorf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	response, err := NewClient().Query(context.Background(), server.URL+"/domain/example.test")
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Body) != body || response.StatusCode != http.StatusOK || response.URL == "" || response.Header.Get("Cache-Control") != "max-age=60" {
		t.Fatalf("response = %#v, body %q", response, response.Body)
	}
}

func TestQueryReturnsHTTPErrorWithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{ "errorCode": 404, "custom": "kept" }`)
	}))
	defer server.Close()

	response, err := NewClient().Query(context.Background(), server.URL)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
		t.Fatalf("error = %#v", err)
	}
	if !strings.Contains(string(response.Body), `"custom"`) {
		t.Fatalf("body = %q", response.Body)
	}
}

func TestQueryRejectsInvalidSuccessfulJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not json")
	}))
	defer server.Close()
	response, err := NewClient().Query(context.Background(), server.URL)
	if !errors.Is(err, ErrInvalidResponse) || string(response.Body) != "not json" {
		t.Fatalf("response = %#v, error = %v", response, err)
	}
}

func TestQueryResponseLimitReturnsPrefix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"long":"value"}`)
	}))
	defer server.Close()
	response, err := NewClient(WithLimits(Limits{MaxResponseBytes: 8})).Query(context.Background(), server.URL)
	if !errors.Is(err, ErrResponseTooLarge) || !response.Truncated || len(response.Body) != 8 {
		t.Fatalf("response = %#v, error = %v", response, err)
	}
}

func TestAutomaticPolicyRejectsPrivateAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	_, err := NewClient().query(context.Background(), server.URL, PublicRDAPEndpoint, true)
	if !errors.Is(err, ErrDisallowedEndpoint) {
		t.Fatalf("error = %v", err)
	}
}

func TestEndpointPolicies(t *testing.T) {
	if !AllowAnyEndpoint(Endpoint{}, netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("AllowAnyEndpoint rejected loopback")
	}
	for address, want := range map[string]bool{
		"8.8.8.8":              true,
		"2001:4860:4860::8888": true,
		"127.0.0.1":            false,
		"10.0.0.1":             false,
		"192.0.2.1":            false,
		"2001:db8::1":          false,
		"64:ff9b::a00:1":       false,
		"fec0::1":              false,
	} {
		if got := PublicRDAPEndpoint(Endpoint{}, netip.MustParseAddr(address)); got != want {
			t.Errorf("PublicRDAPEndpoint(%s) = %v, want %v", address, got, want)
		}
	}
}

func TestAutomaticQueryRejectsHTTPSDowngrade(t *testing.T) {
	previous, err := http.NewRequest(http.MethodGet, "https://rdap.example/domain/example.test", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	next, err := http.NewRequest(http.MethodGet, "http://rdap.example/domain/example.test", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := redirectChecker(5, true)(next, []*http.Request{previous}); !errors.Is(err, ErrInsecureRedirect) {
		t.Fatalf("error = %v", err)
	}
	if err := redirectChecker(5, false)(next, []*http.Request{previous}); err != nil {
		t.Fatalf("direct query redirect error = %v", err)
	}
}

func TestQueryHonorsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := NewClient().Query(ctx, server.URL)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

func TestQueryHeaderTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	client := NewClient(WithLimits(Limits{OperationTimeout: time.Second, IdleTimeout: 20 * time.Millisecond}))
	started := time.Now()
	_, err := client.Query(context.Background(), server.URL)
	if err == nil || time.Since(started) > 250*time.Millisecond {
		t.Fatalf("error = %v after %v", err, time.Since(started))
	}
}

func TestLookupTriesAlternateServiceAndDialsValidatedIP(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `upstream unavailable`)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"handle":"EXAMPLE.TEST"}`)
	}))
	defer second.Close()

	firstPort := serverPort(t, first.URL)
	secondPort := serverPort(t, second.URL)
	oldRoutes := generatedDNSRoutes
	generatedDNSRoutes = map[string][]string{
		"test": {
			"http://first.rdap.test:" + firstPort + "/",
			"http://second.rdap.test:" + secondPort + "/",
		},
	}
	t.Cleanup(func() { generatedDNSRoutes = oldRoutes })

	resolver := &recordingResolver{addresses: map[string][]netip.Addr{
		"first.rdap.test":  {netip.MustParseAddr("203.0.113.10")},
		"second.rdap.test": {netip.MustParseAddr("203.0.113.11")},
	}}
	dialer := &recordingDialer{targets: map[string]string{
		net.JoinHostPort("203.0.113.10", firstPort):  first.Listener.Addr().String(),
		net.JoinHostPort("203.0.113.11", secondPort): second.Listener.Addr().String(),
	}}
	client := NewClient(
		WithResolver(resolver),
		WithDialer(dialer),
		WithLookupEndpointPolicy(AllowAnyEndpoint),
	)
	result, err := client.Lookup(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Response.URL, "second.rdap.test") || !strings.Contains(string(result.Response.Body), "EXAMPLE.TEST") {
		t.Fatalf("result = %#v", result)
	}
	if got := dialer.Addresses(); len(got) != 2 || strings.Contains(strings.Join(got, ","), "rdap.test") {
		t.Fatalf("dialed addresses = %#v; want two pinned IP literals", got)
	}
	if resolver.Calls() != 2 {
		t.Fatalf("resolver calls = %d, want 2", resolver.Calls())
	}
}

func TestQueryFollowsRedirectAndPreservesFinalURL(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer final.Close()
	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/domain/example.test", http.StatusTemporaryRedirect)
	}))
	defer initial.Close()
	response, err := NewClient().Query(context.Background(), initial.URL)
	if err != nil {
		t.Fatal(err)
	}
	if response.URL != final.URL+"/domain/example.test" {
		t.Fatalf("final URL = %q", response.URL)
	}
}

func TestValidateURL(t *testing.T) {
	for _, value := range []string{"file:///tmp/test", "https://user@example.test/", "https://example.test/#fragment", "https://example.test:0/"} {
		if _, err := validateURL(value); !errors.Is(err, ErrDisallowedEndpoint) {
			t.Errorf("validateURL(%q) error = %v", value, err)
		}
	}
}

func serverPort(t *testing.T, rawURL string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

type recordingResolver struct {
	mu        sync.Mutex
	addresses map[string][]netip.Addr
	calls     int
}

func (r *recordingResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	addresses := r.addresses[strings.ToLower(host)]
	if len(addresses) == 0 {
		return nil, &net.DNSError{Name: host, Err: "not found", IsNotFound: true}
	}
	return append([]netip.Addr(nil), addresses...), nil
}

func (r *recordingResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type recordingDialer struct {
	mu        sync.Mutex
	targets   map[string]string
	addresses []string
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	target := d.targets[address]
	d.mu.Unlock()
	if target == "" {
		return nil, errors.New("unexpected dial target " + strconv.Quote(address))
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func (d *recordingDialer) Addresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addresses...)
}
