package whois

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestQuerySendsCRLFAndPreservesResponse(t *testing.T) {
	t.Parallel()

	endpoint, received, closeServer := serveOnce(t, func(conn net.Conn, request string) {
		_, _ = conn.Write([]byte("first\r\nsecond\n\xff"))
	})
	defer closeServer()

	response, err := NewClient().Query(context.Background(), endpoint, "domain example.test")
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if got := <-received; got != "domain example.test\r\n" {
		t.Fatalf("wire query = %q", got)
	}
	if got, want := string(response.Body), "first\r\nsecond\n\xff"; got != want {
		t.Fatalf("Body = %q, want %q", got, want)
	}
	if response.Endpoint != endpoint {
		t.Fatalf("Endpoint = %#v, want %#v", response.Endpoint, endpoint)
	}
	if response.Duration <= 0 {
		t.Fatalf("response duration = %v, want positive duration", response.Duration)
	}
}

func TestQueryResponseLimitReturnsExactPrefix(t *testing.T) {
	t.Parallel()

	endpoint, _, closeServer := serveOnce(t, func(conn net.Conn, request string) {
		_, _ = conn.Write([]byte("abcdefgh"))
	})
	defer closeServer()

	client := NewClient(WithLimits(Limits{MaxResponseBytes: 4}))
	response, err := client.Query(context.Background(), endpoint, "example")
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Query() error = %v, want ErrResponseTooLarge", err)
	}
	if !response.Truncated || string(response.Body) != "abcd" {
		t.Fatalf("response = %#v", response)
	}
	if response.Error == nil {
		t.Fatal("response error = nil, want retained request error")
	}
}

func TestQueryRejectsMultipleLines(t *testing.T) {
	t.Parallel()

	_, err := NewClient().Query(context.Background(), Endpoint{Host: "127.0.0.1"}, "one\r\ntwo")
	if !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("Query() error = %v, want ErrInvalidQuery", err)
	}
}

func TestQueryIdleTimeout(t *testing.T) {
	t.Parallel()

	endpoint, _, closeServer := serveOnce(t, func(conn net.Conn, request string) {
		time.Sleep(250 * time.Millisecond)
	})
	defer closeServer()

	client := NewClient(WithLimits(Limits{
		OperationTimeout: time.Second,
		IdleTimeout:      25 * time.Millisecond,
	}))
	started := time.Now()
	_, err := client.Query(context.Background(), endpoint, "example")
	if err == nil {
		t.Fatal("Query() error = nil, want timeout")
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("Query() took %v", elapsed)
	}
}

func TestQueryHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewClient().Query(ctx, Endpoint{Host: "127.0.0.1", Port: 43}, "example")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Query() error = %v, want context.Canceled", err)
	}
}

func TestEndpointPolicies(t *testing.T) {
	t.Parallel()

	if !AllowAnyEndpoint(Endpoint{}, netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("AllowAnyEndpoint rejected loopback")
	}
	for _, test := range []struct {
		endpoint Endpoint
		address  string
		want     bool
	}{
		{Endpoint{Port: 43}, "1.1.1.1", true},
		{Endpoint{Port: 4321}, "2001:4860:4860::8888", true},
		{Endpoint{Port: 80}, "1.1.1.1", false},
		{Endpoint{Port: 43}, "127.0.0.1", false},
		{Endpoint{Port: 43}, "10.0.0.1", false},
		{Endpoint{Port: 43}, "2001:db8::1", false},
		{Endpoint{Port: 43}, "64:ff9b::a00:1", false},
		{Endpoint{Port: 43}, "fec0::1", false},
	} {
		if got := PublicWHOISEndpoint(test.endpoint, netip.MustParseAddr(test.address)); got != test.want {
			t.Errorf("PublicWHOISEndpoint(%#v, %s) = %v, want %v", test.endpoint, test.address, got, test.want)
		}
	}
}

func TestQueryRejectsDisallowedResolvedAddressBeforeDial(t *testing.T) {
	t.Parallel()
	dialer := &countingDialer{}
	client := NewClient(
		WithResolver(staticResolver{addresses: map[string][]netip.Addr{
			"private.test": {netip.MustParseAddr("127.0.0.1")},
		}}),
		WithDialer(dialer),
		WithDirectEndpointPolicy(PublicWHOISEndpoint),
	)
	_, err := client.Query(context.Background(), Endpoint{Host: "private.test", Port: 43}, "example")
	if !errors.Is(err, ErrDisallowedEndpoint) {
		t.Fatalf("Query() error = %v, want ErrDisallowedEndpoint", err)
	}
	if dialer.calls != 0 {
		t.Fatalf("DialContext() calls = %d, want 0", dialer.calls)
	}
}

func TestLookupFollowsReferralAndPreservesHops(t *testing.T) {
	t.Parallel()

	firstEndpoint, firstRequests, closeFirst := serveOnce(t, func(conn net.Conn, request string) {
		_, _ = conn.Write([]byte("Domain Name: EXAMPLE.COM\r\nRegistrar WHOIS Server: registrar.test:4444\r\n"))
	})
	defer closeFirst()
	secondEndpoint, secondRequests, closeSecond := serveOnce(t, func(conn net.Conn, request string) {
		_, _ = conn.Write([]byte("answer\r\n"))
	})
	defer closeSecond()

	resolver := staticResolver{addresses: map[string][]netip.Addr{
		"whois.verisign-grs.com": {netip.MustParseAddr("203.0.113.1")},
		"registrar.test":         {netip.MustParseAddr("203.0.113.2")},
	}}
	dialer := &mappingDialer{targets: map[string]string{
		net.JoinHostPort("203.0.113.1", "43"):   firstEndpoint.String(),
		net.JoinHostPort("203.0.113.2", "4444"): secondEndpoint.String(),
	}}
	client := NewClient(
		WithResolver(resolver),
		WithDialer(dialer),
		WithLookupEndpointPolicy(AllowAnyEndpoint),
	)

	result, err := client.Lookup(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if result.Query != "example.com" || len(result.Responses) != 2 {
		t.Fatalf("result = %#v", result)
	}
	if got := <-firstRequests; got != "domain example.com\r\n" {
		t.Fatalf("first request = %q", got)
	}
	if got := <-secondRequests; got != "example.com\r\n" {
		t.Fatalf("second request = %q", got)
	}
	if result.Responses[0].Referral == nil || result.Responses[0].Referral.Host != "registrar.test" {
		t.Fatalf("referral = %#v", result.Responses[0].Referral)
	}
}

func TestLookupDetectsReferralLoop(t *testing.T) {
	t.Parallel()

	firstEndpoint, _, closeFirst := serveOnce(t, func(conn net.Conn, request string) {
		_, _ = conn.Write([]byte("Domain Name: EXAMPLE.COM\r\nRegistrar WHOIS Server: registrar.test:4445\r\n"))
	})
	defer closeFirst()
	secondEndpoint, _, closeSecond := serveOnce(t, func(conn net.Conn, request string) {
		_, _ = conn.Write([]byte("Registrar WHOIS Server: whois.verisign-grs.com\r\n"))
	})
	defer closeSecond()

	client := NewClient(
		WithResolver(staticResolver{addresses: map[string][]netip.Addr{
			"whois.verisign-grs.com": {netip.MustParseAddr("203.0.113.3")},
			"registrar.test":         {netip.MustParseAddr("203.0.113.4")},
		}}),
		WithDialer(&mappingDialer{targets: map[string]string{
			net.JoinHostPort("203.0.113.3", "43"):   firstEndpoint.String(),
			net.JoinHostPort("203.0.113.4", "4445"): secondEndpoint.String(),
		}}),
		WithLookupEndpointPolicy(AllowAnyEndpoint),
	)

	result, err := client.Lookup(context.Background(), "example.com")
	if !errors.Is(err, ErrReferralLoop) {
		t.Fatalf("Lookup() error = %v, want ErrReferralLoop", err)
	}
	if len(result.Responses) != 2 {
		t.Fatalf("responses = %d, want 2", len(result.Responses))
	}
}

func TestLookupHopLimitReturnsPartialResult(t *testing.T) {
	t.Parallel()

	endpoint, _, closeServer := serveOnce(t, func(conn net.Conn, request string) {
		_, _ = conn.Write([]byte("Domain Name: EXAMPLE.COM\r\nRegistrar WHOIS Server: registrar.test\r\n"))
	})
	defer closeServer()
	client := NewClient(
		WithResolver(staticResolver{addresses: map[string][]netip.Addr{
			"whois.verisign-grs.com": {netip.MustParseAddr("203.0.113.5")},
		}}),
		WithDialer(&mappingDialer{targets: map[string]string{
			net.JoinHostPort("203.0.113.5", "43"): endpoint.String(),
		}}),
		WithLookupEndpointPolicy(AllowAnyEndpoint),
		WithLimits(Limits{MaxHops: 1}),
	)
	result, err := client.Lookup(context.Background(), "example.com")
	if !errors.Is(err, ErrTooManyReferrals) {
		t.Fatalf("Lookup() error = %v, want ErrTooManyReferrals", err)
	}
	if len(result.Responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(result.Responses))
	}
}

func TestLookupReturnsCompletedHopWhenReferralFails(t *testing.T) {
	t.Parallel()

	endpoint, _, closeServer := serveOnce(t, func(conn net.Conn, request string) {
		_, _ = conn.Write([]byte("Domain Name: EXAMPLE.COM\r\nRegistrar WHOIS Server: missing.test\r\n"))
	})
	defer closeServer()
	client := NewClient(
		WithResolver(staticResolver{addresses: map[string][]netip.Addr{
			"whois.verisign-grs.com": {netip.MustParseAddr("203.0.113.6")},
		}}),
		WithDialer(&mappingDialer{targets: map[string]string{
			net.JoinHostPort("203.0.113.6", "43"): endpoint.String(),
		}}),
		WithLookupEndpointPolicy(AllowAnyEndpoint),
	)
	result, err := client.Lookup(context.Background(), "example.com")
	if err == nil {
		t.Fatal("Lookup() error = nil, want referral resolution failure")
	}
	if len(result.Responses) != 2 || result.Responses[0].Referral == nil {
		t.Fatalf("result = %#v", result)
	}
	if result.Responses[1].Endpoint.Host != "missing.test" || result.Responses[1].Error == nil {
		t.Fatalf("failed referral response = %#v", result.Responses[1])
	}
}

func serveOnce(t *testing.T, handler func(net.Conn, string)) (Endpoint, <-chan string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portValue, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	var once sync.Once
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		request, _ := bufio.NewReader(conn).ReadString('\n')
		received <- request
		handler(conn, request)
	}()
	return Endpoint{Host: host, Port: uint16(port)}, received, func() {
		once.Do(func() { _ = listener.Close() })
	}
}

type staticResolver struct {
	addresses map[string][]netip.Addr
}

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addresses := r.addresses[strings.ToLower(host)]
	if len(addresses) == 0 {
		return nil, &net.DNSError{Name: host, Err: "not found", IsNotFound: true}
	}
	return addresses, nil
}

type mappingDialer struct {
	targets map[string]string
}

func (d *mappingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target := d.targets[address]
	if target == "" {
		return nil, &net.AddrError{Err: "unexpected test address", Addr: address}
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, target)
}

type countingDialer struct {
	calls int
}

func (d *countingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.calls++
	return nil, &net.AddrError{Err: "unexpected dial", Addr: address}
}
