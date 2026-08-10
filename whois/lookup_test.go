package whois

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"testing"
)

func TestClassifyQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input      string
		kind       resourceKind
		normalized string
		query      string
	}{
		{" BÜCHER.de. ", kindDomain, "xn--bcher-kva.de", "xn--bcher-kva.de"},
		{"AS 64496", kindASN, "AS64496", "AS64496"},
		{"192.0.2.9/24", kindPrefix, "192.0.2.0/24", "192.0.2.0/24"},
		{"1.0.0.127.in-addr.arpa.", kindReverse, "1.0.0.127.in-addr.arpa", "1.0.0.127.in-addr.arpa"},
		{"8.b.d.0.1.0.0.2.ip6.arpa", kindReverse, "8.b.d.0.1.0.0.2.ip6.arpa", "8.b.d.0.1.0.0.2.ip6.arpa"},
		{"2002:c000:0201::1", kindAddress, "2002:c000:201::1", "192.0.2.1"},
		{"2001:0000:4136:e378:8000:63bf:3fff:fdd2", kindAddress, "2001:0:4136:e378:8000:63bf:3fff:fdd2", "192.0.2.45"},
		{"NET-EXAMPLE", kindHandle, "NET-EXAMPLE", "NET-EXAMPLE"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			got, err := classifyQuery(test.input, defaultMaxQueryBytes)
			if err != nil {
				t.Fatalf("classifyQuery() error = %v", err)
			}
			if got.kind != test.kind || got.normalized != test.normalized || got.query != test.query {
				t.Fatalf("classifyQuery() = %#v", got)
			}
		})
	}
}

func TestClassifyRejectsServerSyntax(t *testing.T) {
	t.Parallel()
	for _, query := range []string{"domain example.com", "bad_label.example", "."} {
		_, err := classifyQuery(query, defaultMaxQueryBytes)
		if !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("classifyQuery(%q) error = %v, want ErrInvalidQuery", query, err)
		}
	}
}

func TestFormatQuery(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host  string
		query string
		kind  resourceKind
		want  string
	}{
		{"whois.verisign-grs.com", "example.com", kindDomain, "domain example.com"},
		{"whois.verisign-grs.com", "www.example.com", kindDomain, "www.example.com"},
		{"whois.denic.de", "example.de", kindDomain, "-T dn,ace example.de"},
		{"whois.punktum.dk", "example.dk", kindDomain, "--show-handles example.dk"},
		{"whois.arin.net", "AS64496", kindASN, "a 64496"},
		{"whois.arin.net", "192.0.2.1", kindAddress, "n + 192.0.2.1"},
		{"whois.arin.net", "192.0.2.0/24", kindPrefix, "r + = 192.0.2.0/24"},
		{"whois.arin.net", "1.0.0.127.in-addr.arpa", kindReverse, "1.0.0.127.in-addr.arpa"},
		{"whois.apnic.net", "1.1.1.in-addr.arpa", kindReverse, "-V whodis 1.1.1.in-addr.arpa"},
		{"whois.ripe.net", "AS3333", kindASN, "-V whodis AS3333"},
		{"whois.jprs.jp", "example.jp", kindDomain, "example.jp/e"},
		{"whois.nic.ad.jp", "AS2516", kindASN, "AS 2516/e"},
		{"whois.nic.ad.jp", "133.1.1.1", kindAddress, "133.1.1.1/e"},
	}
	for _, test := range tests {
		if got := formatQuery(Endpoint{Host: test.host, Port: 43}, test.query, test.kind); got != test.want {
			t.Errorf("formatQuery(%s, %q) = %q, want %q", test.host, test.query, got, test.want)
		}
	}
}

func TestReferralParsers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode referralMode
		body string
		want Endpoint
	}{
		{referralIANA, "refer: whois.example.test\r\n", Endpoint{Host: "whois.example.test", Port: 43}},
		{referralARIN, "ReferralServer: whois://old.test\nReferralServer: rwhois://new.test:4321/\n", Endpoint{Host: "new.test", Port: 4321}},
		{referralVerisign, "   Domain Name: EXAMPLE.COM\n   Registrar WHOIS Server: registrar.test\n", Endpoint{Host: "registrar.test", Port: 43}},
		{referralGeneric, "Registrar WHOIS Server: whois.registrar.test:4343\n", Endpoint{Host: "whois.registrar.test", Port: 4343}},
		{referralAPNIC, "descr: Transferred to the RIPE NCC\nmnt-by: APNIC-STUB\n\n", Endpoint{Host: "whois.ripe.net", Port: 43}},
		{referralAPNIC, "remarks: Authoritative data can be queried at whois.nic.ad.jp.\n", Endpoint{Host: "whois.nic.ad.jp", Port: 43}},
	}
	for _, test := range tests {
		got := findReferral(Endpoint{Host: "initial.test", Port: 43}, test.mode, []byte(test.body))
		if got == nil || *got != test.want {
			t.Errorf("findReferral(%d) = %#v, want %#v", test.mode, got, test.want)
		}
	}
}

func TestGeneratedRoutingData(t *testing.T) {
	t.Parallel()
	if route, ok := findDomainRoute("example.com"); !ok || route.Endpoint.Host == "" {
		t.Fatalf(".com route = %#v, %v", route, ok)
	}
	if endpoint, ok := findNetworkRoute(netip.MustParseAddr("1.1.1.1")); !ok || endpoint.Host == "" {
		t.Fatalf("IPv4 route = %#v, %v", endpoint, ok)
	}
	for _, address := range []string{"10.0.0.1", "127.0.0.1"} {
		if endpoint, ok := findNetworkRoute(netip.MustParseAddr(address)); !ok || endpoint.Host != "whois.arin.net" {
			t.Errorf("special IPv4 route for %s = %#v, %v", address, endpoint, ok)
		}
	}
	if endpoint, ok := findNetworkRoute(netip.MustParseAddr("2a00:1450::1")); !ok || endpoint.Host == "" {
		t.Fatalf("IPv6 route = %#v, %v", endpoint, ok)
	}
	if endpoint, ok := findASNRoute(3333); !ok || endpoint.Host == "" {
		t.Fatalf("ASN route = %#v, %v", endpoint, ok)
	}
	if endpoint, ok := findASNRoute(64512); !ok || endpoint.Host != "whois.ripe.net" {
		t.Fatalf("private ASN route = %#v, %v", endpoint, ok)
	}
}

func TestCuratedDomainAndHandleRoutes(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"example.co.uk":      "whois.nic.uk",
		"example.ac.uk":      "whois.nic.ac.uk",
		"example.co.ca":      "whois.co.ca",
		"example.priv.at":    "whois.nic.priv.at",
		"example.co.za":      "whois.registry.net.za",
		"example.org.za":     "org-whois.registry.net.za",
		"example.net.za":     "net-whois.registry.net.za",
		"example.web.za":     "web-whois.registry.net.za",
		"example.gov.scot":   "whois.nic.gov.scot",
		"example.gov.wales":  "whois.nic.gov.wales",
		"example.llyw.cymru": "whois.nic.llyw.cymru",
	}
	for domain, want := range tests {
		route, ok := findDomainRoute(domain)
		if !ok || route.Endpoint.Host != want {
			t.Errorf("findDomainRoute(%q) = %#v, %v; want %s", domain, route, ok, want)
		}
	}

	target, err := classifyQuery("RIPE-NCC-HM-MNT", defaultMaxQueryBytes)
	if err != nil {
		t.Fatal(err)
	}
	route, err := routeTarget(target)
	if err != nil || route.Endpoint.Host != "whois.ripe.net" {
		t.Errorf("RIPE maintainer route = %#v, %v", route, err)
	}

	for handle, want := range map[string]string{
		"TEST-CZNIC": "whois.nic.cz",
		"TEST-DK":    "whois.punktum.dk",
		"TEST-NICAT": "whois.nic.at",
		"TEST-NORID": "whois.norid.no",
	} {
		target, err = classifyQuery(handle, defaultMaxQueryBytes)
		if err != nil {
			t.Fatal(err)
		}
		route, err = routeTarget(target)
		if err != nil || route.Endpoint.Host != want {
			t.Errorf("NIC handle %q route = %#v, %v; want %s", handle, route, err, want)
		}
	}

	for _, handle := range []string{"AZ1234JP", "JP12345678"} {
		target, err = classifyQuery(handle, defaultMaxQueryBytes)
		if err != nil {
			t.Fatal(err)
		}
		route, err = routeTarget(target)
		if err != nil || route.Endpoint.Host != "whois.nic.ad.jp" {
			t.Errorf("JPNIC handle %q route = %#v, %v", handle, route, err)
		}
	}
}

func TestNoServerErrorIncludesRegistryURL(t *testing.T) {
	t.Parallel()
	target, err := classifyQuery("example.al", defaultMaxQueryBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = routeTarget(target)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("routeTarget() error = %v, want ErrNoServer", err)
	}
	var noServer *NoServerError
	if !errors.As(err, &noServer) || noServer.WebURL == "" {
		t.Fatalf("routeTarget() error = %#v", err)
	}
}

func TestGeneratedRoutingDataInvariants(t *testing.T) {
	t.Parallel()
	for name, route := range generatedTLDData {
		if name == "" || name != strings.ToLower(name) || strings.Contains(name, ".") {
			t.Fatalf("invalid TLD key %q", name)
		}
		if route.Endpoint.Host == "" {
			continue
		}
		if normalized, err := normalizeEndpoint(route.Endpoint); err != nil || normalized != route.Endpoint {
			t.Errorf("TLD %q endpoint = %#v, normalize error %v", name, route.Endpoint, err)
		}
	}

	for name, routes := range map[string][]networkRoute{
		"IPv4": generatedIPv4Routes,
		"IPv6": generatedIPv6Routes,
	} {
		if !sort.SliceIsSorted(routes, func(i, j int) bool {
			if routes[i].Prefix.Bits() != routes[j].Prefix.Bits() {
				return routes[i].Prefix.Bits() > routes[j].Prefix.Bits()
			}
			return routes[i].Prefix.String() < routes[j].Prefix.String()
		}) {
			t.Errorf("%s routes are not sorted most-specific-first", name)
		}
		seen := make(map[netip.Prefix]struct{}, len(routes))
		for _, route := range routes {
			if !route.Prefix.IsValid() || route.Prefix != route.Prefix.Masked() {
				t.Errorf("%s contains invalid prefix %v", name, route.Prefix)
			}
			if _, exists := seen[route.Prefix]; exists {
				t.Errorf("%s contains duplicate prefix %v", name, route.Prefix)
			}
			seen[route.Prefix] = struct{}{}
			if _, err := normalizeEndpoint(route.Endpoint); err != nil {
				t.Errorf("%s prefix %v endpoint: %v", name, route.Prefix, err)
			}
		}
	}

	for index, route := range generatedASNRoutes {
		if route.First > route.Last {
			t.Errorf("ASN route is reversed: %#v", route)
		}
		if index > 0 && generatedASNRoutes[index-1].Last >= route.First {
			t.Errorf("ASN routes overlap or are unsorted: %#v and %#v", generatedASNRoutes[index-1], route)
		}
		if _, err := normalizeEndpoint(route.Endpoint); err != nil {
			t.Errorf("ASN range %d-%d endpoint: %v", route.First, route.Last, err)
		}
	}

	seenSpecial := make(map[netip.Prefix]struct{}, len(generatedNonPublicPrefixes))
	for _, prefix := range generatedNonPublicPrefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			t.Errorf("invalid special-purpose prefix %v", prefix)
		}
		if _, exists := seenSpecial[prefix]; exists {
			t.Errorf("duplicate special-purpose prefix %v", prefix)
		}
		seenSpecial[prefix] = struct{}{}
	}
}
