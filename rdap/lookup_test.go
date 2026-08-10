package rdap

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"foundry.fsky.io/fsky/whodis/internal/target"
)

func TestLookupURLs(t *testing.T) {
	oldTLDs := generatedTLDs
	oldDNS := generatedDNSRoutes
	oldIPv4 := generatedIPv4Routes
	oldIPv6 := generatedIPv6Routes
	oldASNs := generatedASNRoutes
	oldTags := generatedObjectTagRoutes
	t.Cleanup(func() {
		generatedTLDs = oldTLDs
		generatedDNSRoutes = oldDNS
		generatedIPv4Routes = oldIPv4
		generatedIPv6Routes = oldIPv6
		generatedASNRoutes = oldASNs
		generatedObjectTagRoutes = oldTags
	})
	generatedTLDs = map[string]bool{"com": true}
	generatedDNSRoutes = map[string][]string{
		"com":         {"http://rdap.test/", "https://rdap.test/v1/"},
		"private.com": {"https://longest.test/"},
		"example":     {"https://idn.test/"},
	}
	generatedIPv4Routes = []networkRoute{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), URLs: []string{"https://specific.test/"}},
		{Prefix: netip.MustParsePrefix("192.0.0.0/8"), URLs: []string{"https://broad.test/"}},
	}
	generatedIPv6Routes = []networkRoute{{Prefix: netip.MustParsePrefix("2001:db8::/32"), URLs: []string{"https://v6.test/"}}}
	generatedASNRoutes = []asnRoute{{First: 64496, Last: 64511, URLs: []string{"https://asn.test/"}}}
	generatedObjectTagRoutes = map[string][]string{"RIPE": {"https://entity.test/"}}

	tests := []struct {
		query string
		want  []string
	}{
		{"example.com", []string{"https://rdap.test/v1/domain/example.com", "http://rdap.test/domain/example.com"}},
		{"www.private.com", []string{"https://longest.test/domain/www.private.com"}},
		{"bücher.example", []string{"https://idn.test/domain/xn--bcher-kva.example"}},
		{"com", []string{"https://rdap.iana.org/domain/com"}},
		{"192.0.2.42", []string{"https://specific.test/ip/192.0.2.42"}},
		{"192.0.2.99/24", []string{"https://specific.test/ip/192.0.2.0/24"}},
		{"2001:db8::1", []string{"https://v6.test/ip/2001:db8::1"}},
		{"2001:db8:1::1/48", []string{"https://v6.test/ip/2001:db8:1::/48"}},
		{"2.0.192.in-addr.arpa", []string{"https://specific.test/domain/2.0.192.in-addr.arpa"}},
		{"AS 64496", []string{"https://asn.test/autnum/64496"}},
		{"AS64511", []string{"https://asn.test/autnum/64511"}},
		{"OPS4-RIPE", []string{"https://entity.test/entity/OPS4-RIPE"}},
		{"ABC?-ripe", []string{"https://entity.test/entity/ABC%3F-ripe"}},
	}
	for _, test := range tests {
		parsed, err := target.Parse(test.query, defaultMaxQueryBytes)
		if err != nil {
			t.Fatalf("Parse(%q): %v", test.query, err)
		}
		got, _, err := lookupURLs(parsed)
		if err != nil {
			t.Errorf("lookupURLs(%q): %v", test.query, err)
			continue
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("lookupURLs(%q) = %#v, want %#v", test.query, got, test.want)
		}
	}

	parsed, _ := target.Parse("UNKNOWN-HANDLE", defaultMaxQueryBytes)
	if _, _, err := lookupURLs(parsed); !errors.Is(err, ErrNoService) {
		t.Fatalf("unknown handle error = %v", err)
	}
	parsed, _ = target.Parse("example.invalid", defaultMaxQueryBytes)
	if _, _, err := lookupURLs(parsed); !errors.Is(err, ErrNoService) {
		t.Fatalf("unbootstrapped domain error = %v", err)
	}
}

func TestGeneratedDataInvariants(t *testing.T) {
	for name, urls := range generatedDNSRoutes {
		if name == "" || len(urls) == 0 {
			t.Errorf("invalid DNS route %q: %#v", name, urls)
		}
	}
	for label, routes := range map[string][]networkRoute{"IPv4": generatedIPv4Routes, "IPv6": generatedIPv6Routes} {
		seen := make(map[netip.Prefix]struct{})
		lastBits := 129
		for _, route := range routes {
			if route.Prefix.Bits() > lastBits {
				t.Errorf("%s routes not most-specific first", label)
			}
			lastBits = route.Prefix.Bits()
			if route.Prefix != route.Prefix.Masked() || len(route.URLs) == 0 {
				t.Errorf("invalid %s route %#v", label, route)
			}
			if _, exists := seen[route.Prefix]; exists {
				t.Errorf("duplicate %s prefix %s", label, route.Prefix)
			}
			seen[route.Prefix] = struct{}{}
		}
	}
	for index, route := range generatedASNRoutes {
		if route.First > route.Last || len(route.URLs) == 0 {
			t.Errorf("invalid ASN route %#v", route)
		}
		if index > 0 && generatedASNRoutes[index-1].Last >= route.First {
			t.Errorf("overlapping ASN routes %#v and %#v", generatedASNRoutes[index-1], route)
		}
	}
}
