package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseTLDPage(t *testing.T) {
	t.Parallel()
	body := []byte(`<p>(Generic top-level domain)</p>
<p><b>URL for registration services:</b> <a href="https://registry.test/">registry</a><br/>
<b>WHOIS Server:</b> WHOIS.NIC.EXAMPLE <br></p>`)
	got := parseTLDPage("EXAMPLE", body)
	if got.Name != "example" || got.Type != "generic" || got.Server != "whois.nic.example" || got.WebURL != "https://registry.test/" || got.Mode != "referralGeneric" {
		t.Fatalf("parseTLDPage() = %#v", got)
	}
}

func TestParseTLDPageInfersGenericWHOIS(t *testing.T) {
	t.Parallel()
	got := parseTLDPage("ACADEMY", []byte(`<p>(Generic top-level domain)</p>`))
	if got.Server != "whois.nic.academy" || got.Mode != "referralGeneric" || !got.Inferred {
		t.Fatalf("parseTLDPage() = %#v", got)
	}
}

func TestValidateInferredTLD(t *testing.T) {
	t.Parallel()

	inferred := tldRecord{Name: "example", Server: "whois.nic.example", Mode: "referralGeneric", Inferred: true}
	got := validateInferredTLD(context.Background(), stubResolver{err: errors.New("not found")}, inferred)
	if got.Server != "" || got.Mode != "" {
		t.Fatalf("unresolvable inferred record = %#v", got)
	}

	got = validateInferredTLD(context.Background(), stubResolver{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, inferred)
	if got.Server != inferred.Server || got.Mode != inferred.Mode {
		t.Fatalf("resolvable inferred record = %#v", got)
	}

	explicit := tldRecord{Name: "example", Server: "whois.registry.example", Mode: "referralGeneric"}
	got = validateInferredTLD(context.Background(), stubResolver{err: errors.New("temporary failure")}, explicit)
	if got.Server != explicit.Server {
		t.Fatalf("explicit record = %#v", got)
	}
}

func TestParseNumberRange(t *testing.T) {
	t.Parallel()
	first, last, err := parseNumberRange("64496-64511")
	if err != nil || first != 64496 || last != 64511 {
		t.Fatalf("parseNumberRange() = %d, %d, %v", first, last, err)
	}
	if _, _, err := parseNumberRange("2-1"); err == nil {
		t.Fatal("parseNumberRange() accepted reversed range")
	}
}

func TestRenderSnapshot(t *testing.T) {
	t.Parallel()
	data := snapshot{
		Generated: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		TLDs:      []tldRecord{{Name: "example", Server: "whois.example", Mode: "referralGeneric"}},
		IPv4:      []prefixRecord{{Prefix: "1.0.0.0/8", Server: "whois.apnic.net"}},
		IPv6:      []prefixRecord{{Prefix: "2001:200::/23", Server: "whois.apnic.net"}},
		ASNs:      []asnRecord{{First: 1, Last: 2, Server: "whois.arin.net"}},
		NonPublic: []string{"10.0.0.0/8"},
		Updated:   map[string]string{},
	}
	got, err := renderSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"generatedTLDData", "whois.example", "1.0.0.0/8", "generatedASNRoutes", "generatedNonPublicPrefixes"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("generated source does not contain %q", want)
		}
	}
}

type stubResolver struct {
	addresses []netip.Addr
	err       error
}

func (r stubResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addresses, r.err
}
