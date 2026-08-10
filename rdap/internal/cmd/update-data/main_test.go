package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestParseAllBootstrapRegistryShapes(t *testing.T) {
	dns, err := parseStringRoutes([][][]string{{{"COM", "example"}, {"https://rdap.example/"}}}, 2, 0, 1, strings.ToLower)
	if err != nil || len(dns) != 2 || dns["com"][0] != "https://rdap.example/" {
		t.Fatalf("DNS routes = %#v, %v", dns, err)
	}
	tags, err := parseStringRoutes([][][]string{{{"ignored"}, {"ripe"}, {"https://rdap.example/"}}}, 3, 1, 2, strings.ToUpper)
	if err != nil || tags["RIPE"][0] != "https://rdap.example/" {
		t.Fatalf("object-tag routes = %#v, %v", tags, err)
	}
	ipv4, err := parseNetworkRoutes([][][]string{{{"192.0.2.1/24", "198.51.100.0/24"}, {"https://rdap.example/"}}})
	if err != nil || len(ipv4) != 2 || ipv4[0].Prefix != "192.0.2.0/24" {
		t.Fatalf("IPv4 routes = %#v, %v", ipv4, err)
	}
	ipv6, err := parseNetworkRoutes([][][]string{{{"2001:db8::1/32"}, {"https://rdap.example/"}}})
	if err != nil || len(ipv6) != 1 || ipv6[0].Prefix != "2001:db8::/32" {
		t.Fatalf("IPv6 routes = %#v, %v", ipv6, err)
	}
	asns, err := parseASNRoutes([][][]string{{{"64496-64511", "65536"}, {"https://rdap.example/"}}})
	if err != nil || len(asns) != 2 || asns[0].First != 64496 || asns[0].Last != 64511 || asns[1].First != asns[1].Last {
		t.Fatalf("ASN routes = %#v, %v", asns, err)
	}
}

func TestBootstrapValidationRejectsMalformedAndDuplicateData(t *testing.T) {
	tests := []struct {
		name string
		call func() error
	}{
		{"shape", func() error {
			_, err := parseStringRoutes([][][]string{{{"com"}}}, 2, 0, 1, strings.ToLower)
			return err
		}},
		{"duplicate key", func() error {
			_, err := parseStringRoutes([][][]string{{{"com", "COM"}, {"https://rdap.example/"}}}, 2, 0, 1, strings.ToLower)
			return err
		}},
		{"missing slash", func() error { _, err := validateURLs([]string{"https://rdap.example/rdap"}); return err }},
		{"duplicate URL", func() error {
			_, err := validateURLs([]string{"https://rdap.example/", "https://rdap.example/"})
			return err
		}},
		{"duplicate prefix", func() error {
			_, err := parseNetworkRoutes([][][]string{{{"192.0.2.0/24", "192.0.2.1/24"}, {"https://rdap.example/"}}})
			return err
		}},
		{"reversed ASN", func() error { _, _, err := parseRange("10-1"); return err }},
		{"overlapping ASN", func() error {
			_, err := parseASNRoutes([][][]string{{{"1-10", "10-20"}, {"https://rdap.example/"}}})
			return err
		}},
		{"duplicate TLD", func() error { _, err := parseTLDs([]byte("COM\ncom\n")); return err }},
		{"malformed TLD", func() error { _, err := parseTLDs([]byte("not_a_tld\n")); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("malformed input was accepted")
			}
		})
	}
}

func TestParseTLDsSortsAndIgnoresMetadata(t *testing.T) {
	got, err := parseTLDs([]byte("# Version 1\nNET\ncom\nXN--P1AI\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "com,net,xn--p1ai" {
		t.Fatalf("TLDs = %#v", got)
	}
}

func TestParseNonPublicRegistry(t *testing.T) {
	body := []byte(`<registry><record><address>192.0.2.0/24</address><global>False</global></record><record><address>8.8.8.0/24</address><global>True</global></record><registry><record><address>2001:db8::/32</address><global>N/A</global></record></registry></registry>`)
	got, err := parseNonPublic(body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "192.0.2.0/24,2001:db8::/32" {
		t.Fatalf("prefixes = %#v", got)
	}
}

func TestRenderSnapshotIsDeterministicAndIncludesMetadata(t *testing.T) {
	data := snapshot{
		Generated: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		Published: map[string]string{"DNS": "2026-08-01T00:00:00Z"},
		TLDs:      []string{"com"},
		DNS: map[string][]string{
			"net": {"https://z.example/"},
			"com": {"https://a.example/"},
		},
		ObjectTags: map[string][]string{"RIPE": {"https://rdap.example/"}},
	}
	first, err := renderSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	second, err := renderSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("rendered output is not deterministic")
	}
	text := string(first)
	for _, want := range []string{"Retrieved: 2026-08-10T12:00:00Z", "DNS publication: 2026-08-01T00:00:00Z", `"com":`, `"RIPE":`} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered source does not contain %q", want)
		}
	}
	if strings.Index(text, `"com":`) > strings.Index(text, `"net":`) {
		t.Fatal("map keys were not sorted")
	}
}
