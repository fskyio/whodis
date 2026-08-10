// Command update-data refreshes the checked-in RDAP bootstrap snapshot from
// IANA. Normal builds and library use never fetch bootstrap data.
package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	dnsURL         = "https://data.iana.org/rdap/dns.json"
	ipv4URL        = "https://data.iana.org/rdap/ipv4.json"
	ipv6URL        = "https://data.iana.org/rdap/ipv6.json"
	asnURL         = "https://data.iana.org/rdap/asn.json"
	objectTagsURL  = "https://data.iana.org/rdap/object-tags.json"
	tldListURL     = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	ipv4SpecialURL = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xml"
	ipv6SpecialURL = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xml"
)

type registry struct {
	Publication string       `json:"publication"`
	Services    [][][]string `json:"services"`
}

type networkRecord struct {
	Prefix string
	URLs   []string
}

type asnRecord struct {
	First uint32
	Last  uint32
	URLs  []string
}

type snapshot struct {
	Generated  time.Time
	Published  map[string]string
	TLDs       []string
	DNS        map[string][]string
	IPv4       []networkRecord
	IPv6       []networkRecord
	ASNs       []asnRecord
	ObjectTags map[string][]string
	NonPublic  []string
}

type xmlRegistry struct {
	Records    []xmlRecord   `xml:"record"`
	Registries []xmlRegistry `xml:"registry"`
}

type xmlRecord struct {
	Address string `xml:"address"`
	Global  string `xml:"global"`
}

func main() {
	output := flag.String("output", "generated_data.go", "path to generated Go source")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	data, err := loadSnapshot(ctx, client)
	if err != nil {
		fatal(err)
	}
	source, err := renderSnapshot(data)
	if err != nil {
		fatal(err)
	}
	formatted, err := format.Source(source)
	if err != nil {
		fatal(fmt.Errorf("format generated source: %w", err))
	}
	if err := os.WriteFile(*output, formatted, 0o644); err != nil {
		fatal(err)
	}
}

func loadSnapshot(ctx context.Context, client *http.Client) (snapshot, error) {
	data := snapshot{
		Generated:  time.Now().UTC(),
		Published:  make(map[string]string),
		DNS:        make(map[string][]string),
		ObjectTags: make(map[string][]string),
	}

	for name, source := range map[string]string{"DNS": dnsURL, "IPv4": ipv4URL, "IPv6": ipv6URL, "ASN": asnURL, "object tags": objectTagsURL} {
		body, err := fetch(ctx, client, source)
		if err != nil {
			return snapshot{}, err
		}
		var value registry
		if err := json.Unmarshal(body, &value); err != nil {
			return snapshot{}, fmt.Errorf("parse %s: %w", source, err)
		}
		if strings.TrimSpace(value.Publication) == "" {
			return snapshot{}, fmt.Errorf("parse %s: missing publication timestamp", source)
		}
		data.Published[name] = value.Publication
		switch name {
		case "DNS":
			data.DNS, err = parseStringRoutes(value.Services, 2, 0, 1, strings.ToLower)
		case "IPv4", "IPv6":
			var records []networkRecord
			records, err = parseNetworkRoutes(value.Services)
			if name == "IPv4" {
				data.IPv4 = records
			} else {
				data.IPv6 = records
			}
		case "ASN":
			data.ASNs, err = parseASNRoutes(value.Services)
		case "object tags":
			data.ObjectTags, err = parseStringRoutes(value.Services, 3, 1, 2, strings.ToUpper)
		}
		if err != nil {
			return snapshot{}, fmt.Errorf("parse %s: %w", source, err)
		}
	}

	tldBody, err := fetch(ctx, client, tldListURL)
	if err != nil {
		return snapshot{}, err
	}
	data.TLDs, err = parseTLDs(tldBody)
	if err != nil {
		return snapshot{}, fmt.Errorf("parse %s: %w", tldListURL, err)
	}

	for _, source := range []string{ipv4SpecialURL, ipv6SpecialURL} {
		body, err := fetch(ctx, client, source)
		if err != nil {
			return snapshot{}, err
		}
		prefixes, err := parseNonPublic(body)
		if err != nil {
			return snapshot{}, fmt.Errorf("parse %s: %w", source, err)
		}
		data.NonPublic = append(data.NonPublic, prefixes...)
	}
	data.NonPublic = uniqueStrings(data.NonPublic)
	return data, nil
}

func parseTLDs(body []byte) ([]string, error) {
	seen := make(map[string]struct{})
	var result []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 63 || strings.HasPrefix(line, "-") || strings.HasSuffix(line, "-") {
			return nil, fmt.Errorf("invalid TLD %q", line)
		}
		for _, character := range line {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return nil, fmt.Errorf("invalid TLD %q", line)
		}
		if _, exists := seen[line]; exists {
			return nil, fmt.Errorf("duplicate TLD %q", line)
		}
		seen[line] = struct{}{}
		result = append(result, line)
	}
	if len(result) == 0 {
		return nil, errors.New("TLD list is empty")
	}
	sort.Strings(result)
	return result, nil
}

func parseStringRoutes(services [][][]string, width, keyIndex, urlIndex int, normalize func(string) string) (map[string][]string, error) {
	result := make(map[string][]string)
	for _, service := range services {
		if len(service) != width {
			return nil, fmt.Errorf("service has %d arrays, want %d", len(service), width)
		}
		urls, err := validateURLs(service[urlIndex])
		if err != nil {
			return nil, err
		}
		for _, rawKey := range service[keyIndex] {
			key := normalize(strings.TrimSpace(rawKey))
			if key == "" {
				return nil, errors.New("empty service key")
			}
			if _, exists := result[key]; exists {
				return nil, fmt.Errorf("duplicate service key %q", key)
			}
			result[key] = urls
		}
	}
	return result, nil
}

func parseNetworkRoutes(services [][][]string) ([]networkRecord, error) {
	seen := make(map[netip.Prefix]struct{})
	var result []networkRecord
	for _, service := range services {
		if len(service) != 2 {
			return nil, errors.New("network service must have two arrays")
		}
		urls, err := validateURLs(service[1])
		if err != nil {
			return nil, err
		}
		for _, value := range service[0] {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, err
			}
			prefix = prefix.Masked()
			if _, exists := seen[prefix]; exists {
				return nil, fmt.Errorf("duplicate prefix %s", prefix)
			}
			seen[prefix] = struct{}{}
			result = append(result, networkRecord{Prefix: prefix.String(), URLs: urls})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a := netip.MustParsePrefix(result[i].Prefix)
		b := netip.MustParsePrefix(result[j].Prefix)
		if a.Bits() != b.Bits() {
			return a.Bits() > b.Bits()
		}
		return a.String() < b.String()
	})
	return result, nil
}

func parseASNRoutes(services [][][]string) ([]asnRecord, error) {
	var result []asnRecord
	for _, service := range services {
		if len(service) != 2 {
			return nil, errors.New("ASN service must have two arrays")
		}
		urls, err := validateURLs(service[1])
		if err != nil {
			return nil, err
		}
		for _, value := range service[0] {
			first, last, err := parseRange(value)
			if err != nil {
				return nil, err
			}
			result = append(result, asnRecord{First: first, Last: last, URLs: urls})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].First != result[j].First {
			return result[i].First < result[j].First
		}
		return result[i].Last < result[j].Last
	})
	for index := 1; index < len(result); index++ {
		if result[index-1].Last >= result[index].First {
			return nil, fmt.Errorf("overlapping ASN ranges %d-%d and %d-%d", result[index-1].First, result[index-1].Last, result[index].First, result[index].Last)
		}
	}
	return result, nil
}

func parseRange(value string) (uint32, uint32, error) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, errors.New("invalid ASN range")
	}
	first, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return 0, 0, err
	}
	last := first
	if len(parts) == 2 {
		last, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return 0, 0, err
		}
	}
	if first > last {
		return 0, 0, errors.New("reversed ASN range")
	}
	return uint32(first), uint32(last), nil
}

func validateURLs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("service has no URLs")
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{})
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Scheme != "http" && parsed.Scheme != "https" || !strings.HasSuffix(parsed.Path, "/") {
			return nil, fmt.Errorf("invalid RDAP base URL %q", value)
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("duplicate RDAP base URL %q", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func parseNonPublic(body []byte) ([]string, error) {
	var value xmlRegistry
	if err := xml.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	var result []string
	var walk func(xmlRegistry)
	walk = func(current xmlRegistry) {
		for _, record := range current.Records {
			fields := strings.Fields(record.Global)
			if len(fields) > 0 && strings.EqualFold(fields[0], "true") {
				continue
			}
			for _, address := range strings.Split(record.Address, ",") {
				parts := strings.Fields(address)
				if len(parts) == 0 {
					continue
				}
				if prefix, err := netip.ParsePrefix(parts[0]); err == nil {
					result = append(result, prefix.Masked().String())
				}
			}
		}
		for _, child := range current.Registries {
			walk(child)
		}
	}
	walk(value)
	return uniqueStrings(result), nil
}

func uniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func fetch(ctx context.Context, client *http.Client, source string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, http.NoBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "whodis-data-updater/1 (+https://foundry.fsky.io/fsky/whodis)")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", source, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", source, response.Status)
	}
	const limit = 16 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, fmt.Errorf("fetch %s: body is too large", source)
	}
	return body, nil
}

func renderSnapshot(data snapshot) ([]byte, error) {
	var output strings.Builder
	output.WriteString("// Code generated by go generate; DO NOT EDIT.\n")
	output.WriteString("// Sources: IANA RDAP bootstrap, TLD, and special-purpose registries.\n")
	fmt.Fprintf(&output, "// Retrieved: %s\n", data.Generated.Format(time.RFC3339))
	for _, name := range []string{"DNS", "IPv4", "IPv6", "ASN", "object tags"} {
		if data.Published[name] != "" {
			fmt.Fprintf(&output, "// %s publication: %s\n", name, data.Published[name])
		}
	}
	output.WriteString("\npackage rdap\n\nimport \"net/netip\"\n\n")

	output.WriteString("var generatedTLDs = map[string]bool{\n")
	for _, value := range data.TLDs {
		fmt.Fprintf(&output, "\t%s: true,\n", strconv.Quote(value))
	}
	output.WriteString("}\n\n")
	renderStringMap(&output, "generatedDNSRoutes", data.DNS)
	renderNetworks(&output, "generatedIPv4Routes", data.IPv4)
	renderNetworks(&output, "generatedIPv6Routes", data.IPv6)
	output.WriteString("var generatedASNRoutes = []asnRoute{\n")
	for _, record := range data.ASNs {
		fmt.Fprintf(&output, "\t{First: %d, Last: %d, URLs: %#v},\n", record.First, record.Last, record.URLs)
	}
	output.WriteString("}\n\n")
	renderStringMap(&output, "generatedObjectTagRoutes", data.ObjectTags)
	output.WriteString("var generatedNonPublicPrefixes = []netip.Prefix{\n")
	for _, value := range data.NonPublic {
		fmt.Fprintf(&output, "\tnetip.MustParsePrefix(%s),\n", strconv.Quote(value))
	}
	output.WriteString("}\n")
	return []byte(output.String()), nil
}

func renderStringMap(output *strings.Builder, name string, values map[string][]string) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Fprintf(output, "var %s = map[string][]string{\n", name)
	for _, key := range keys {
		fmt.Fprintf(output, "\t%s: %#v,\n", strconv.Quote(key), values[key])
	}
	output.WriteString("}\n\n")
}

func renderNetworks(output *strings.Builder, name string, values []networkRecord) {
	fmt.Fprintf(output, "var %s = []networkRoute{\n", name)
	for _, record := range values {
		fmt.Fprintf(output, "\t{Prefix: netip.MustParsePrefix(%s), URLs: %#v},\n", strconv.Quote(record.Prefix), record.URLs)
	}
	output.WriteString("}\n\n")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
