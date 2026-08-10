// Command update-data refreshes the checked-in WHOIS routing snapshot from
// public IANA registries. It is intentionally a maintainer tool: normal builds
// and library use never access HTTP services.
package main

import (
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tldListURL     = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	tldPageURL     = "https://www.iana.org/domains/root/db/%s.html"
	ipv4URL        = "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xml"
	ipv6URL        = "https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xml"
	asnURL         = "https://www.iana.org/assignments/as-numbers/as-numbers.xml"
	ipv4SpecialURL = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xml"
	ipv6SpecialURL = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xml"
)

var (
	whoisPattern = regexp.MustCompile(`(?is)<b>\s*WHOIS Server:\s*</b>\s*([^<\s]+)`)
	webPattern   = regexp.MustCompile(`(?is)<b>\s*URL for registration services:\s*</b>\s*<a[^>]+href=["']([^"']+)`)
	typePattern  = regexp.MustCompile(`(?is)<p>\s*\(([^<()]+) top-level domain\)\s*</p>`)
)

type tldRecord struct {
	Name     string
	Type     string
	Server   string
	WebURL   string
	Mode     string
	Inferred bool
}

type ipResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type prefixRecord struct {
	Prefix string
	Server string
}

type asnRecord struct {
	First  uint32
	Last   uint32
	Server string
}

type xmlRegistry struct {
	Updated    string        `xml:"updated"`
	Records    []xmlRecord   `xml:"record"`
	Registries []xmlRegistry `xml:"registry"`
}

type xmlRecord struct {
	Prefix  string `xml:"prefix"`
	Number  string `xml:"number"`
	Whois   string `xml:"whois"`
	Address string `xml:"address"`
	Global  string `xml:"global"`
}

type snapshot struct {
	Generated time.Time
	TLDs      []tldRecord
	IPv4      []prefixRecord
	IPv6      []prefixRecord
	ASNs      []asnRecord
	NonPublic []string
	Updated   map[string]string
}

func main() {
	output := flag.String("output", "generated_data.go", "path to generated Go source")
	concurrency := flag.Int("concurrency", 8, "maximum concurrent IANA TLD page requests")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}

	data, err := loadSnapshot(ctx, client, *concurrency)
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

	path := *output
	if !filepath.IsAbs(path) {
		path = filepath.Clean(path)
	}
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		fatal(fmt.Errorf("write %s: %w", path, err))
	}
}

func loadSnapshot(ctx context.Context, client *http.Client, concurrency int) (snapshot, error) {
	if concurrency < 1 {
		return snapshot{}, errors.New("concurrency must be positive")
	}

	tlds, err := loadTLDs(ctx, client, net.DefaultResolver, concurrency)
	if err != nil {
		return snapshot{}, err
	}
	ipv4, ipv4Updated, err := loadPrefixes(ctx, client, ipv4URL, true)
	if err != nil {
		return snapshot{}, err
	}
	ipv6, ipv6Updated, err := loadPrefixes(ctx, client, ipv6URL, false)
	if err != nil {
		return snapshot{}, err
	}
	asns, asnUpdated, err := loadASNs(ctx, client)
	if err != nil {
		return snapshot{}, err
	}

	ipv4Special, ipv4SpecialUpdated, err := loadSpecialPrefixes(ctx, client, ipv4SpecialURL)
	if err != nil {
		return snapshot{}, err
	}
	ipv6Special, ipv6SpecialUpdated, err := loadSpecialPrefixes(ctx, client, ipv6SpecialURL)
	if err != nil {
		return snapshot{}, err
	}
	nonPublic := append(ipv4Special, ipv6Special...)
	sort.Strings(nonPublic)

	return snapshot{
		Generated: time.Now().UTC(),
		TLDs:      tlds,
		IPv4:      ipv4,
		IPv6:      ipv6,
		ASNs:      asns,
		NonPublic: nonPublic,
		Updated: map[string]string{
			"IPv4":         ipv4Updated,
			"IPv6":         ipv6Updated,
			"ASN":          asnUpdated,
			"IPv4 special": ipv4SpecialUpdated,
			"IPv6 special": ipv6SpecialUpdated,
		},
	}, nil
}

func loadTLDs(ctx context.Context, client *http.Client, resolver ipResolver, concurrency int) ([]tldRecord, error) {
	body, err := fetch(ctx, client, tldListURL)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}

	type item struct {
		index  int
		record tldRecord
		err    error
	}
	jobs := make(chan int)
	results := make(chan item)
	var workers sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				record, err := loadTLD(ctx, client, resolver, names[index])
				results <- item{index: index, record: record, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range names {
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	records := make([]tldRecord, len(names))
	var firstErr error
	for result := range results {
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
			}
			continue
		}
		records[result.index] = result.record
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	return records, nil
}

func loadTLD(ctx context.Context, client *http.Client, resolver ipResolver, name string) (tldRecord, error) {
	body, err := fetch(ctx, client, fmt.Sprintf(tldPageURL, name))
	if err != nil {
		return tldRecord{}, fmt.Errorf("load TLD %s: %w", name, err)
	}
	record := parseTLDPage(name, body)
	return validateInferredTLD(ctx, resolver, record), nil
}

func validateInferredTLD(ctx context.Context, resolver ipResolver, record tldRecord) tldRecord {
	if record.Inferred {
		resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addresses, resolveErr := resolver.LookupNetIP(resolveCtx, "ip", record.Server)
		cancel()
		if resolveErr != nil || len(addresses) == 0 {
			record.Server = ""
			record.Mode = ""
		}
	}
	return record
}

func parseTLDPage(name string, body []byte) tldRecord {
	record := tldRecord{Name: strings.ToLower(name)}
	if match := typePattern.FindSubmatch(body); len(match) == 2 {
		record.Type = strings.ToLower(strings.TrimSpace(html.UnescapeString(string(match[1]))))
	}
	if match := whoisPattern.FindSubmatch(body); len(match) == 2 {
		record.Server = strings.ToLower(strings.TrimSpace(html.UnescapeString(string(match[1]))))
		switch record.Server {
		case "whois.iana.org":
			record.Mode = "referralIANA"
		case "whois.verisign-grs.com", "ccwhois.verisign-grs.com":
			record.Mode = "referralVerisign"
		default:
			record.Mode = "referralGeneric"
		}
	}
	if match := webPattern.FindSubmatch(body); len(match) == 2 {
		record.WebURL = strings.TrimSpace(html.UnescapeString(string(match[1])))
	}
	// Contracted generic registries conventionally expose WHOIS at
	// whois.nic.<tld>. IANA began removing many WHOIS fields as RDAP became the
	// primary registration-data service, while these compatibility endpoints
	// remained available.
	if record.Server == "" && record.Type == "generic" {
		record.Server = "whois.nic." + record.Name
		record.Mode = "referralGeneric"
		record.Inferred = true
	}
	return record
}

func loadPrefixes(ctx context.Context, client *http.Client, sourceURL string, ipv4 bool) ([]prefixRecord, string, error) {
	body, err := fetch(ctx, client, sourceURL)
	if err != nil {
		return nil, "", err
	}
	var registry xmlRegistry
	if err := xml.Unmarshal(body, &registry); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", sourceURL, err)
	}
	var records []prefixRecord
	walkRecords(registry, func(record xmlRecord) {
		server := strings.ToLower(strings.TrimSpace(record.Whois))
		prefix := strings.TrimSpace(record.Prefix)
		if server == "" || prefix == "" {
			return
		}
		if ipv4 {
			parts := strings.Split(prefix, "/")
			if len(parts) != 2 {
				return
			}
			octet, err := strconv.ParseUint(parts[0], 10, 8)
			if err != nil {
				return
			}
			prefix = fmt.Sprintf("%d.0.0.0/%s", octet, parts[1])
		}
		parsed, err := netip.ParsePrefix(prefix)
		if err != nil {
			return
		}
		records = append(records, prefixRecord{Prefix: parsed.Masked().String(), Server: server})
	})
	sort.Slice(records, func(i, j int) bool {
		a := netip.MustParsePrefix(records[i].Prefix)
		b := netip.MustParsePrefix(records[j].Prefix)
		if a.Bits() != b.Bits() {
			return a.Bits() > b.Bits()
		}
		return records[i].Prefix < records[j].Prefix
	})
	return records, registry.Updated, nil
}

func loadASNs(ctx context.Context, client *http.Client) ([]asnRecord, string, error) {
	body, err := fetch(ctx, client, asnURL)
	if err != nil {
		return nil, "", err
	}
	var registry xmlRegistry
	if err := xml.Unmarshal(body, &registry); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", asnURL, err)
	}
	var records []asnRecord
	walkRecords(registry, func(record xmlRecord) {
		server := strings.ToLower(strings.TrimSpace(record.Whois))
		if server == "" || strings.TrimSpace(record.Number) == "" {
			return
		}
		first, last, err := parseNumberRange(record.Number)
		if err != nil {
			return
		}
		records = append(records, asnRecord{First: first, Last: last, Server: server})
	})
	sort.Slice(records, func(i, j int) bool {
		if records[i].First != records[j].First {
			return records[i].First < records[j].First
		}
		return records[i].Last < records[j].Last
	})
	return records, registry.Updated, nil
}

func loadSpecialPrefixes(ctx context.Context, client *http.Client, sourceURL string) ([]string, string, error) {
	body, err := fetch(ctx, client, sourceURL)
	if err != nil {
		return nil, "", err
	}
	var registry xmlRegistry
	if err := xml.Unmarshal(body, &registry); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", sourceURL, err)
	}
	seen := make(map[netip.Prefix]struct{})
	var prefixes []string
	walkRecords(registry, func(record xmlRecord) {
		globalFields := strings.Fields(record.Global)
		if len(globalFields) > 0 && strings.EqualFold(globalFields[0], "true") {
			return
		}
		for _, value := range strings.Split(record.Address, ",") {
			fields := strings.Fields(value)
			if len(fields) == 0 {
				continue
			}
			prefix, err := netip.ParsePrefix(fields[0])
			if err != nil {
				continue
			}
			prefix = prefix.Masked()
			if _, exists := seen[prefix]; exists {
				continue
			}
			seen[prefix] = struct{}{}
			prefixes = append(prefixes, prefix.String())
		}
	})
	sort.Strings(prefixes)
	return prefixes, registry.Updated, nil
}

func parseNumberRange(value string) (uint32, uint32, error) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) > 2 || len(parts) == 0 {
		return 0, 0, errors.New("invalid range")
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
		return 0, 0, errors.New("range is reversed")
	}
	return uint32(first), uint32(last), nil
}

func walkRecords(registry xmlRegistry, visit func(xmlRecord)) {
	for _, record := range registry.Records {
		visit(record)
	}
	for _, child := range registry.Registries {
		walkRecords(child, visit)
	}
}

func fetch(ctx context.Context, client *http.Client, sourceURL string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "whodis-data-updater/1 (+https://foundry.fsky.io/fsky/whodis)")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", sourceURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("fetch %s: %s", sourceURL, response.Status)
	}
	const maxSourceBytes = 16 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", sourceURL, err)
	}
	if len(body) > maxSourceBytes {
		return nil, fmt.Errorf("read %s: response exceeds %d bytes", sourceURL, maxSourceBytes)
	}
	return body, nil
}

func renderSnapshot(data snapshot) ([]byte, error) {
	var output strings.Builder
	output.WriteString("// Code generated by go generate; DO NOT EDIT.\n")
	output.WriteString("//\n// Sources:\n")
	for _, sourceURL := range []string{tldListURL, "https://www.iana.org/domains/root/db/", ipv4URL, ipv6URL, asnURL, ipv4SpecialURL, ipv6SpecialURL} {
		fmt.Fprintf(&output, "//   - %s\n", sourceURL)
	}
	output.WriteString("// Conventional whois.nic.<tld> fallbacks were retained only when DNS-resolvable.\n")
	fmt.Fprintf(&output, "// Retrieved: %s\n", data.Generated.Format(time.RFC3339))
	for _, key := range []string{"IPv4", "IPv6", "ASN", "IPv4 special", "IPv6 special"} {
		if data.Updated[key] != "" {
			fmt.Fprintf(&output, "// %s registry updated: %s\n", key, data.Updated[key])
		}
	}
	output.WriteString("\npackage whois\n\nimport \"net/netip\"\n\n")

	output.WriteString("var generatedTLDData = map[string]routeEntry{\n")
	for _, record := range data.TLDs {
		fmt.Fprintf(&output, "\t%s: {", strconv.Quote(record.Name))
		if record.Server != "" {
			fmt.Fprintf(&output, "Endpoint: Endpoint{Host: %s, Port: 43}, Mode: %s", strconv.Quote(record.Server), record.Mode)
			if record.WebURL != "" {
				fmt.Fprintf(&output, ", WebURL: %s", strconv.Quote(record.WebURL))
			}
		} else if record.WebURL != "" {
			fmt.Fprintf(&output, "WebURL: %s", strconv.Quote(record.WebURL))
		}
		output.WriteString("},\n")
	}
	output.WriteString("}\n\n")

	renderPrefixes(&output, "generatedIPv4Routes", data.IPv4)
	renderPrefixes(&output, "generatedIPv6Routes", data.IPv6)
	output.WriteString("var generatedASNRoutes = []asnRoute{\n")
	for _, record := range data.ASNs {
		fmt.Fprintf(&output, "\t{First: %d, Last: %d, Endpoint: Endpoint{Host: %s, Port: 43}},\n", record.First, record.Last, strconv.Quote(record.Server))
	}
	output.WriteString("}\n")
	output.WriteString("\nvar generatedNonPublicPrefixes = []netip.Prefix{\n")
	for _, prefix := range data.NonPublic {
		fmt.Fprintf(&output, "\tnetip.MustParsePrefix(%s),\n", strconv.Quote(prefix))
	}
	output.WriteString("}\n")
	return []byte(output.String()), nil
}

func renderPrefixes(output *strings.Builder, name string, records []prefixRecord) {
	fmt.Fprintf(output, "var %s = []networkRoute{\n", name)
	for _, record := range records {
		fmt.Fprintf(output, "\t{Prefix: netip.MustParsePrefix(%s), Endpoint: Endpoint{Host: %s, Port: 43}},\n", strconv.Quote(record.Prefix), strconv.Quote(record.Server))
	}
	output.WriteString("}\n\n")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
