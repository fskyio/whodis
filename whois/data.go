package whois

//go:generate go run ./internal/cmd/update-data -output generated_data.go

import (
	"net/netip"
	"strings"
)

type routeEntry struct {
	Endpoint Endpoint
	WebURL   string
	Mode     referralMode
}

type networkRoute struct {
	Prefix   netip.Prefix
	Endpoint Endpoint
}

type asnRoute struct {
	First    uint32
	Last     uint32
	Endpoint Endpoint
}

// Curated entries cover multi-label public registries and known routing
// exceptions that are not represented by IANA's top-level delegation data.
// They are intentionally maintained separately from generatedData. The
// CentralNic SLD list is published at
// https://centralnicregistry.com/policies/dispute/. The .uk and commercial
// .za endpoints are documented by their registry operators at
// https://registrars.nominet.uk/uk-namespace/registration-and-domain-management/query-tools/whois/
// and https://registry.net.za/content.php?contentid=171.
var curatedDomainRoutes = map[string]routeEntry{
	"ac.uk":      serverRoute("whois.nic.ac.uk"),
	"ae.org":     serverRoute("whois.centralnic.com"),
	"br.com":     serverRoute("whois.centralnic.com"),
	"cn.com":     serverRoute("whois.centralnic.com"),
	"co.ca":      serverRoute("whois.co.ca"),
	"co.za":      serverRoute("whois.registry.net.za"),
	"com.de":     serverRoute("whois.centralnic.com"),
	"com.se":     serverRoute("whois.centralnic.com"),
	"de.com":     serverRoute("whois.centralnic.com"),
	"eu.com":     serverRoute("whois.centralnic.com"),
	"gb.net":     serverRoute("whois.centralnic.com"),
	"gr.com":     serverRoute("whois.centralnic.com"),
	"gov.scot":   serverRoute("whois.nic.gov.scot"),
	"gov.wales":  serverRoute("whois.nic.gov.wales"),
	"hu.net":     serverRoute("whois.centralnic.com"),
	"jp.net":     serverRoute("whois.centralnic.com"),
	"jpn.com":    serverRoute("whois.centralnic.com"),
	"llyw.cymru": serverRoute("whois.nic.llyw.cymru"),
	"mex.com":    serverRoute("whois.centralnic.com"),
	"net.za":     serverRoute("net-whois.registry.net.za"),
	"org.za":     serverRoute("org-whois.registry.net.za"),
	"priv.at":    serverRoute("whois.nic.priv.at"),
	"ru.com":     serverRoute("whois.centralnic.com"),
	"sa.com":     serverRoute("whois.centralnic.com"),
	"se.net":     serverRoute("whois.centralnic.com"),
	"uk.com":     serverRoute("whois.centralnic.com"),
	"uk.net":     serverRoute("whois.centralnic.com"),
	"uk":         serverRoute("whois.nic.uk"),
	"us.com":     serverRoute("whois.centralnic.com"),
	"us.org":     serverRoute("whois.centralnic.com"),
	"web.za":     serverRoute("web-whois.registry.net.za"),
	"e164.arpa":  serverRoute("whois.ripe.net"),
}

var handlePrefixRoutes = map[string]Endpoint{
	"net-":    {Host: "whois.arin.net", Port: 43},
	"netblk-": {Host: "whois.arin.net", Port: 43},
	"denic-":  {Host: "whois.denic.de", Port: 43},
	"as-":     {Host: "whois.ripe.net", Port: 43},
	"rs-":     {Host: "whois.ripe.net", Port: 43},
	"rtrs-":   {Host: "whois.ripe.net", Port: 43},
	"fltr-":   {Host: "whois.ripe.net", Port: 43},
	"prng-":   {Host: "whois.ripe.net", Port: 43},
	"poem-":   {Host: "whois.ripe.net", Port: 43},
	"form-":   {Host: "whois.ripe.net", Port: 43},
	"pgpkey-": {Host: "whois.ripe.net", Port: 43},
}

var handleSuffixRoutes = map[string]Endpoint{
	"-arin":    {Host: "whois.arin.net", Port: 43},
	"-ap":      {Host: "whois.apnic.net", Port: 43},
	"-afrinic": {Host: "whois.afrinic.net", Port: 43},
	"-cznic":   {Host: "whois.nic.cz", Port: 43},
	"-dk":      {Host: "whois.punktum.dk", Port: 43},
	"-lacnic":  {Host: "whois.lacnic.net", Port: 43},
	"-mnt":     {Host: "whois.ripe.net", Port: 43},
	"-nicat":   {Host: "whois.nic.at", Port: 43},
	"-norid":   {Host: "whois.norid.no", Port: 43},
	"-ripe":    {Host: "whois.ripe.net", Port: 43},
}

// Documentation and private-use ASNs are commonly represented in RPSL even
// though IANA does not delegate them to an RIR WHOIS service. RIPE's database
// is the conventional global RPSL lookup point for these ranges (RFCs 5398
// and 6996).
var curatedASNRoutes = []asnRoute{
	{First: 64_496, Last: 65_534, Endpoint: Endpoint{Host: "whois.ripe.net", Port: 43}},
	{First: 4_200_000_000, Last: 4_294_967_294, Endpoint: Endpoint{Host: "whois.ripe.net", Port: 43}},
}

// The IANA IPv4 allocation registry has no WHOIS field for these reserved
// /8s, while ARIN publishes their special-use records. Other special IPv4
// blocks inherit a usable server from their allocated parent range.
var curatedNetworkRoutes = []networkRoute{
	{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Endpoint: Endpoint{Host: "whois.arin.net", Port: 43}},
	{Prefix: netip.MustParsePrefix("127.0.0.0/8"), Endpoint: Endpoint{Host: "whois.arin.net", Port: 43}},
}

var ripeLikeServers = map[string]struct{}{
	"whois.ripe.net":    {},
	"whois.apnic.net":   {},
	"whois.afrinic.net": {},
	"rr.arin.net":       {},
	"rr.level3.net":     {},
	"rr.ntt.net":        {},
	"whois.ripn.net":    {},
	"whois.register.si": {},
	"whois.nic.ir":      {},
	"whois.tcinet.ru":   {},
}

func serverRoute(host string) routeEntry {
	return routeEntry{Endpoint: Endpoint{Host: host, Port: 43}, Mode: referralGeneric}
}

func findDomainRoute(domain string) (routeEntry, bool) {
	labels := strings.Split(domain, ".")
	for index := 0; index < len(labels); index++ {
		suffix := strings.Join(labels[index:], ".")
		if route, ok := curatedDomainRoutes[suffix]; ok {
			return route, true
		}
		if route, ok := generatedTLDData[suffix]; ok {
			return route, true
		}
	}
	return routeEntry{}, false
}

func findNetworkRoute(address netip.Addr) (Endpoint, bool) {
	address = address.Unmap()
	routes := generatedIPv6Routes
	if address.Is4() {
		routes = generatedIPv4Routes
	}
	var best networkRoute
	found := false
	for _, candidates := range [][]networkRoute{curatedNetworkRoutes, routes} {
		for _, route := range candidates {
			if route.Prefix.Contains(address) && (!found || route.Prefix.Bits() > best.Prefix.Bits()) {
				best = route
				found = true
			}
		}
	}
	return best.Endpoint, found
}

func findASNRoute(asn uint32) (Endpoint, bool) {
	for _, route := range curatedASNRoutes {
		if asn >= route.First && asn <= route.Last {
			return route.Endpoint, true
		}
	}
	for _, route := range generatedASNRoutes {
		if asn >= route.First && asn <= route.Last {
			return route.Endpoint, true
		}
	}
	return Endpoint{}, false
}
