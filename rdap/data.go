package rdap

//go:generate go run ./internal/cmd/update-data -output generated_data.go

import (
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

type networkRoute struct {
	Prefix netip.Prefix
	URLs   []string
}

type asnRoute struct {
	First uint32
	Last  uint32
	URLs  []string
}

// supplementalDNSRoutes lists working registry RDAP services that are absent
// from the IANA bootstrap registry, which only gTLDs are required to use. They
// are consulted only when no IANA route matches, so a registry that registers
// with IANA takes over on the next snapshot refresh.
var supplementalDNSRoutes = map[string][]string{
	"co": {"https://rdap.registry.co/co/"},
	"de": {"https://rdap.denic.de/"},
	"io": {"https://rdap.identitydigital.services/rdap/"},
}

func findDomainURLs(domain string) []string {
	labels := strings.Split(domain, ".")
	for _, routes := range []map[string][]string{generatedDNSRoutes, supplementalDNSRoutes} {
		for index := range labels {
			if values := routes[strings.Join(labels[index:], ".")]; len(values) > 0 {
				return orderedURLs(values)
			}
		}
	}
	return nil
}

func findNetworkURLs(address netip.Addr) []string {
	routes := generatedIPv6Routes
	if address.Unmap().Is4() {
		routes = generatedIPv4Routes
		address = address.Unmap()
	}
	for _, route := range routes {
		if route.Prefix.Contains(address) {
			return orderedURLs(route.URLs)
		}
	}
	return nil
}

func findASNURLs(asn uint32) []string {
	for _, route := range generatedASNRoutes {
		if asn >= route.First && asn <= route.Last {
			return orderedURLs(route.URLs)
		}
	}
	return nil
}

func findObjectTagURLs(handle string) []string {
	index := strings.LastIndex(handle, "-")
	if index < 0 || index+1 == len(handle) {
		return nil
	}
	return orderedURLs(generatedObjectTagRoutes[strings.ToUpper(handle[index+1:])])
}

func orderedURLs(values []string) []string {
	result := append([]string(nil), values...)
	sort.SliceStable(result, func(i, j int) bool {
		a, _ := url.Parse(result[i])
		b, _ := url.Parse(result[j])
		return a.Scheme == "https" && b.Scheme != "https"
	})
	return result
}
