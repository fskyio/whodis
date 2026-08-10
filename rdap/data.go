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

func findDomainURLs(domain string) []string {
	labels := strings.Split(domain, ".")
	for index := 0; index < len(labels); index++ {
		if values := generatedDNSRoutes[strings.Join(labels[index:], ".")]; len(values) > 0 {
			return orderedURLs(values)
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
