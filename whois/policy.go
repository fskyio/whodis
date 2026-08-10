package whois

import "net/netip"

// These translation and deprecated local prefixes need conservative handling
// in addition to IANA entries marked non-global. In particular, allowing the
// well-known NAT64 prefix would let a DNS answer encode a private IPv4 target.
var supplementalNonPublicPrefixes = mustPrefixes(
	"::/96",
	"64:ff9b::/96",
	"fec0::/10",
)

// AllowAnyEndpoint permits every valid endpoint and address.
func AllowAnyEndpoint(_ Endpoint, _ netip.Addr) bool { return true }

// PublicWHOISEndpoint permits publicly routable addresses on the standard
// WHOIS and RWhois ports.
func PublicWHOISEndpoint(endpoint Endpoint, address netip.Addr) bool {
	port := endpoint.Port
	if port == 0 {
		port = defaultPort
	}
	if port != 43 && port != 4321 {
		return false
	}

	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range generatedNonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	for _, prefix := range supplementalNonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
