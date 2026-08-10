package rdap

import "net/netip"

var supplementalNonPublicPrefixes = mustPrefixes(
	"::/96",
	"64:ff9b::/96",
	"fec0::/10",
)

// AllowAnyEndpoint permits every resolved address. It is the default policy
// for caller-directed Query operations.
func AllowAnyEndpoint(_ Endpoint, _ netip.Addr) bool { return true }

// PublicRDAPEndpoint permits public unicast addresses while rejecting IANA
// special-purpose and other non-public destinations.
func PublicRDAPEndpoint(_ Endpoint, address netip.Addr) bool {
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
