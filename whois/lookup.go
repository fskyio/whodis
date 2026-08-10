package whois

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

type resourceKind uint8

const (
	kindUnknown resourceKind = iota
	kindDomain
	kindTLD
	kindAddress
	kindPrefix
	kindReverse
	kindASN
	kindHandle
)

type lookupTarget struct {
	normalized string
	query      string
	kind       resourceKind
	address    netip.Addr
	asn        uint32
}

// Lookup discovers an appropriate WHOIS server, queries it, and follows
// recognized referrals. A non-empty Result may be returned with an error if a
// later hop fails.
func (c *Client) Lookup(ctx context.Context, query string) (Result, error) {
	target, err := classifyQuery(query, c.limits.MaxQueryBytes)
	result := Result{Query: target.normalized}
	if err != nil {
		return result, &OpError{Op: "classify", Err: err}
	}

	route, err := routeTarget(target)
	if err != nil {
		return result, err
	}

	ctx, cancel := c.withOperationTimeout(ctx)
	defer cancel()

	endpoint := route.Endpoint
	mode := route.Mode
	seen := make(map[Endpoint]struct{}, c.limits.MaxHops)
	for hop := 0; hop < c.limits.MaxHops; hop++ {
		endpoint, err = normalizeEndpoint(endpoint)
		if err != nil {
			return result, &OpError{Op: "follow referral", Endpoint: endpoint, Err: err}
		}
		if _, exists := seen[endpoint]; exists {
			return result, &OpError{Op: "follow referral", Endpoint: endpoint, Err: ErrReferralLoop}
		}
		seen[endpoint] = struct{}{}

		wireQuery := formatQuery(endpoint, target.query, target.kind)
		response, queryErr := c.query(ctx, endpoint, wireQuery, c.lookupPolicy)
		response.Referral = findReferral(endpoint, mode, response.Body)
		if queryErr == nil || len(response.Body) > 0 || response.Truncated {
			result.Responses = append(result.Responses, response)
		}
		if queryErr != nil {
			return result, queryErr
		}
		if response.Referral == nil {
			return result, nil
		}
		if hop+1 == c.limits.MaxHops {
			return result, &OpError{Op: "follow referral", Endpoint: *response.Referral, Err: ErrTooManyReferrals}
		}

		endpoint = *response.Referral
		mode = referralModeFor(endpoint, target.kind)
	}
	return result, nil
}

func classifyQuery(input string, maxBytes int) (lookupTarget, error) {
	trimmed := strings.TrimSpace(input)
	target := lookupTarget{normalized: trimmed, query: trimmed}
	if err := validateQuery(trimmed, maxBytes); err != nil {
		return target, err
	}

	if address, prefix, ok := parseReverseName(trimmed); ok {
		target.kind = kindReverse
		target.address = address
		if prefix.IsValid() {
			target.address = prefix.Addr()
		}
		target.normalized = strings.ToLower(strings.TrimSuffix(trimmed, "."))
		target.query = target.normalized
		return target, nil
	}

	if prefix, err := netip.ParsePrefix(trimmed); err == nil {
		prefix = prefix.Masked()
		target.kind = kindPrefix
		target.address = prefix.Addr().Unmap()
		target.query = prefix.String()
		target.normalized = target.query
		return applyTransitionAddress(target), nil
	}
	if address, err := netip.ParseAddr(trimmed); err == nil {
		address = address.Unmap()
		target.kind = kindAddress
		target.address = address
		target.query = address.String()
		target.normalized = target.query
		return applyTransitionAddress(target), nil
	}

	if asn, ok := parseASN(trimmed); ok {
		target.kind = kindASN
		target.asn = asn
		target.query = "AS" + strconv.FormatUint(uint64(asn), 10)
		target.normalized = target.query
		return target, nil
	}

	if strings.ContainsAny(trimmed, " \t@") {
		return target, fmt.Errorf("%w: smart lookups require a single resource; use Query for server-specific syntax", ErrInvalidQuery)
	}

	domainInput := strings.TrimPrefix(strings.TrimSuffix(trimmed, "."), ".")
	ascii, err := idna.Lookup.ToASCII(domainInput)
	if err == nil {
		ascii = strings.ToLower(ascii)
		if _, ok := generatedTLDData[ascii]; ok {
			target.kind = kindTLD
			target.normalized = ascii
			target.query = ascii
			return target, nil
		}
		if strings.Contains(ascii, ".") {
			target.kind = kindDomain
			target.normalized = ascii
			target.query = ascii
			return target, nil
		}
	}
	if domainInput == "" || strings.Contains(domainInput, ".") {
		return target, fmt.Errorf("%w: malformed domain name", ErrInvalidQuery)
	}

	target.kind = kindHandle
	target.normalized = trimmed
	target.query = trimmed
	return target, nil
}

func parseASN(value string) (uint32, bool) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || !strings.EqualFold(value[:2], "as") {
		return 0, false
	}
	number := strings.TrimSpace(value[2:])
	if number == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(number, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(parsed), true
}

func parseReverseName(value string) (netip.Addr, netip.Prefix, bool) {
	lower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if strings.HasSuffix(lower, ".in-addr.arpa") {
		name := strings.TrimSuffix(lower, ".in-addr.arpa")
		labels := strings.Split(name, ".")
		if len(labels) < 1 || len(labels) > 4 {
			return netip.Addr{}, netip.Prefix{}, false
		}
		bytes := [4]byte{}
		for index, label := range labels {
			part, err := strconv.ParseUint(label, 10, 8)
			if err != nil {
				return netip.Addr{}, netip.Prefix{}, false
			}
			bytes[len(labels)-1-index] = byte(part)
		}
		address := netip.AddrFrom4(bytes)
		prefix := netip.PrefixFrom(address, len(labels)*8).Masked()
		return address, prefix, true
	}
	if strings.HasSuffix(lower, ".ip6.arpa") {
		name := strings.TrimSuffix(lower, ".ip6.arpa")
		labels := strings.Split(name, ".")
		if len(labels) < 1 || len(labels) > 32 {
			return netip.Addr{}, netip.Prefix{}, false
		}
		nibbles := make([]byte, 32)
		for index, label := range labels {
			if len(label) != 1 {
				return netip.Addr{}, netip.Prefix{}, false
			}
			part, err := strconv.ParseUint(label, 16, 4)
			if err != nil {
				return netip.Addr{}, netip.Prefix{}, false
			}
			nibbles[len(labels)-1-index] = byte(part)
		}
		bytes := [16]byte{}
		for index := 0; index < len(nibbles); index += 2 {
			bytes[index/2] = nibbles[index]<<4 | nibbles[index+1]
		}
		address := netip.AddrFrom16(bytes)
		prefix := netip.PrefixFrom(address, len(labels)*4).Masked()
		return address, prefix, true
	}
	return netip.Addr{}, netip.Prefix{}, false
}

func applyTransitionAddress(target lookupTarget) lookupTarget {
	address := target.address
	if !address.Is6() {
		return target
	}
	bytes := address.As16()
	if bytes[0] == 0x20 && bytes[1] == 0x02 {
		address = netip.AddrFrom4([4]byte{bytes[2], bytes[3], bytes[4], bytes[5]})
		target.kind = kindAddress
		target.address = address
		target.query = address.String()
		return target
	}
	if bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0 && bytes[3] == 0 {
		address = netip.AddrFrom4([4]byte{^bytes[12], ^bytes[13], ^bytes[14], ^bytes[15]})
		target.kind = kindAddress
		target.address = address
		target.query = address.String()
	}
	return target
}

func routeTarget(target lookupTarget) (routeEntry, error) {
	switch target.kind {
	case kindTLD:
		return routeEntry{Endpoint: Endpoint{Host: "whois.iana.org", Port: 43}, Mode: referralIANA}, nil
	case kindDomain:
		route, ok := findDomainRoute(target.query)
		if !ok || route.Endpoint.Host == "" {
			return routeEntry{}, &NoServerError{Query: target.normalized, WebURL: route.WebURL}
		}
		return route, nil
	case kindAddress, kindPrefix, kindReverse:
		endpoint, ok := findNetworkRoute(target.address)
		if !ok {
			return routeEntry{}, &NoServerError{Query: target.normalized}
		}
		return routeEntry{Endpoint: endpoint, Mode: referralModeFor(endpoint, target.kind)}, nil
	case kindASN:
		endpoint, ok := findASNRoute(target.asn)
		if !ok {
			return routeEntry{}, &NoServerError{Query: target.normalized}
		}
		return routeEntry{Endpoint: endpoint, Mode: referralModeFor(endpoint, target.kind)}, nil
	case kindHandle:
		lower := strings.ToLower(target.query)
		if isJPNICHandle(target.query) {
			endpoint := Endpoint{Host: "whois.nic.ad.jp", Port: 43}
			return routeEntry{Endpoint: endpoint, Mode: referralModeFor(endpoint, target.kind)}, nil
		}
		for prefix, endpoint := range handlePrefixRoutes {
			if strings.HasPrefix(lower, prefix) {
				return routeEntry{Endpoint: endpoint, Mode: referralModeFor(endpoint, target.kind)}, nil
			}
		}
		for suffix, endpoint := range handleSuffixRoutes {
			if strings.HasSuffix(lower, suffix) {
				return routeEntry{Endpoint: endpoint, Mode: referralModeFor(endpoint, target.kind)}, nil
			}
		}
		if strings.Contains(lower, "-") {
			endpoint := Endpoint{Host: "whois.arin.net", Port: 43}
			return routeEntry{Endpoint: endpoint, Mode: referralARIN}, nil
		}
	}
	return routeEntry{}, &NoServerError{Query: target.normalized}
}

func formatQuery(endpoint Endpoint, query string, kind resourceKind) string {
	host := strings.ToLower(endpoint.Host)
	if host == "whois.verisign-grs.com" || host == "ccwhois.verisign-grs.com" {
		if kind == kindDomain && strings.Count(query, ".") == 1 && !strings.ContainsAny(query, "=~ ") {
			return "domain " + query
		}
	}
	if host == "whois.denic.de" && kind == kindDomain {
		return "-T dn,ace " + query
	}
	if (host == "whois.punktum.dk" || host == "whois.dk-hostmaster.dk") && kind == kindDomain {
		return "--show-handles " + query
	}
	if host == "whois.jprs.jp" {
		return query + "/e"
	}
	if host == "whois.nic.ad.jp" {
		if kind == kindASN && strings.HasPrefix(strings.ToUpper(query), "AS") {
			return "AS " + query[2:] + "/e"
		}
		return query + "/e"
	}
	if host == "whois.arin.net" {
		switch kind {
		case kindASN:
			return "a " + strings.TrimPrefix(strings.ToUpper(query), "AS")
		case kindAddress:
			return "n + " + query
		case kindPrefix:
			return "r + = " + query
		}
	}
	if _, ok := ripeLikeServers[host]; ok {
		return "-V whodis " + query
	}
	return query
}

func isJPNICHandle(value string) bool {
	value = strings.ToUpper(value)
	if len(value) == 10 && strings.HasPrefix(value, "JP") {
		for _, ch := range value[2:] {
			if ch < '0' || ch > '9' {
				return false
			}
		}
		return true
	}
	if len(value) < 7 || !strings.HasSuffix(value, "JP") {
		return false
	}
	if value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' {
		return false
	}
	for _, ch := range value[2 : len(value)-2] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
