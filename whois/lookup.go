package whois

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"foundry.fsky.io/fsky/whodis/internal/target"
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
	parsed, err := target.Parse(input, maxBytes)
	result := lookupTarget{
		normalized: parsed.Normalized,
		query:      parsed.Query,
		address:    parsed.Address,
		asn:        parsed.ASN,
	}
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidQuery, err)
	}
	switch parsed.Kind {
	case target.Address:
		result.kind = kindAddress
	case target.Prefix:
		result.kind = kindPrefix
	case target.Reverse:
		result.kind = kindReverse
	case target.ASN:
		result.kind = kindASN
	case target.Name:
		if _, ok := generatedTLDData[parsed.NameASCII]; ok {
			result.kind = kindTLD
			result.normalized = parsed.NameASCII
			result.query = parsed.NameASCII
		} else if strings.Contains(parsed.NameASCII, ".") {
			result.kind = kindDomain
			result.normalized = parsed.NameASCII
			result.query = parsed.NameASCII
		} else {
			result.kind = kindHandle
		}
	default:
		return result, fmt.Errorf("%w: unrecognized resource", ErrInvalidQuery)
	}
	return result, nil
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
