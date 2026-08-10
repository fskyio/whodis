package whois

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

type referralMode uint8

const (
	referralNone referralMode = iota
	referralGeneric
	referralIANA
	referralARIN
	referralAPNIC
	referralVerisign
)

func referralModeFor(endpoint Endpoint, kind resourceKind) referralMode {
	switch strings.ToLower(endpoint.Host) {
	case "whois.iana.org":
		return referralIANA
	case "whois.arin.net":
		return referralARIN
	case "whois.apnic.net":
		return referralAPNIC
	case "whois.verisign-grs.com", "ccwhois.verisign-grs.com":
		return referralVerisign
	}
	if kind == kindDomain {
		return referralGeneric
	}
	return referralNone
}

func findReferral(endpoint Endpoint, mode referralMode, body []byte) *Endpoint {
	lines := responseLines(body)
	var value string
	switch mode {
	case referralIANA:
		value = firstAttribute(lines, "refer")
	case referralARIN:
		value = lastAttribute(lines, "referralserver")
	case referralAPNIC:
		value = apnicReferral(lines)
	case referralVerisign:
		value = verisignReferral(lines)
	case referralGeneric:
		value = firstAttribute(lines, "registrar whois server")
		if value == "" {
			value = firstAttribute(lines, "whois server")
		}
	default:
		return nil
	}
	if value == "" {
		return nil
	}
	referral, err := parseReferralEndpoint(value)
	if err != nil {
		return nil
	}
	// Registry and registrar responses commonly repeat their own WHOIS server.
	// Treat that as terminal; multi-server cycles are detected by Lookup.
	if sameEndpoint(endpoint, referral) {
		return nil
	}
	return &referral
}

func responseLines(body []byte) []string {
	value := strings.ReplaceAll(string(body), "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.Split(value, "\n")
}

func firstAttribute(lines []string, names ...string) string {
	for _, line := range lines {
		name, value, ok := splitAttribute(line)
		if !ok {
			continue
		}
		for _, wanted := range names {
			if strings.EqualFold(name, wanted) {
				return value
			}
		}
	}
	return ""
}

func lastAttribute(lines []string, names ...string) string {
	var found string
	for _, line := range lines {
		name, value, ok := splitAttribute(line)
		if !ok {
			continue
		}
		for _, wanted := range names {
			if strings.EqualFold(name, wanted) {
				found = value
				break
			}
		}
	}
	return found
}

func splitAttribute(line string) (string, string, bool) {
	name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
	if !ok {
		return "", "", false
	}
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	return name, value, name != "" && value != ""
}

func apnicReferral(lines []string) string {
	rirServers := map[string]string{
		"AFRINIC": "whois.afrinic.net",
		"ARIN":    "whois.arin.net",
		"LACNIC":  "whois.lacnic.net",
		"RIPE":    "whois.ripe.net",
	}

	var transferredTo string
	maintainedByAPNIC := false
	var nirServer string
	finishObject := func() string {
		if nirServer != "" {
			return nirServer
		}
		if maintainedByAPNIC {
			if server := rirServers[transferredTo]; server != "" {
				return server
			}
		}
		transferredTo = ""
		maintainedByAPNIC = false
		nirServer = ""
		return ""
	}

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			if server := finishObject(); server != "" {
				return server
			}
			continue
		}
		name, value, ok := splitAttribute(line)
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(name, "descr"):
			const prefix = "Transferred to the "
			if len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) {
				fields := strings.Fields(value[len(prefix):])
				if len(fields) > 0 {
					transferredTo = strings.ToUpper(fields[0])
				}
			}
		case strings.EqualFold(name, "mnt-by") && strings.EqualFold(value, "APNIC-STUB"):
			maintainedByAPNIC = true
		case strings.EqualFold(name, "remarks") && strings.Contains(strings.ToLower(value), "whois.nic.ad.jp"):
			nirServer = "whois.nic.ad.jp"
		}
	}
	return finishObject()
}

func verisignReferral(lines []string) string {
	insideFirstDomain := false
	for _, line := range lines {
		name, value, ok := splitAttribute(line)
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(name, "Domain Name"):
			if insideFirstDomain {
				return ""
			}
			insideFirstDomain = true
		case strings.EqualFold(name, "Server Name") && !insideFirstDomain:
			return ""
		case insideFirstDomain && strings.EqualFold(name, "Registrar WHOIS Server"):
			return value
		}
	}
	return ""
}

func parseReferralEndpoint(value string) (Endpoint, error) {
	value = strings.Trim(strings.TrimSpace(value), "\"'")
	fields := strings.Fields(value)
	if len(fields) > 0 {
		value = fields[0]
	}

	port := defaultPort
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "whois://") || strings.HasPrefix(lower, "rwhois://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return Endpoint{}, err
		}
		if strings.EqualFold(parsed.Scheme, "rwhois") {
			port = 4321
		}
		if parsed.Port() != "" {
			parsedPort, err := strconv.ParseUint(parsed.Port(), 10, 16)
			if err != nil || parsedPort == 0 {
				return Endpoint{}, ErrDisallowedEndpoint
			}
			port = uint16(parsedPort)
		}
		return normalizeEndpoint(Endpoint{Host: parsed.Hostname(), Port: port})
	}

	value = strings.TrimSuffix(value, "/")
	if host, portValue, err := net.SplitHostPort(value); err == nil {
		parsedPort, err := strconv.ParseUint(portValue, 10, 16)
		if err != nil || parsedPort == 0 {
			return Endpoint{}, ErrDisallowedEndpoint
		}
		return normalizeEndpoint(Endpoint{Host: host, Port: uint16(parsedPort)})
	}
	if strings.Count(value, ":") == 1 {
		host, portValue, _ := strings.Cut(value, ":")
		if parsedPort, err := strconv.ParseUint(portValue, 10, 16); err == nil && parsedPort > 0 {
			return normalizeEndpoint(Endpoint{Host: host, Port: uint16(parsedPort)})
		}
	}
	return normalizeEndpoint(Endpoint{Host: strings.TrimSuffix(value, "."), Port: port})
}

func sameEndpoint(a, b Endpoint) bool {
	a, errA := normalizeEndpoint(a)
	b, errB := normalizeEndpoint(b)
	return errA == nil && errB == nil && a == b
}
