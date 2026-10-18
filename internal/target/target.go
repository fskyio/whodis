// Package target normalizes registration-data lookup targets shared by the
// WHOIS and RDAP clients. Protocol-specific routing remains in those clients.
package target

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var ErrInvalid = errors.New("invalid lookup target")

type Kind uint8

const (
	Unknown Kind = iota
	Name
	Address
	Prefix
	Reverse
	ASN
)

type Target struct {
	Normalized string
	Query      string
	NameASCII  string
	Kind       Kind
	Address    netip.Addr
	Prefix     netip.Prefix
	ASN        uint32
}

func Parse(input string, maxBytes int) (Target, error) {
	trimmed := strings.TrimSpace(input)
	target := Target{Normalized: trimmed, Query: trimmed}
	if err := validate(trimmed, maxBytes); err != nil {
		return target, err
	}

	if address, prefix, ok := parseReverseName(trimmed); ok {
		target.Kind = Reverse
		target.Address = address
		target.Prefix = prefix
		if prefix.IsValid() {
			target.Address = prefix.Addr()
		}
		target.Normalized = strings.ToLower(strings.TrimSuffix(trimmed, "."))
		target.Query = target.Normalized
		return target, nil
	}

	if prefix, err := netip.ParsePrefix(trimmed); err == nil {
		prefix = prefix.Masked()
		target.Kind = Prefix
		target.Prefix = prefix
		target.Address = prefix.Addr().Unmap()
		target.Query = prefix.String()
		target.Normalized = target.Query
		return applyTransitionAddress(target), nil
	}
	if address, err := netip.ParseAddr(trimmed); err == nil {
		address = address.Unmap()
		target.Kind = Address
		target.Address = address
		target.Query = address.String()
		target.Normalized = target.Query
		return applyTransitionAddress(target), nil
	}

	asn, ok, err := parseASN(trimmed)
	if err != nil {
		return target, err
	}
	if ok {
		target.Kind = ASN
		target.ASN = asn
		target.Query = "AS" + strconv.FormatUint(uint64(asn), 10)
		target.Normalized = target.Query
		return target, nil
	}

	if strings.ContainsAny(trimmed, " \t@") {
		return target, fmt.Errorf("%w: smart lookups require a single resource", ErrInvalid)
	}

	domainInput := strings.TrimPrefix(strings.TrimSuffix(trimmed, "."), ".")
	if domainInput == "" {
		return target, fmt.Errorf("%w: malformed domain name", ErrInvalid)
	}
	ascii, err := idna.Lookup.ToASCII(domainInput)
	if err == nil {
		name := strings.ToLower(ascii)
		if strings.Contains(name, ".") {
			if err := validateDomainLength(name); err != nil {
				return target, err
			}
		}
		target.Kind = Name
		target.NameASCII = name
		return target, nil
	}
	if strings.Contains(domainInput, ".") {
		return target, fmt.Errorf("%w: malformed domain name", ErrInvalid)
	}

	// A non-domain single token can still be a registry-specific handle.
	target.Kind = Name
	return target, nil
}

func validate(query string, maxBytes int) error {
	if query == "" {
		return fmt.Errorf("%w: query is empty", ErrInvalid)
	}
	if maxBytes > 0 && len(query) > maxBytes {
		return fmt.Errorf("%w: query is longer than %d bytes", ErrInvalid, maxBytes)
	}
	if strings.ContainsAny(query, "\r\n\x00") {
		return fmt.Errorf("%w: query contains a line break or NUL", ErrInvalid)
	}
	return nil
}

// parseASN recognizes "AS" followed by a decimal number. Digits that overflow
// 32 bits are reported as an error rather than treated as a handle.
func parseASN(value string) (uint32, bool, error) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || !strings.EqualFold(value[:2], "as") {
		return 0, false, nil
	}
	number := strings.TrimSpace(value[2:])
	if number == "" {
		return 0, false, nil
	}
	parsed, err := strconv.ParseUint(number, 10, 32)
	if errors.Is(err, strconv.ErrRange) {
		return 0, false, fmt.Errorf("%w: AS number %s exceeds 4294967295", ErrInvalid, number)
	}
	if err != nil {
		return 0, false, nil
	}
	return uint32(parsed), true, nil
}

// validateDomainLength enforces the DNS limits that IDNA lookup mapping does
// not: no empty labels, at most 63 bytes per label and 253 bytes in total.
func validateDomainLength(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("%w: domain name is longer than 253 characters", ErrInvalid)
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" {
			return fmt.Errorf("%w: domain name has an empty label", ErrInvalid)
		}
		if len(label) > 63 {
			return fmt.Errorf("%w: domain label is longer than 63 characters", ErrInvalid)
		}
	}
	return nil
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

func applyTransitionAddress(target Target) Target {
	address := target.Address
	if !address.Is6() {
		return target
	}
	bytes := address.As16()
	if bytes[0] == 0x20 && bytes[1] == 0x02 {
		address = netip.AddrFrom4([4]byte{bytes[2], bytes[3], bytes[4], bytes[5]})
		target.Kind = Address
		target.Address = address
		target.Prefix = netip.Prefix{}
		target.Query = address.String()
		return target
	}
	if bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0 && bytes[3] == 0 {
		address = netip.AddrFrom4([4]byte{^bytes[12], ^bytes[13], ^bytes[14], ^bytes[15]})
		target.Kind = Address
		target.Address = address
		target.Prefix = netip.Prefix{}
		target.Query = address.String()
	}
	return target
}
