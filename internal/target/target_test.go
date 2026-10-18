package target

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRejectsMalformedNamesAndNumbers(t *testing.T) {
	for _, input := range []string{
		"a..com",
		"example.com..",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 127) + "com",
		"AS4294967296",
		"as 99999999999999999999",
	} {
		if parsed, err := Parse(input, 1024); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%.40q) = kind %d, %v; want ErrInvalid", input, parsed.Kind, err)
		}
	}
}

func TestParseAcceptsBoundaryValues(t *testing.T) {
	for input, want := range map[string]Kind{
		"AS4294967295":                    ASN,
		strings.Repeat("a", 63) + ".com":  Name,
		"example.com.":                    Name,
		"ZG39-ARIN":                       Name,
		strings.Repeat("handle", 15):      Name,
		"as-set-example":                  Name,
		"bücher.de":                       Name,
		"192.0.2.0/24":                    Prefix,
		"2.0.192.in-addr.arpa":            Reverse,
		"xn--bcher-kva.de":                Name,
		strings.Repeat("a.", 125) + "com": Name,
	} {
		parsed, err := Parse(input, 1024)
		if err != nil || parsed.Kind != want {
			t.Errorf("Parse(%.40q) = kind %d, %v; want kind %d", input, parsed.Kind, err, want)
		}
	}
}
