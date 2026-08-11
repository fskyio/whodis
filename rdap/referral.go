package rdap

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/url"
	"strings"
)

type rdapLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
	Type string `json:"type"`
}

func findReferral(currentURL string, body []byte) (string, error) {
	var document struct {
		ObjectClassName string            `json:"objectClassName"`
		Links           []json.RawMessage `json:"links"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return "", nil
	}
	if !strings.EqualFold(document.ObjectClassName, "domain") {
		return "", nil
	}
	for _, encodedLink := range document.Links {
		var link rdapLink
		if err := json.Unmarshal(encodedLink, &link); err != nil {
			continue
		}
		if !hasLinkRelation(link.Rel, "related") || !isRDAPMediaType(link.Type) || strings.TrimSpace(link.Href) == "" {
			continue
		}
		return resolveReferralURL(currentURL, link.Href)
	}
	return "", nil
}

func hasLinkRelation(value, wanted string) bool {
	for _, relation := range strings.Fields(value) {
		if strings.EqualFold(relation, wanted) {
			return true
		}
	}
	return false
}

func isRDAPMediaType(value string) bool {
	if strings.TrimSpace(value) == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "application/rdap+json") || strings.EqualFold(mediaType, "application/json")
}

func resolveReferralURL(currentURL, href string) (string, error) {
	base, err := validateURL(currentURL)
	if err != nil {
		return "", err
	}
	reference, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDisallowedEndpoint, err)
	}
	referral, err := validateURL(base.ResolveReference(reference).String())
	if err != nil {
		return "", err
	}
	if strings.EqualFold(base.Scheme, "https") && strings.EqualFold(referral.Scheme, "http") {
		return "", ErrInsecureReferral
	}
	return referral.String(), nil
}

func referralURLKey(rawURL string) (string, error) {
	parsed, err := validateURL(rawURL)
	if err != nil {
		return "", err
	}
	port := parsed.Port()
	if port == "" {
		if strings.EqualFold(parsed.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.ToLower(parsed.Scheme) + "\x00" + strings.ToLower(strings.TrimSuffix(parsed.Hostname(), ".")) + "\x00" + port + "\x00" + parsed.EscapedPath() + "\x00" + parsed.RawQuery, nil
}
