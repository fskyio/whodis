package web

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const openSearchMediaType = "application/opensearchdescription+xml"

type openSearchDescription struct {
	XMLName       xml.Name          `xml:"OpenSearchDescription"`
	XMLNS         string            `xml:"xmlns,attr"`
	ShortName     string            `xml:"ShortName"`
	Description   string            `xml:"Description"`
	InputEncoding string            `xml:"InputEncoding"`
	Image         openSearchImage   `xml:"Image"`
	URLs          []openSearchURL   `xml:"Url"`
	Queries       []openSearchQuery `xml:"Query,omitempty"`
}

type openSearchImage struct {
	Height int    `xml:"height,attr"`
	Width  int    `xml:"width,attr"`
	Type   string `xml:"type,attr"`
	URL    string `xml:",chardata"`
}

type openSearchURL struct {
	Type     string `xml:"type,attr"`
	Method   string `xml:"method,attr,omitempty"`
	Template string `xml:"template,attr"`
	Rel      string `xml:"rel,attr,omitempty"`
}

type openSearchQuery struct {
	Role        string `xml:"role,attr"`
	SearchTerms string `xml:"searchTerms,attr"`
}

func (a *App) handleOpenSearch(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/opensearch.xml" {
		http.NotFound(w, r)
		return
	}
	if !allowGet(w, r) {
		return
	}

	baseURL := a.requestBaseURL(r)
	description := openSearchDescription{
		XMLNS:         "http://a9.com/-/spec/opensearch/1.1/",
		ShortName:     "who dis?",
		Description:   "Look up domain names, IP addresses, CIDR ranges, ASNs, and entity handles with who dis?",
		InputEncoding: "UTF-8",
		Image:         openSearchImage{Height: 16, Width: 16, Type: "image/x-icon", URL: baseURL + "/favicon.ico"},
		URLs: []openSearchURL{
			{Type: openSearchMediaType, Template: baseURL + "/opensearch.xml", Rel: "self"},
			{Type: "text/html", Method: http.MethodGet, Template: baseURL + "/lookup?q={searchTerms}"},
		},
		Queries: []openSearchQuery{{Role: "example", SearchTerms: "example.com"}},
	}

	w.Header().Set("Content-Type", openSearchMediaType+"; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, xml.Header)
	if err := xml.NewEncoder(w).Encode(description); err != nil {
		a.logf("OpenSearch description encoding error: %v", err)
	}
}

func (a *App) requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if a.config.TrustProxyHeaders {
		if forwardedProto := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); forwardedProto == "http" || forwardedProto == "https" {
			scheme = forwardedProto
		}
	}

	return (&url.URL{Scheme: scheme, Host: r.Host}).String()
}

func firstHeaderValue(value string) string {
	if index := strings.IndexByte(value, ','); index >= 0 {
		value = value[:index]
	}
	return strings.ToLower(strings.TrimSpace(value))
}
