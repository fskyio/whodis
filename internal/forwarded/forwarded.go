// Package forwarded derives the client address and public origin of a request,
// honoring reverse-proxy headers only when they are trusted.
package forwarded

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ClientIP returns the client address. With trustProxyHeaders it prefers the
// first X-Forwarded-For entry, then X-Real-IP.
func ClientIP(r *http.Request, trustProxyHeaders bool) string {
	if trustProxyHeaders {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			if index := strings.Index(forwarded, ","); index >= 0 {
				return strings.TrimSpace(forwarded[:index])
			}
			return strings.TrimSpace(forwarded)
		}
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return strings.TrimSpace(realIP)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// BaseURL returns the scheme and host the client used to reach the server.
// With trustProxyHeaders it honors X-Forwarded-Proto.
func BaseURL(r *http.Request, trustProxyHeaders bool) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if trustProxyHeaders {
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
