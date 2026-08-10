package web

import (
	"testing"
	"time"
)

func TestLoadConfigPreservesEnvironmentContract(t *testing.T) {
	values := map[string]string{
		"PORT":                  "9090",
		"CACHE_TTL":             "2h",
		"RATE_LIMIT_PER_MINUTE": "0",
		"RATE_LIMIT_BURST":      "4",
		"TRUST_PROXY_HEADERS":   "true",
	}
	config := LoadConfig(func(key string) string { return values[key] }, t.Logf)
	if config.Port != "9090" || config.CacheTTL != 2*time.Hour || config.RateLimitPerMinute != 0 || config.RateLimitBurst != 4 || !config.TrustProxyHeaders {
		t.Fatalf("config = %#v", config)
	}
	if config.LookupTimeout != 25*time.Second || config.RDAPAutoTimeout != 10*time.Second {
		t.Fatalf("lookup timeouts = %v, %v", config.LookupTimeout, config.RDAPAutoTimeout)
	}
}
