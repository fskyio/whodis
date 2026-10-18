package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	tokenA = "0123456789abcdef0123456789abcdef"
	tokenB = "fedcba9876543210fedcba9876543210-_.~"
)

func load(t *testing.T, values map[string]string) (Config, error) {
	t.Helper()
	return Load(func(key string) string { return values[key] }, t.Logf)
}

func TestLoadPreservesEnvironmentContract(t *testing.T) {
	config, err := load(t, map[string]string{
		"PORT":                      "9090",
		"CACHE_TTL":                 "2h",
		"RATE_LIMIT_PER_MINUTE":     "0",
		"RATE_LIMIT_BURST":          "4",
		"TRUST_PROXY_HEADERS":       "true",
		"MCP_RATE_LIMIT_PER_MINUTE": "90",
		"MCP_RATE_LIMIT_BURST":      "30",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.Port != "9090" || config.CacheTTL != 2*time.Hour || config.RateLimitPerMinute != 0 || config.RateLimitBurst != 4 || !config.TrustProxyHeaders {
		t.Fatalf("config = %#v", config)
	}
	if config.MCPRateLimitPerMinute != 90 || config.MCPRateLimitBurst != 30 {
		t.Fatalf("MCP rate limit = %v, burst %d", config.MCPRateLimitPerMinute, config.MCPRateLimitBurst)
	}
	if config.LookupTimeout != 25*time.Second || config.RDAPAutoTimeout != 10*time.Second {
		t.Fatalf("lookup timeouts = %v, %v", config.LookupTimeout, config.RDAPAutoTimeout)
	}
}

func TestLoadDefaultsServeBothSurfacesWithoutMCPLimits(t *testing.T) {
	config, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !config.EnableWebUI || !config.EnableMCP || config.MCPRequireToken || len(config.MCPTokens) != 0 {
		t.Fatalf("config = %#v", config)
	}
	if config.RateLimitPerMinute != 20 || config.MCPRateLimitPerMinute != 0 {
		t.Fatalf("rate limits = web %v, MCP %v", config.RateLimitPerMinute, config.MCPRateLimitPerMinute)
	}
}

func TestLoadParsesTokenList(t *testing.T) {
	config, err := load(t, map[string]string{
		"ENABLE_WEB_UI":     "false",
		"MCP_TOKENS":        " " + tokenA + " ,," + tokenB + ",",
		"MCP_REQUIRE_TOKEN": "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.EnableWebUI || !config.EnableMCP || !config.MCPRequireToken || !slices.Equal(config.MCPTokens, []string{tokenA, tokenB}) {
		t.Fatalf("config = %#v", config)
	}
}

func TestLoadRejectsUnsafeExposureSettings(t *testing.T) {
	for _, test := range []struct {
		name   string
		values map[string]string
		want   string
	}{
		{"nothing served", map[string]string{"ENABLE_WEB_UI": "false", "ENABLE_MCP": "0"}, "both false"},
		{"misspelled toggle", map[string]string{"ENABLE_WEB_UI": "flase"}, "ENABLE_WEB_UI must be true or false"},
		{"misspelled requirement", map[string]string{"MCP_REQUIRE_TOKEN": "yes", "MCP_TOKENS": tokenA}, "MCP_REQUIRE_TOKEN must be true or false"},
		{"required without tokens", map[string]string{"MCP_REQUIRE_TOKEN": "true"}, "MCP_TOKENS is empty"},
		{"short token", map[string]string{"MCP_TOKENS": tokenA + ",short"}, "entry 2 is shorter than 32"},
		{"token not path safe", map[string]string{"MCP_TOKENS": tokenA + "/" + tokenA}, "entry 1 may only contain"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := load(t, test.values)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
