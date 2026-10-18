// Package config loads whodis settings from the environment.
package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MinMCPTokenLength is the shortest accepted MCP access token.
const MinMCPTokenLength = 32

type Config struct {
	Port               string
	CacheTTL           time.Duration
	RateLimitPerMinute float64
	RateLimitBurst     int
	TrustProxyHeaders  bool
	LookupTimeout      time.Duration
	RDAPAutoTimeout    time.Duration

	EnableWebUI           bool
	EnableMCP             bool
	MCPRateLimitPerMinute float64
	MCPRateLimitBurst     int
	MCPTokens             []string
	MCPRequireToken       bool
}

// Load reads the configuration. Malformed tuning values are logged and replaced
// by their defaults; settings that control what is exposed must be valid, and
// their errors are returned.
func Load(getenv func(string) string, logf func(string, ...any)) (Config, error) {
	config := Config{
		Port:               "8080",
		CacheTTL:           24 * time.Hour,
		RateLimitPerMinute: 20,
		RateLimitBurst:     10,
		LookupTimeout:      25 * time.Second,
		RDAPAutoTimeout:    10 * time.Second,
		MCPRateLimitBurst:  20,
	}
	if value := getenv("PORT"); value != "" {
		config.Port = value
	}
	if value := getenv("CACHE_TTL"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			logf("Invalid CACHE_TTL value %q, defaulting to 24h", value)
		} else {
			config.CacheTTL = parsed
		}
	}
	config.RateLimitPerMinute = loadRate(getenv, logf, "RATE_LIMIT_PER_MINUTE", config.RateLimitPerMinute)
	config.RateLimitBurst = loadBurst(getenv, logf, "RATE_LIMIT_BURST", config.RateLimitBurst)
	value := getenv("TRUST_PROXY_HEADERS")
	config.TrustProxyHeaders = value == "1" || strings.EqualFold(value, "true")
	config.MCPRateLimitPerMinute = loadRate(getenv, logf, "MCP_RATE_LIMIT_PER_MINUTE", config.MCPRateLimitPerMinute)
	config.MCPRateLimitBurst = loadBurst(getenv, logf, "MCP_RATE_LIMIT_BURST", config.MCPRateLimitBurst)

	var errs []error
	var err error
	if config.EnableWebUI, err = loadBool(getenv, "ENABLE_WEB_UI", true); err != nil {
		errs = append(errs, err)
	}
	if config.EnableMCP, err = loadBool(getenv, "ENABLE_MCP", true); err != nil {
		errs = append(errs, err)
	}
	if config.MCPRequireToken, err = loadBool(getenv, "MCP_REQUIRE_TOKEN", false); err != nil {
		errs = append(errs, err)
	}
	if config.MCPTokens, err = parseTokens(getenv("MCP_TOKENS")); err != nil {
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		if !config.EnableWebUI && !config.EnableMCP {
			errs = append(errs, errors.New("ENABLE_WEB_UI and ENABLE_MCP are both false; nothing would be served"))
		}
		if config.MCPRequireToken && len(config.MCPTokens) == 0 {
			errs = append(errs, errors.New("MCP_REQUIRE_TOKEN is true but MCP_TOKENS is empty"))
		}
	}
	return config, errors.Join(errs...)
}

func loadRate(getenv func(string) string, logf func(string, ...any), name string, fallback float64) float64 {
	value := getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0 {
		logf("Invalid %s %q, defaulting to %g", name, value, fallback)
		return fallback
	}
	return parsed
}

func loadBurst(getenv func(string) string, logf func(string, ...any), name string, fallback int) int {
	value := getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		logf("Invalid %s %q, defaulting to %d", name, value, fallback)
		return fallback
	}
	return parsed
}

func loadBool(getenv func(string) string, name string, fallback bool) (bool, error) {
	value := getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback, fmt.Errorf("%s must be true or false, got %q", name, value)
	}
	return parsed, nil
}

// parseTokens splits a comma-separated token list. Tokens appear in URL paths,
// so they are limited to unreserved URL characters.
func parseTokens(value string) ([]string, error) {
	var tokens []string
	for index, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if len(token) < MinMCPTokenLength {
			return nil, fmt.Errorf("MCP_TOKENS entry %d is shorter than %d characters", index+1, MinMCPTokenLength)
		}
		if strings.IndexFunc(token, func(r rune) bool { return !isUnreserved(r) }) >= 0 {
			return nil, fmt.Errorf("MCP_TOKENS entry %d may only contain letters, digits, '-', '.', '_' and '~'", index+1)
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func isUnreserved(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' || r == '~'
}
