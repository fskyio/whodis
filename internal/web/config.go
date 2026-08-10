package web

import (
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port               string
	CacheTTL           time.Duration
	RateLimitPerMinute float64
	RateLimitBurst     int
	TrustProxyHeaders  bool
	LookupTimeout      time.Duration
	RDAPAutoTimeout    time.Duration
}

func LoadConfig(getenv func(string) string, logf func(string, ...any)) Config {
	config := Config{
		Port:               "8080",
		CacheTTL:           24 * time.Hour,
		RateLimitPerMinute: 20,
		RateLimitBurst:     10,
		LookupTimeout:      25 * time.Second,
		RDAPAutoTimeout:    10 * time.Second,
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
	if value := getenv("RATE_LIMIT_PER_MINUTE"); value != "" {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || parsed < 0 {
			logf("Invalid RATE_LIMIT_PER_MINUTE %q, defaulting to 20", value)
		} else {
			config.RateLimitPerMinute = parsed
		}
	}
	if value := getenv("RATE_LIMIT_BURST"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			logf("Invalid RATE_LIMIT_BURST %q, defaulting to 10", value)
		} else {
			config.RateLimitBurst = parsed
		}
	}
	value := getenv("TRUST_PROXY_HEADERS")
	config.TrustProxyHeaders = value == "1" || strings.EqualFold(value, "true")
	return config
}
