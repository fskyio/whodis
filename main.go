package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"foundry.fsky.io/fsky/whodis/whois"
)

//go:embed templates/* static/*
var content embed.FS

var tmpl *template.Template

type WhoisResponse struct {
	Server string
	Body   string
}

type CacheEntry struct {
	Responses []WhoisResponse
	Error     string
	IsError   bool
	ExpiresAt time.Time
	FetchedAt time.Time
}

type CacheStore struct {
	mu    sync.RWMutex
	items map[string]CacheEntry
}

func (c *CacheStore) Get(key string) (CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, found := c.items[key]
	if !found {
		return CacheEntry{}, false
	}
	if time.Now().After(entry.ExpiresAt) {
		return CacheEntry{}, false
	}
	return entry, true
}

func (c *CacheStore) Set(key string, entry CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = entry
}

func (c *CacheStore) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, v := range c.items {
		if now.After(v.ExpiresAt) {
			delete(c.items, k)
		}
	}
}

var cache *CacheStore
var cacheTTL time.Duration

// RateLimiter is a per-key token bucket limiter. Only cache misses are
// metered, so cache hits remain free regardless of limit settings.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rpm     float64
	burst   int
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

func NewRateLimiter(rpm float64, burst int) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*tokenBucket),
		rpm:     rpm,
		burst:   burst,
	}
}

func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	b, ok := r.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: float64(r.burst), lastRefill: now}
		r.buckets[key] = b
	}
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * (r.rpm / 60.0)
	if b.tokens > float64(r.burst) {
		b.tokens = float64(r.burst)
	}
	b.lastRefill = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (r *RateLimiter) Cleanup(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for k, b := range r.buckets {
		if b.lastRefill.Before(cutoff) {
			delete(r.buckets, k)
		}
	}
}

var limiter *RateLimiter
var trustProxyHeaders bool

type lookupClient interface {
	Lookup(context.Context, string) (whois.Result, error)
}

var whoisClient lookupClient = whois.NewClient()

// clientIP extracts the client IP, optionally honoring X-Forwarded-For /
// X-Real-IP when TRUST_PROXY_HEADERS is enabled. These headers are trivially
// spoofable by direct clients, so they must only be trusted when whodis sits
// behind a reverse proxy that sets them.
func clientIP(r *http.Request) string {
	if trustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.Index(xff, ","); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type PageData struct {
	Query     string
	Responses []WhoisResponse
	Error     string
	FetchedAt string
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	query := r.URL.Query().Get("q")
	if query != "" {
		http.Redirect(w, r, "/whois?q="+url.QueryEscape(query), http.StatusSeeOther)
		return
	}

	data := PageData{}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := tmpl.ExecuteTemplate(w, "index.html", data)
	if err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func handleWhois(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	query = strings.TrimSpace(query)
	queryLower := strings.ToLower(query)

	if query == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := PageData{
		Query: query,
	}

	isCacheHit := false
	effectiveTTL := time.Duration(0)

	if len(query) > 256 {
		data.Error = "Query is too long. Please limit to 256 characters."
	} else {
		// Check Cache
		if entry, found := cache.Get(queryLower); found {
			isCacheHit = true
			data.Responses = entry.Responses
			if entry.IsError {
				data.Error = entry.Error
				effectiveTTL = 5 * time.Minute
			} else {
				effectiveTTL = cacheTTL
			}
			data.FetchedAt = entry.FetchedAt.Format(time.RFC1123)
		} else {
			// Cache Miss - apply rate limit before spending an upstream query
			if limiter != nil && !limiter.Allow(clientIP(r)) {
				data.Error = "Rate limit exceeded. Please wait a moment and try again."
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Retry-After", "30")
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.WriteHeader(http.StatusTooManyRequests)
				if tplErr := tmpl.ExecuteTemplate(w, "index.html", data); tplErr != nil {
					log.Printf("Template execution error: %v", tplErr)
				}
				return
			}

			lookupCtx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			result, lookupErr := whoisClient.Lookup(lookupCtx, query)
			cancel()
			if errors.Is(lookupErr, context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
				return
			}

			responses := make([]WhoisResponse, 0, len(result.Responses))
			for _, response := range result.Responses {
				body := strings.TrimSpace(strings.ToValidUTF8(string(response.Body), "\uFFFD"))
				if body == "" {
					continue
				}
				responses = append(responses, WhoisResponse{
					Server: displayEndpoint(response.Endpoint),
					Body:   body,
				})
			}

			entryToCache := CacheEntry{}
			cacheDuration := cacheTTL
			data.Responses = responses
			entryToCache.Responses = responses
			if lookupErr != nil {
				data.Error = "WHOIS lookup failed: " + lookupErr.Error()
				entryToCache.Error = data.Error
				entryToCache.IsError = true
				cacheDuration = 5 * time.Minute
			} else if len(responses) == 0 {
				data.Error = "No output returned from the WHOIS server."
				entryToCache.Error = data.Error
				entryToCache.IsError = true
				cacheDuration = 5 * time.Minute
			}

			entryToCache.ExpiresAt = time.Now().Add(cacheDuration)
			entryToCache.FetchedAt = time.Now()
			data.FetchedAt = entryToCache.FetchedAt.Format(time.RFC1123)
			cache.Set(queryLower, entryToCache)
			effectiveTTL = cacheDuration
		}
	}

	// Set caching headers

	if query != "" && effectiveTTL > 0 {
		if isCacheHit {
			w.Header().Set("Whodis-Cache", "HIT")
		} else {
			w.Header().Set("Whodis-Cache", "MISS")
		}
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(effectiveTTL.Seconds())))
	} else {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := tmpl.ExecuteTemplate(w, "index.html", data)
	if err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func displayEndpoint(endpoint whois.Endpoint) string {
	if endpoint.Port == 0 || endpoint.Port == 43 {
		return endpoint.Host
	}
	return endpoint.String()
}

func main() {
	var err error
	tmpl, err = template.ParseFS(content, "templates/*.html")
	if err != nil {
		log.Fatalf("Error parsing templates: %v", err)
	}

	cache = &CacheStore{
		items: make(map[string]CacheEntry),
	}

	cacheTTL = 24 * time.Hour
	if ttlStr := os.Getenv("CACHE_TTL"); ttlStr != "" {
		parsedTTL, err := time.ParseDuration(ttlStr)
		if err != nil {
			log.Printf("Invalid CACHE_TTL value %q, defaulting to 24h. Error: %v", ttlStr, err)
		} else {
			cacheTTL = parsedTTL
		}
	}

	// Start background cleanup routine
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			cache.Cleanup()
		}
	}()

	// Rate limiter configuration
	rpm := 20.0
	if v := os.Getenv("RATE_LIMIT_PER_MINUTE"); v != "" {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil || parsed < 0 {
			log.Printf("Invalid RATE_LIMIT_PER_MINUTE %q, defaulting to 20", v)
		} else {
			rpm = parsed
		}
	}
	burst := 10
	if v := os.Getenv("RATE_LIMIT_BURST"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 1 {
			log.Printf("Invalid RATE_LIMIT_BURST %q, defaulting to 10", v)
		} else {
			burst = parsed
		}
	}
	if v := os.Getenv("TRUST_PROXY_HEADERS"); v == "1" || strings.EqualFold(v, "true") {
		trustProxyHeaders = true
	}
	if rpm > 0 {
		limiter = NewRateLimiter(rpm, burst)
		log.Printf("Rate limiting enabled: %.0f req/min per IP, burst %d (trust proxy headers: %v)", rpm, burst, trustProxyHeaders)
		go func() {
			for {
				time.Sleep(10 * time.Minute)
				limiter.Cleanup(1 * time.Hour)
			}
		}()
	} else {
		log.Printf("Rate limiting disabled")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	// Serve static files from embedded FS
	mux.Handle("/static/", http.FileServer(http.FS(content)))

	// Serve favicon.ico from root for legacy browsers
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		file, err := content.ReadFile("static/favicon.ico")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		w.Write(file)
	})

	mux.HandleFunc("/whois", handleWhois)
	mux.HandleFunc("/", handleIndex)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Printf("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}()

	log.Printf("Starting server on http://localhost:%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
