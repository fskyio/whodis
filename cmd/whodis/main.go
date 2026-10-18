package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitfield.org/fsky/whodis/internal/config"
	"gitfield.org/fsky/whodis/internal/lookup"
	"gitfield.org/fsky/whodis/internal/mcpserver"
	"gitfield.org/fsky/whodis/internal/web"
	"gitfield.org/fsky/whodis/rdap"
	"gitfield.org/fsky/whodis/whois"
)

func main() {
	cfg, err := config.Load(os.Getenv, log.Printf)
	if err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	service, err := lookup.NewService(lookup.Config{
		CacheTTL:        cfg.CacheTTL,
		LookupTimeout:   cfg.LookupTimeout,
		RDAPAutoTimeout: cfg.RDAPAutoTimeout,
	}, whois.NewClient(), rdap.NewClient())
	if err != nil {
		log.Fatalf("Initialize lookups: %v", err)
	}

	mux := http.NewServeMux()
	var limiters []*lookup.RateLimiter
	if cfg.EnableWebUI {
		limiter := newRateLimiter(cfg.RateLimitPerMinute, cfg.RateLimitBurst)
		app, err := web.New(service, web.Config{Limiter: limiter, TrustProxyHeaders: cfg.TrustProxyHeaders})
		if err != nil {
			log.Fatalf("Initialize web UI: %v", err)
		}
		mux.Handle("/", app.Handler())
		limiters = append(limiters, limiter)
		log.Printf("Web UI enabled; %s", describeRateLimit(cfg.RateLimitPerMinute, cfg.RateLimitBurst))
	} else {
		log.Printf("Web UI disabled")
	}
	if cfg.EnableMCP {
		limiter := newRateLimiter(cfg.MCPRateLimitPerMinute, cfg.MCPRateLimitBurst)
		mcpserver.New(service, mcpserver.Config{
			Limiter:           limiter,
			Tokens:            cfg.MCPTokens,
			RequireToken:      cfg.MCPRequireToken,
			TrustProxyHeaders: cfg.TrustProxyHeaders,
			WebUI:             cfg.EnableWebUI,
		}).Register(mux)
		limiters = append(limiters, limiter)
		access := "open to all"
		if cfg.MCPRequireToken {
			access = "token required"
		}
		log.Printf("MCP enabled at %s (%s, %d tokens); %s without a token", mcpserver.Path, access, len(cfg.MCPTokens), describeRateLimit(cfg.MCPRateLimitPerMinute, cfg.MCPRateLimitBurst))
	} else {
		log.Printf("MCP disabled")
	}
	log.Printf("Trust proxy headers: %v", cfg.TrustProxyHeaders)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go service.RunMaintenance(ctx, limiters...)

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Printf("Shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}()

	log.Printf("Starting server on http://localhost:%s", cfg.Port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server failed: %v", err)
	}
}

// newRateLimiter returns nil, which admits every request, when perMinute is
// not positive.
func newRateLimiter(perMinute float64, burst int) *lookup.RateLimiter {
	if perMinute <= 0 {
		return nil
	}
	return lookup.NewRateLimiter(perMinute, burst)
}

func describeRateLimit(perMinute float64, burst int) string {
	if perMinute <= 0 {
		return "rate limiting disabled"
	}
	return fmt.Sprintf("rate limit %g req/min per IP (burst %d)", perMinute, burst)
}
