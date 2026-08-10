package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"foundry.fsky.io/fsky/whodis/internal/web"
	"foundry.fsky.io/fsky/whodis/rdap"
	"foundry.fsky.io/fsky/whodis/whois"
)

func main() {
	config := web.LoadConfig(os.Getenv, log.Printf)
	app, err := web.New(config, whois.NewClient(), rdap.NewClient())
	if err != nil {
		log.Fatalf("Initialize application: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go app.RunMaintenance(ctx)

	server := &http.Server{
		Addr:              ":" + config.Port,
		Handler:           app.Handler(),
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

	if config.RateLimitPerMinute > 0 {
		log.Printf("Rate limiting enabled: %.0f req/min per IP, burst %d (trust proxy headers: %v)", config.RateLimitPerMinute, config.RateLimitBurst, config.TrustProxyHeaders)
	} else {
		log.Printf("Rate limiting disabled")
	}
	log.Printf("Starting server on http://localhost:%s", config.Port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server failed: %v", err)
	}
}
