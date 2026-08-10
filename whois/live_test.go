package whois_test

import (
	"context"
	"os"
	"testing"
	"time"

	"foundry.fsky.io/fsky/whodis/whois"
)

// TestLiveLookup is deliberately opt-in: public WHOIS services are rate
// limited and ordinary test runs must remain deterministic and offline.
func TestLiveLookup(t *testing.T) {
	if os.Getenv("WHOIS_LIVE_TESTS") != "1" {
		t.Skip("set WHOIS_LIVE_TESTS=1 to query public WHOIS services")
	}

	client := whois.NewClient()
	for _, query := range []string{"example.com", "1.1.1.1", "AS3333"} {
		t.Run(query, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			result, err := client.Lookup(ctx, query)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", query, err)
			}
			if len(result.Responses) == 0 || len(result.Responses[len(result.Responses)-1].Body) == 0 {
				t.Fatalf("Lookup(%q) returned no response body", query)
			}
		})
	}
}
