package rdap_test

import (
	"context"
	"os"
	"testing"
	"time"

	"foundry.fsky.io/fsky/whodis/rdap"
)

func TestLiveLookup(t *testing.T) {
	if os.Getenv("RDAP_LIVE_TESTS") != "1" {
		t.Skip("set RDAP_LIVE_TESTS=1 to query public RDAP services")
	}
	client := rdap.NewClient()
	for _, query := range []string{"example.com", "com", "1.1.1.1", "AS3333", "OPS4-RIPE"} {
		t.Run(query, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			result, err := client.Lookup(ctx, query)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", query, err)
			}
			if len(result.Response.Body) == 0 {
				t.Fatalf("Lookup(%q) returned no response body", query)
			}
		})
	}
}
