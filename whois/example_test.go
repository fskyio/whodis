package whois_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"foundry.fsky.io/fsky/whodis/whois"
)

func ExampleClient_Lookup() {
	client := whois.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	result, err := client.Lookup(ctx, "example.com")
	for _, response := range result.Responses {
		fmt.Printf("%s returned %d bytes\n", response.Endpoint, len(response.Body))
	}
	if err != nil {
		// Result can contain completed exchanges when a later referral fails.
		fmt.Printf("lookup incomplete: %v\n", err)
	}
}

func ExampleClient_Query() {
	client := whois.NewClient(
		whois.WithLimits(whois.Limits{MaxResponseBytes: 512 * 1024}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := client.Query(ctx, whois.Endpoint{
		Host: "whois.example.net",
		Port: 4343,
	}, "custom server syntax")
	if err != nil {
		return
	}
	fmt.Printf("received %d raw bytes\n", len(response.Body))
}

func ExampleNoServerError() {
	result, err := whois.NewClient().Lookup(context.Background(), "example.invalid")
	_ = result

	var noServer *whois.NoServerError
	if errors.As(err, &noServer) && noServer.WebURL != "" {
		fmt.Printf("use the registry website: %s\n", noServer.WebURL)
	}
}
