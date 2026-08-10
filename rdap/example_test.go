package rdap_test

import (
	"context"
	"fmt"
	"time"

	"foundry.fsky.io/fsky/whodis/rdap"
)

func ExampleClient_Lookup() {
	client := rdap.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := client.Lookup(ctx, "example.com")
	if err != nil {
		return
	}
	fmt.Printf("%s returned %d raw bytes\n", result.Response.URL, len(result.Response.Body))
}

func ExampleClient_Query() {
	client := rdap.NewClient()
	response, err := client.Query(context.Background(), "https://rdap.example/rdap/help")
	if err != nil {
		return
	}
	fmt.Printf("received HTTP %d with %d raw bytes\n", response.StatusCode, len(response.Body))
}
