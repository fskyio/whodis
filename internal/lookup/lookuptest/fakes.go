// Package lookuptest provides fake protocol clients for lookup.Service tests.
package lookuptest

import (
	"context"
	"sync/atomic"

	"gitfield.org/fsky/whodis/rdap"
	"gitfield.org/fsky/whodis/whois"
)

// RDAPClient returns Result and Err, or delegates to LookupFunc when set.
type RDAPClient struct {
	Result     rdap.Result
	Err        error
	LookupFunc func(context.Context, string) (rdap.Result, error)
	calls      atomic.Int32
}

func (c *RDAPClient) Lookup(ctx context.Context, query string) (rdap.Result, error) {
	c.calls.Add(1)
	if c.LookupFunc != nil {
		return c.LookupFunc(ctx, query)
	}
	return c.Result, c.Err
}

// Calls reports how many lookups were performed.
func (c *RDAPClient) Calls() int { return int(c.calls.Load()) }

// WHOISClient returns Result and Err, or delegates to LookupFunc when set.
type WHOISClient struct {
	Result     whois.Result
	Err        error
	LookupFunc func(context.Context, string) (whois.Result, error)
	calls      atomic.Int32
}

func (c *WHOISClient) Lookup(ctx context.Context, query string) (whois.Result, error) {
	c.calls.Add(1)
	if c.LookupFunc != nil {
		return c.LookupFunc(ctx, query)
	}
	return c.Result, c.Err
}

// Calls reports how many lookups were performed.
func (c *WHOISClient) Calls() int { return int(c.calls.Load()) }
