// Package rdap provides bounded, policy-driven Registration Data Access
// Protocol lookups while preserving response bodies as opaque bytes.
//
// [Client.Lookup] normalizes a domain, TLD, IP address or prefix, reverse DNS
// name, AS number, or provider-tagged entity handle; selects an authoritative
// service from an embedded IANA bootstrap snapshot; and performs an HTTP GET.
// [Client.Query] sends a GET to an exact caller-selected HTTP(S) URL.
//
// The package validates successful bodies as JSON but does not interpret,
// reshape, or discard response fields. A completed [Response] can accompany
// an error, including HTTP errors and response truncation.
package rdap
