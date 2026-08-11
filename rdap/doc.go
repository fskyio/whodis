// Package rdap provides bounded, policy-driven Registration Data Access
// Protocol lookups while preserving response bodies as opaque bytes.
//
// [Client.Lookup] normalizes a domain, TLD, IP address or prefix, reverse DNS
// name, AS number, or provider-tagged entity handle; selects an authoritative
// service from an embedded IANA bootstrap snapshot; and performs an HTTP GET.
// [Client.Query] sends a GET to an exact caller-selected HTTP(S) URL.
//
// The package validates successful bodies as JSON but does not reshape or
// discard response fields. Lookup follows recognized top-level RDAP referral
// links. Completed [Response] values can accompany an error from a later hop,
// including HTTP errors and response truncation.
package rdap
