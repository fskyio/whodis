// Package whois provides direct RFC 3912 queries and policy-driven automatic
// discovery of authoritative WHOIS servers.
//
// [Client.Query] sends one caller-supplied query to one caller-supplied
// endpoint. It does not alter the query or follow referrals, and its default
// policy permits private addresses and non-standard ports. Use it when the
// endpoint and server-specific query language are already known.
//
// [Client.Lookup] normalizes and classifies domains, IP addresses and
// prefixes, AS numbers, reverse zones, transition addresses, and known NIC or
// RPSL handles. It chooses an initial endpoint, applies registry-specific query
// syntax, and follows recognized referrals. Its default policy permits only
// publicly routable resolved addresses on ports 43 and 4321. The accepted IP
// literal is passed to the dialer so a hostname is not resolved a second time.
//
// Response bodies are opaque bytes. The package does not parse records,
// convert character sets, remove disclaimers, or normalize newlines. Referral
// fields are inspected only to drive traversal and populate [Response]
// metadata.
//
// A lookup can return both a non-empty [Result] and an error when a later hop
// fails. Callers should inspect completed responses before handling the error.
// Package errors support [errors.Is] and [errors.As], including
// [NoServerError] and [OpError].
//
// Clients are safe for concurrent use after construction. Per-call contexts,
// built-in operation and idle timeouts, response limits, and injectable
// resolvers, dialers, and endpoint policies allow callers to control network
// behavior without changing response semantics.
package whois
