// Package lookup performs the cached RDAP and WHOIS lookups shared by the web
// UI and the MCP server.
package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitfield.org/fsky/whodis/internal/target"
	"gitfield.org/fsky/whodis/rdap"
	"gitfield.org/fsky/whodis/whois"
)

const errorCacheTTL = 5 * time.Minute

// Protocol selects how a lookup is performed. Items report the protocol that
// produced them, which is always RDAP or WHOIS.
type Protocol string

const (
	Auto  Protocol = "auto"
	RDAP  Protocol = "rdap"
	WHOIS Protocol = "whois"
)

// WHOISClient is implemented by *whois.Client.
type WHOISClient interface {
	Lookup(context.Context, string) (whois.Result, error)
}

// RDAPClient is implemented by *rdap.Client.
type RDAPClient interface {
	Lookup(context.Context, string) (rdap.Result, error)
}

// Item is one queried server, in traversal order.
type Item struct {
	Protocol   Protocol
	Source     string
	StatusCode int
	Duration   time.Duration
	Error      string
	Body       []byte
	// JSON reports that Body is a valid JSON document.
	JSON    bool
	Warning string
}

// Result is a completed lookup. Error and Notice summarize the whole lookup;
// per-server failures are reported on Items.
type Result struct {
	Query     string
	Requested Protocol
	Items     []Item
	Error     string
	Notice    string
	Duration  time.Duration
	TTL       time.Duration
	Cacheable bool
}

// ParseProtocol parses a case-insensitive protocol name. An empty value
// selects Auto.
func ParseProtocol(value string) (Protocol, error) {
	switch Protocol(strings.ToLower(strings.TrimSpace(value))) {
	case "", Auto:
		return Auto, nil
	case RDAP:
		return RDAP, nil
	case WHOIS:
		return WHOIS, nil
	default:
		return Auto, fmt.Errorf("unknown protocol %q", value)
	}
}

func normalizedCacheKey(mode Protocol, query string) string {
	normalized := strings.ToLower(strings.TrimSpace(query))
	if parsed, err := target.Parse(query, MaxQueryBytes); err == nil {
		if parsed.NameASCII != "" && strings.Contains(parsed.NameASCII, ".") {
			normalized = parsed.NameASCII
		} else {
			normalized = strings.ToLower(parsed.Normalized)
		}
	}
	return string(mode) + "\x00" + normalized
}

func (s *Service) perform(ctx context.Context, query string, mode Protocol) (Result, error) {
	switch mode {
	case RDAP:
		result, err := s.lookupRDAP(ctx, query)
		result.Requested = mode
		if isRequestCancellation(ctx, err) {
			return Result{}, ctx.Err()
		}
		return result, nil
	case WHOIS:
		result, err := s.lookupWHOIS(ctx, query)
		result.Requested = mode
		if isRequestCancellation(ctx, err) {
			return Result{}, ctx.Err()
		}
		return result, nil
	default:
		rdapCtx, cancel := context.WithTimeout(ctx, s.config.RDAPAutoTimeout)
		rdapResult, rdapErr := s.lookupRDAP(rdapCtx, query)
		cancel()
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if rdapErr == nil || !shouldFallbackRDAP(rdapErr) || hasSuccessfulRDAPResponse(rdapResult) {
			rdapResult.Requested = Auto
			return rdapResult, nil
		}

		whoisResult, whoisErr := s.lookupWHOIS(ctx, query)
		if isRequestCancellation(ctx, whoisErr) {
			return Result{}, ctx.Err()
		}
		whoisResult.Requested = Auto
		whoisResult.Notice = "RDAP was unavailable (" + rdapErr.Error() + "); showing WHOIS fallback."
		whoisResult.Items = append(summarizeFailedItems(rdapResult.Items), whoisResult.Items...)
		whoisResult.TTL = errorCacheTTL
		whoisResult.Cacheable = true
		if whoisErr != nil && whoisResult.Error == "" {
			whoisResult.Error = "WHOIS fallback failed: " + whoisErr.Error()
		}
		return whoisResult, nil
	}
}

func (s *Service) lookupRDAP(ctx context.Context, query string) (Result, error) {
	result, err := s.rdap.Lookup(ctx, query)
	output := Result{Query: result.Query, TTL: errorCacheTTL, Cacheable: true}
	responses := result.Responses
	if len(responses) == 0 && (result.Response.Error != nil || result.Response.URL != "" || len(result.Response.Body) > 0 || result.Response.StatusCode != 0 || result.Response.Truncated) {
		responses = []rdap.Response{result.Response}
	}
	for _, response := range responses {
		item := Item{
			Protocol:   RDAP,
			Source:     response.URL,
			StatusCode: response.StatusCode,
			Duration:   response.Duration,
			Error:      responseError(response.Error),
			Body:       append([]byte(nil), response.Body...),
			JSON:       json.Valid(response.Body),
		}
		if len(response.Body) > 0 && !item.JSON {
			item.Warning = "The RDAP server returned invalid JSON; showing the original response body."
		}
		output.Items = append(output.Items, item)
	}
	if err != nil {
		if len(output.Items) > 0 && output.Items[len(output.Items)-1].Error == "" {
			last := &output.Items[len(output.Items)-1]
			if last.StatusCode < http.StatusOK || last.StatusCode >= http.StatusMultipleChoices || !last.JSON {
				last.Error = err.Error()
			}
		}
		output.Error = "RDAP lookup failed: " + err.Error()
		return output, err
	}
	output.TTL, output.Cacheable = rdapResponsesFreshness(responses, s.config.CacheTTL, s.now())
	return output, nil
}

func hasSuccessfulRDAPResponse(result Result) bool {
	for _, item := range result.Items {
		if item.Protocol == RDAP && item.StatusCode >= http.StatusOK && item.StatusCode < http.StatusMultipleChoices && item.JSON {
			return true
		}
	}
	return false
}

func (s *Service) lookupWHOIS(ctx context.Context, query string) (Result, error) {
	result, err := s.whois.Lookup(ctx, query)
	output := Result{Query: result.Query, TTL: s.config.CacheTTL, Cacheable: true}
	for index, response := range result.Responses {
		body := strings.TrimSpace(strings.ToValidUTF8(string(response.Body), "\uFFFD"))
		itemError := responseError(response.Error)
		if body == "" && itemError == "" && err != nil && index == len(result.Responses)-1 {
			itemError = err.Error()
		}
		if body == "" && itemError == "" {
			continue
		}
		output.Items = append(output.Items, Item{
			Protocol: WHOIS,
			Source:   displayWHOISEndpoint(response.Endpoint),
			Duration: response.Duration,
			Error:    itemError,
			Body:     []byte(body),
		})
	}
	if err != nil {
		output.Error = "WHOIS lookup failed: " + err.Error()
		output.TTL = errorCacheTTL
	} else if len(output.Items) == 0 {
		output.Error = "No output returned from the WHOIS server."
		output.TTL = errorCacheTTL
		err = errors.New("empty WHOIS response")
	}
	return output, err
}

func summarizeFailedItems(items []Item) []Item {
	result := make([]Item, 0, len(items))
	for _, item := range items {
		item.Body = nil
		item.JSON = false
		item.Warning = ""
		result = append(result, item)
	}
	return result
}

func responseError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func displayWHOISEndpoint(endpoint whois.Endpoint) string {
	if endpoint.Port == 0 || endpoint.Port == 43 {
		return endpoint.Host
	}
	return endpoint.String()
}

func shouldFallbackRDAP(err error) bool {
	var httpErr *rdap.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode < 400 || httpErr.StatusCode >= 500
	}
	return true
}

func isRequestCancellation(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
}

func rdapFreshness(header http.Header, capTTL time.Duration, now time.Time) (time.Duration, bool) {
	directives := parseCacheControl(header.Values("Cache-Control"))
	for _, name := range []string{"no-store", "private", "no-cache"} {
		if _, exists := directives[name]; exists {
			return 0, false
		}
	}
	age := parseDeltaSeconds(header.Get("Age"))
	if age < 0 {
		age = 0
	}
	for _, name := range []string{"s-maxage", "max-age"} {
		if value, exists := directives[name]; exists {
			seconds := parseDeltaSeconds(value)
			if seconds < 0 {
				continue
			}
			return clampFreshness(time.Duration(seconds-age)*time.Second, capTTL)
		}
	}
	if expires, err := http.ParseTime(header.Get("Expires")); err == nil {
		base := now
		if date, dateErr := http.ParseTime(header.Get("Date")); dateErr == nil {
			base = date
		}
		return clampFreshness(expires.Sub(base)-time.Duration(age)*time.Second, capTTL)
	}
	return clampFreshness(capTTL, capTTL)
}

func rdapResponsesFreshness(responses []rdap.Response, capTTL time.Duration, now time.Time) (time.Duration, bool) {
	if len(responses) == 0 {
		return 0, false
	}
	result := capTTL
	for _, response := range responses {
		ttl, cacheable := rdapFreshness(response.Header, capTTL, now)
		if !cacheable {
			return 0, false
		}
		if ttl < result {
			result = ttl
		}
	}
	return result, result > 0
}

func parseCacheControl(values []string) map[string]string {
	result := make(map[string]string)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			name, directiveValue, found := strings.Cut(strings.TrimSpace(part), "=")
			name = strings.ToLower(name)
			if !found {
				result[name] = ""
				continue
			}
			result[name] = strings.Trim(strings.TrimSpace(directiveValue), "\"")
		}
	}
	return result
}

func parseDeltaSeconds(value string) int64 {
	if value == "" {
		return 0
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || seconds < 0 {
		return -1
	}
	return seconds
}

func clampFreshness(ttl, capTTL time.Duration) (time.Duration, bool) {
	if ttl <= 0 {
		return 0, false
	}
	if ttl > capTTL {
		ttl = capTTL
	}
	return ttl, true
}
