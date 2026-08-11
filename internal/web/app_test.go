package web

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/whodis/rdap"
	"foundry.fsky.io/fsky/whodis/whois"
)

func TestLookupDefaultsToAutoAndRendersCompleteRDAPJSON(t *testing.T) {
	body := []byte(`{"handle":"EXAMPLE","extension":{"unknown":true},"unsafe":"<script>alert(1)</script>"}`)
	rdapClient := &fakeRDAPClient{result: rdap.Result{
		Query: "example.com",
		Response: rdap.Response{
			URL:        "https://rdap.example/domain/example.com",
			StatusCode: http.StatusOK,
			Header:     http.Header{"Cache-Control": {"max-age=60"}},
			Body:       body,
		},
	}}
	whoisClient := &fakeWHOISClient{}
	app := newTestApp(t, whoisClient, rdapClient)

	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=Example.COM", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Whodis-Cache") != "MISS" {
		t.Fatalf("status = %d, cache = %q", recorder.Code, recorder.Header().Get("Whodis-Cache"))
	}
	page := recorder.Body.String()
	for _, want := range []string{"RDAP", `href="https://rdap.example/domain/example.com" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer"`, "200 OK", `class="result-hop" open`, "Hop 1", "Lookup completed in", "ms", "json-key", "json-boolean", "extension", "unknown", "&lt;script&gt;alert(1)&lt;/script&gt;", "<summary>Raw JSON</summary>", `value="auto" checked`, `rel="search"`, `href="/opensearch.xml"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not contain %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Fatal("untrusted JSON was rendered as HTML")
	}
	if whoisClient.calls != 0 {
		t.Fatalf("WHOIS calls = %d", whoisClient.calls)
	}
}

func TestLookupRendersEachHopOpenWithItsDuration(t *testing.T) {
	rdapClient := &fakeRDAPClient{result: rdap.Result{
		Query: "example.com",
		Responses: []rdap.Response{
			{URL: "https://registry.example/domain/example.com", StatusCode: http.StatusOK, Duration: 184 * time.Millisecond, Body: []byte(`{"handle":"REGISTRY"}`)},
			{URL: "https://registrar.example/domain/example.com", StatusCode: http.StatusOK, Duration: 1250 * time.Millisecond, Body: []byte(`{"handle":"REGISTRAR"}`)},
		},
	}}
	app := newTestApp(t, &fakeWHOISClient{}, rdapClient)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=example.com&protocol=rdap", nil))

	page := recorder.Body.String()
	if got := strings.Count(page, `class="result-hop" open`); got != 2 {
		t.Fatalf("open hop sections = %d, want 2:\n%s", got, page)
	}
	for _, want := range []string{"Hop 1", "Hop 2", "184 ms", "1.25 s"} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not contain %q:\n%s", want, page)
		}
	}
}

func TestFailedRDAPHopRendersEndpointErrorAndFailureState(t *testing.T) {
	rdapClient := &fakeRDAPClient{
		result: rdap.Result{Response: rdap.Response{
			URL:        "https://bad.example/domain/example.com",
			StatusCode: http.StatusBadGateway,
			Duration:   1250 * time.Millisecond,
			Body:       []byte(`{"errorCode":502}`),
		}},
		err: &rdap.HTTPError{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway"},
	}
	app := newTestApp(t, &fakeWHOISClient{}, rdapClient)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=example.com&protocol=rdap", nil))

	page := recorder.Body.String()
	for _, want := range []string{`class="result-hop result-hop-failed" open`, "Hop 1", "bad.example", "1.25 s", "Failed", "Request failed:", "rdap server returned 502 Bad Gateway"} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not contain %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "RDAP lookup failed:") {
		t.Fatal("full lookup error duplicated the failed-hop error")
	}
}

func TestFailedWHOISHopWithoutBodyRendersEndpointAndError(t *testing.T) {
	whoisClient := &fakeWHOISClient{
		result: whois.Result{Responses: []whois.Response{{
			Endpoint: whois.Endpoint{Host: "whois.failed.test"},
			Duration: 2 * time.Second,
			Error:    errors.New("connection refused"),
		}}},
		err: errors.New("connection refused"),
	}
	app := newTestApp(t, whoisClient, &fakeRDAPClient{})
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=example.com&protocol=whois", nil))

	page := recorder.Body.String()
	for _, want := range []string{`class="result-hop result-hop-failed" open`, "Hop 1", "whois.failed.test", "2.00 s", "Failed", "Request failed:", "connection refused"} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not contain %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "WHOIS lookup failed:") {
		t.Fatal("full lookup error duplicated the failed-hop error")
	}
}

func TestOpenSearchDescriptionUsesRequestOrigin(t *testing.T) {
	app := newTestApp(t, &fakeWHOISClient{}, &fakeRDAPClient{})
	request := httptest.NewRequest(http.MethodGet, "http://who.dis.test/opensearch.xml", nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/opensearchdescription+xml; charset=utf-8" {
		t.Fatalf("status = %d, content type = %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	var description openSearchDescription
	if err := xml.Unmarshal(recorder.Body.Bytes(), &description); err != nil {
		t.Fatalf("decode OpenSearch description: %v\n%s", err, recorder.Body.String())
	}
	if description.ShortName != "who dis?" || description.InputEncoding != "UTF-8" || len(description.URLs) != 2 {
		t.Fatalf("description = %#v", description)
	}
	if got, want := description.Image, (openSearchImage{Height: 16, Width: 16, Type: "image/x-icon", URL: "http://who.dis.test/favicon.ico"}); got != want {
		t.Fatalf("image = %#v, want %#v", got, want)
	}
	if got, want := description.URLs[1].Template, "http://who.dis.test/lookup?q={searchTerms}"; got != want {
		t.Fatalf("search template = %q, want %q", got, want)
	}
}

func TestOpenSearchDescriptionUsesForwardedHTTPSWhenTrusted(t *testing.T) {
	app := newTestApp(t, &fakeWHOISClient{}, &fakeRDAPClient{})
	app.config.TrustProxyHeaders = true
	request := httptest.NewRequest(http.MethodGet, "/opensearch.xml", nil)
	request.Host = "who.dis.test"
	request.Header.Set("X-Forwarded-Proto", "https, http")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	if !strings.Contains(recorder.Body.String(), `template="https://who.dis.test/lookup?q={searchTerms}"`) {
		t.Fatalf("OpenSearch description does not use forwarded HTTPS:\n%s", recorder.Body.String())
	}
}

func TestRDAPRawViewPreservesOriginalBody(t *testing.T) {
	body := []byte("{\"url\":\"https:\\/\\/rdap.example\\/domain\\/example.com\",\"number\":1.2300e+02}\n")
	app := newTestApp(t, &fakeWHOISClient{}, &fakeRDAPClient{})
	data := pageData{}
	app.populatePage(&data, lookupResult{Items: []resultItem{{
		Protocol:   protocolRDAP,
		StatusCode: http.StatusOK,
		Body:       body,
		JSON:       true,
	}}}, time.Now())
	if len(data.Results) != 1 || data.Results[0].RawBody != string(body) {
		t.Fatalf("raw body = %q, want %q", data.Results[0].RawBody, body)
	}
	var highlighted strings.Builder
	for _, token := range data.Results[0].Tokens {
		highlighted.WriteString(token.Text)
	}
	if !strings.Contains(highlighted.String(), `https:\/\/rdap.example\/domain\/example.com`) {
		t.Fatalf("highlighted body changed escaped slashes: %s", highlighted.String())
	}
}

func TestFormatDuration(t *testing.T) {
	for _, test := range []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{name: "milliseconds", duration: 184 * time.Millisecond, want: "184 ms"},
		{name: "minimum millisecond", duration: 500 * time.Microsecond, want: "1 ms"},
		{name: "seconds", duration: 1250 * time.Millisecond, want: "1.25 s"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := formatDuration(test.duration); got != test.want {
				t.Fatalf("formatDuration(%v) = %q, want %q", test.duration, got, test.want)
			}
		})
	}
}

func TestPopulatePageNumbersHopsAndCopiesDuration(t *testing.T) {
	app := newTestApp(t, &fakeWHOISClient{}, &fakeRDAPClient{})
	data := pageData{}
	app.populatePage(&data, lookupResult{Items: []resultItem{
		{Protocol: protocolWHOIS, Source: "whois.first.test", Duration: 12 * time.Millisecond, Body: []byte("first")},
		{Protocol: protocolWHOIS, Source: "whois.second.test", Duration: 1250 * time.Millisecond, Body: []byte("second")},
	}}, time.Now())

	if len(data.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(data.Results))
	}
	if data.Results[0].Hop != 1 || data.Results[0].Duration != "12 ms" {
		t.Fatalf("first result = %#v", data.Results[0])
	}
	if data.Results[1].Hop != 2 || data.Results[1].Duration != "1.25 s" {
		t.Fatalf("second result = %#v", data.Results[1])
	}
}

func TestUnknownProtocolReturns400WithoutLookup(t *testing.T) {
	rdapClient := &fakeRDAPClient{}
	whoisClient := &fakeWHOISClient{}
	app := newTestApp(t, whoisClient, rdapClient)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=example.com&protocol=dns", nil))
	if recorder.Code != http.StatusBadRequest || rdapClient.calls != 0 || whoisClient.calls != 0 {
		t.Fatalf("status = %d, RDAP calls = %d, WHOIS calls = %d", recorder.Code, rdapClient.calls, whoisClient.calls)
	}
}

func TestInvalidTargetReturns400WithoutLookup(t *testing.T) {
	rdapClient := &fakeRDAPClient{}
	whoisClient := &fakeWHOISClient{}
	app := newTestApp(t, whoisClient, rdapClient)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=two%20resources", nil))
	if recorder.Code != http.StatusBadRequest || rdapClient.calls != 0 || whoisClient.calls != 0 {
		t.Fatalf("status = %d, RDAP calls = %d, WHOIS calls = %d", recorder.Code, rdapClient.calls, whoisClient.calls)
	}
}

func TestLegacyRoutesRedirectToLookupAndPreserveExplicitProtocol(t *testing.T) {
	app := newTestApp(t, &fakeWHOISClient{}, &fakeRDAPClient{})
	tests := map[string]string{
		"/whois?q=example.com":               "/lookup?q=example.com",
		"/?q=example.com&protocol=whois":     "/lookup?protocol=whois&q=example.com",
		"/whois?q=example.com&protocol=rdap": "/lookup?protocol=rdap&q=example.com",
		"/whois?protocol=whois":              "/lookup?protocol=whois",
	}
	for requestURL, wantLocation := range tests {
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, requestURL, nil))
		if recorder.Code != http.StatusPermanentRedirect || recorder.Header().Get("Location") != wantLocation {
			t.Errorf("GET %s = %d Location %q; want %d %q", requestURL, recorder.Code, recorder.Header().Get("Location"), http.StatusPermanentRedirect, wantLocation)
		}
	}
}

func TestAutoDoesNotFallbackOnFourHundredResponse(t *testing.T) {
	rdapClient := &fakeRDAPClient{
		result: rdap.Result{Response: rdap.Response{URL: "https://rdap.example/domain/missing.test", StatusCode: http.StatusNotFound, Body: []byte(`{"errorCode":404,"title":"not found"}`)}},
		err:    &rdap.HTTPError{StatusCode: http.StatusNotFound, Status: "404 Not Found"},
	}
	whoisClient := &fakeWHOISClient{}
	app := newTestApp(t, whoisClient, rdapClient)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=missing.test", nil))
	if whoisClient.calls != 0 {
		t.Fatalf("WHOIS calls = %d", whoisClient.calls)
	}
	page := recorder.Body.String()
	for _, want := range []string{"404 Not Found", "errorCode", "Failed", "Request failed:"} {
		if !strings.Contains(page, want) {
			t.Errorf("body does not contain %q", want)
		}
	}
	if strings.Contains(page, "RDAP lookup failed:") {
		t.Fatal("full lookup error duplicated the failed-hop error")
	}
}

func TestAutoFallbackSuppressesFailedRDAPBodyAndRetainsMode(t *testing.T) {
	rdapClient := &fakeRDAPClient{
		result: rdap.Result{Response: rdap.Response{URL: "https://bad.example/", StatusCode: http.StatusBadGateway, Body: []byte(`{"secret-failed-body":true}`)}},
		err:    &rdap.HTTPError{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway"},
	}
	whoisClient := &fakeWHOISClient{result: whois.Result{Query: "example.com", Responses: []whois.Response{{Endpoint: whois.Endpoint{Host: "whois.example"}, Body: []byte("Domain Name: EXAMPLE.COM\r\n")}}}}
	app := newTestApp(t, whoisClient, rdapClient)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=example.com&protocol=auto", nil))
	page := recorder.Body.String()
	for _, want := range []string{"showing WHOIS fallback", "Hop 1", "Hop 2", "bad.example", "Failed", "Request failed:", "rdap server returned 502 Bad Gateway", "Domain Name: EXAMPLE.COM", `value="auto" checked`} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
	if strings.Contains(page, "secret-failed-body") {
		t.Fatal("failed RDAP body leaked into fallback page")
	}
}

func TestAutoPreservesSuccessfulRDAPHopWhenReferralFails(t *testing.T) {
	rdapClient := &fakeRDAPClient{
		result: rdap.Result{Query: "example.com", Responses: []rdap.Response{{
			URL:        "https://registry.example/domain/example.com",
			StatusCode: http.StatusOK,
			Body:       []byte(`{"objectClassName":"domain","handle":"REGISTRY"}`),
		}}},
		err: errors.New("registrar unavailable"),
	}
	whoisClient := &fakeWHOISClient{result: whois.Result{Responses: []whois.Response{{Body: []byte("must not be used")}}}}
	app := newTestApp(t, whoisClient, rdapClient)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=example.com", nil))

	page := recorder.Body.String()
	resultPosition := strings.Index(page, "REGISTRY")
	errorPosition := strings.Index(page, "RDAP lookup failed: registrar unavailable")
	if resultPosition < 0 || errorPosition < resultPosition {
		t.Fatalf("partial RDAP error was not rendered after its completed response:\n%s", page)
	}
	if whoisClient.calls != 0 || strings.Contains(page, "must not be used") || strings.Contains(page, "showing WHOIS fallback") {
		t.Fatalf("successful partial RDAP result incorrectly fell back to WHOIS: calls = %d\n%s", whoisClient.calls, page)
	}
}

func TestForcedRDAPShowsInvalidJSONEscaped(t *testing.T) {
	rdapClient := &fakeRDAPClient{
		result: rdap.Result{Response: rdap.Response{URL: "https://rdap.example/", StatusCode: http.StatusOK, Body: []byte(`<b>not json</b>`)}},
		err:    rdap.ErrInvalidResponse,
	}
	app := newTestApp(t, &fakeWHOISClient{}, rdapClient)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=example.com&protocol=rdap", nil))
	page := recorder.Body.String()
	if !strings.Contains(page, "invalid JSON") || !strings.Contains(page, "&lt;b&gt;not json&lt;/b&gt;") || strings.Contains(page, "<b>not json</b>") {
		t.Fatalf("body = %s", page)
	}
	if !strings.Contains(page, `value="rdap" checked`) {
		t.Fatal("forced mode was not retained")
	}
	if strings.Contains(page, "<summary>Raw JSON</summary>") {
		t.Fatal("invalid JSON duplicated its already-raw primary display")
	}
}

func TestBothProtocolFailuresPreservePartialWHOIS(t *testing.T) {
	rdapClient := &fakeRDAPClient{err: rdap.ErrNoService}
	whoisClient := &fakeWHOISClient{
		result: whois.Result{Responses: []whois.Response{{Endpoint: whois.Endpoint{Host: "whois.example"}, Body: []byte("partial output")}}},
		err:    errors.New("registrar unavailable"),
	}
	app := newTestApp(t, whoisClient, rdapClient)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/lookup?q=example.com", nil))
	for _, want := range []string{"no RDAP service", "WHOIS lookup failed", "registrar unavailable", "partial output"} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("body does not contain %q", want)
		}
	}
	page := recorder.Body.String()
	if strings.Index(page, "WHOIS lookup failed") < strings.Index(page, "partial output") {
		t.Fatalf("later-hop WHOIS error was rendered above its completed response:\n%s", page)
	}
}

func TestCacheSeparatesProtocolsAndReportsRemainingLifetime(t *testing.T) {
	rdapClient := &fakeRDAPClient{result: rdap.Result{Response: rdap.Response{URL: "https://rdap.example/", StatusCode: http.StatusOK, Header: http.Header{"Cache-Control": {"max-age=60"}}, Body: []byte(`{}`)}}}
	whoisClient := &fakeWHOISClient{result: whois.Result{Responses: []whois.Response{{Endpoint: whois.Endpoint{Host: "whois.example"}, Body: []byte("whois")}}}}
	app := newTestApp(t, whoisClient, rdapClient)
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	app.now = func() time.Time { return now }
	app.cache = newCache(app.now)
	handler := app.Handler()

	request := func(rawURL string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, rawURL, nil))
		return recorder
	}
	if got := request("/lookup?q=example.com&protocol=rdap"); got.Header().Get("Whodis-Cache") != "MISS" {
		t.Fatalf("first cache = %q", got.Header().Get("Whodis-Cache"))
	}
	now = now.Add(15 * time.Second)
	if got := request("/lookup?q=EXAMPLE.COM&protocol=rdap"); got.Header().Get("Cache-Control") != "public, max-age=45" || got.Header().Get("Whodis-Cache") != "HIT" {
		t.Fatalf("hit headers = %#v", got.Header())
	} else if !strings.Contains(got.Body.String(), "Lookup completed in ") || !strings.Contains(got.Body.String(), "(cached)") || strings.Contains(got.Body.String(), "Cached result") {
		t.Fatalf("cache hit page does not identify cached result:\n%s", got.Body.String())
	}
	request("/lookup?q=example.com&protocol=whois")
	if rdapClient.calls != 1 || whoisClient.calls != 1 {
		t.Fatalf("RDAP calls = %d, WHOIS calls = %d", rdapClient.calls, whoisClient.calls)
	}
}

func TestRateLimitAppliesOnlyToCacheMisses(t *testing.T) {
	rdapClient := &fakeRDAPClient{}
	whoisClient := &fakeWHOISClient{result: whois.Result{Responses: []whois.Response{{Endpoint: whois.Endpoint{Host: "whois.example"}, Body: []byte("whois")}}}}
	app := newTestApp(t, whoisClient, rdapClient)
	app.limiter = newRateLimiter(1, 1, app.now)
	handler := app.Handler()
	for index, rawURL := range []string{"/lookup?q=example.com&protocol=whois", "/lookup?q=example.com&protocol=whois", "/lookup?q=example.net&protocol=whois"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, rawURL, nil))
		want := http.StatusOK
		if index == 2 {
			want = http.StatusTooManyRequests
		}
		if recorder.Code != want {
			t.Errorf("request %d status = %d, want %d", index, recorder.Code, want)
		}
	}
	if whoisClient.calls != 1 {
		t.Fatalf("WHOIS calls = %d", whoisClient.calls)
	}
}
