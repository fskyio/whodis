package rdap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFindReferral(t *testing.T) {
	tests := []struct {
		name    string
		current string
		body    string
		want    string
	}{
		{
			name:    "absolute RDAP link",
			current: "https://registry.example/rdap/domain/example.test",
			body:    `{"objectClassName":"domain","links":[{"rel":"self","href":"https://registry.example/rdap/domain/example.test"},{"rel":"alternate RELATED","href":"https://registrar.example/rdap/domain/example.test","type":"application/rdap+json; charset=utf-8"}]}`,
			want:    "https://registrar.example/rdap/domain/example.test",
		},
		{
			name:    "relative application JSON link",
			current: "http://registry.example/rdap/domain/example.test",
			body:    `{"objectClassName":"domain","links":[{"rel":"related","href":"../../../registrar/domain/example.test","type":"application/json"}]}`,
			want:    "http://registry.example/registrar/domain/example.test",
		},
		{
			name:    "malformed and HTML links skipped",
			current: "https://registry.example/rdap/domain/example.test",
			body:    `{"objectClassName":"domain","links":[7,{"rel":"related","href":"https://www.example.test/","type":"text/html"},{"rel":"related","href":"https://registrar.example/domain/example.test"}]}`,
			want:    "https://registrar.example/domain/example.test",
		},
		{
			name:    "nested related link ignored",
			current: "https://registry.example/rdap/domain/example.test",
			body:    `{"objectClassName":"domain","entities":[{"links":[{"rel":"related","href":"https://entity.example/rdap/entity/123","type":"application/rdap+json"}]}]}`,
		},
		{
			name:    "non-domain related link ignored",
			current: "https://rir.example/rdap/ip/192.0.2.0/24",
			body:    `{"objectClassName":"ip network","links":[{"rel":"related","href":"https://rir.example/rdap/entity/123","type":"application/rdap+json"}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := findReferral(test.current, []byte(test.body))
			if err != nil || got != test.want {
				t.Fatalf("findReferral() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestReferralURLGuards(t *testing.T) {
	if _, err := resolveReferralURL("https://registry.example/domain/example.test", "http://registrar.example/domain/example.test"); !errors.Is(err, ErrInsecureReferral) {
		t.Fatalf("HTTPS downgrade error = %v, want ErrInsecureReferral", err)
	}
	first, err := referralURLKey("https://RDAP.Example:443/domain/example.test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := referralURLKey("https://rdap.example./domain/example.test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("equivalent URL keys differ: %q != %q", first, second)
	}
}

func TestLookupFollowsRDAPReferralAndPreservesHops(t *testing.T) {
	registrar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domain/example.test" {
			t.Errorf("registrar path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"objectClassName":"domain","handle":"REGISTRAR"}`)
	}))
	defer registrar.Close()

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"objectClassName":"domain","handle":"REGISTRY","links":[{"rel":"related","href":%q,"type":"application/rdap+json"}]}`, registrar.URL+"/domain/example.test")
	}))
	defer registry.Close()
	setTestDomainRoute(t, registry.URL+"/")

	client := NewClient(WithLookupEndpointPolicy(AllowAnyEndpoint))
	result, err := client.Lookup(context.Background(), "Example.TEST")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if result.Query != "example.test" || len(result.Responses) != 2 {
		t.Fatalf("result = %#v", result)
	}
	if result.Responses[0].Referral != registrar.URL+"/domain/example.test" {
		t.Fatalf("referral = %q", result.Responses[0].Referral)
	}
	if !strings.Contains(string(result.Responses[0].Body), "REGISTRY") || !strings.Contains(string(result.Responses[1].Body), "REGISTRAR") {
		t.Fatalf("response chain = %#v", result.Responses)
	}
	if result.Response.URL != result.Responses[1].URL {
		t.Fatalf("compatibility response = %#v; want final response", result.Response)
	}
}

func TestLookupPreservesResponsesWhenReferralFails(t *testing.T) {
	registrar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"errorCode":502,"title":"registrar unavailable"}`)
	}))
	defer registrar.Close()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"objectClassName":"domain","links":[{"rel":"related","href":%q}]}`, registrar.URL+"/domain/example.test")
	}))
	defer registry.Close()
	setTestDomainRoute(t, registry.URL+"/")

	result, err := NewClient(WithLookupEndpointPolicy(AllowAnyEndpoint)).Lookup(context.Background(), "example.test")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("Lookup() error = %v, want HTTP 502", err)
	}
	if len(result.Responses) != 2 || result.Responses[0].StatusCode != http.StatusOK || result.Responses[1].StatusCode != http.StatusBadGateway {
		t.Fatalf("responses = %#v", result.Responses)
	}
}

func TestLookupRejectsRDAPReferralLoop(t *testing.T) {
	requests := 0
	var registry *httptest.Server
	registry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = io.WriteString(w, `{"objectClassName":"domain","links":[{"rel":"related","href":"/domain/example.test","type":"application/rdap+json"}]}`)
	}))
	defer registry.Close()
	setTestDomainRoute(t, registry.URL+"/")

	result, err := NewClient(WithLookupEndpointPolicy(AllowAnyEndpoint)).Lookup(context.Background(), "example.test")
	if !errors.Is(err, ErrReferralLoop) {
		t.Fatalf("Lookup() error = %v, want ErrReferralLoop", err)
	}
	if requests != 1 || len(result.Responses) != 1 {
		t.Fatalf("requests = %d, responses = %#v", requests, result.Responses)
	}
}

func TestLookupBoundsRDAPReferralHops(t *testing.T) {
	registrarRequests := 0
	registrar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		registrarRequests++
		_, _ = io.WriteString(w, `{}`)
	}))
	defer registrar.Close()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"objectClassName":"domain","links":[{"rel":"related","href":%q}]}`, registrar.URL+"/domain/example.test")
	}))
	defer registry.Close()
	setTestDomainRoute(t, registry.URL+"/")

	client := NewClient(WithLookupEndpointPolicy(AllowAnyEndpoint), WithLimits(Limits{MaxHops: 1}))
	result, err := client.Lookup(context.Background(), "example.test")
	if !errors.Is(err, ErrTooManyReferrals) {
		t.Fatalf("Lookup() error = %v, want ErrTooManyReferrals", err)
	}
	if registrarRequests != 0 || len(result.Responses) != 1 {
		t.Fatalf("registrar requests = %d, responses = %#v", registrarRequests, result.Responses)
	}
}

func setTestDomainRoute(t *testing.T, baseURL string) {
	t.Helper()
	oldRoutes := generatedDNSRoutes
	generatedDNSRoutes = map[string][]string{"test": {baseURL}}
	t.Cleanup(func() { generatedDNSRoutes = oldRoutes })
}
