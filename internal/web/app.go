package web

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gitfield.org/fsky/whodis/internal/forwarded"
	"gitfield.org/fsky/whodis/internal/lookup"
)

//go:embed templates/* static/*
var content embed.FS

// Config controls request handling that is specific to the web UI.
type Config struct {
	// Limiter admits cache-miss lookups per client IP; nil disables limiting.
	Limiter           *lookup.RateLimiter
	TrustProxyHeaders bool
}

type App struct {
	config  Config
	service *lookup.Service
	tmpl    *template.Template
	logf    func(string, ...any)
}

type pageData struct {
	Query        string
	Protocol     lookup.Protocol
	AutoChecked  bool
	RDAPChecked  bool
	WHOISChecked bool
	Results      []viewResult
	Error        string
	Notice       string
	FetchedAt    string
	LookupTime   string
	CacheHit     bool
	HasFailedHop bool
}

type viewResult struct {
	Hop         int
	Protocol    string
	SourceLabel string
	Source      string
	SourceURL   string
	Status      string
	Duration    string
	Error       string
	Tokens      []jsonToken
	Body        string
	RawBody     string
	Warning     string
}

func New(service *lookup.Service, config Config) (*App, error) {
	if service == nil {
		return nil, fmt.Errorf("lookup service must not be nil")
	}
	tmpl, err := template.ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &App{config: config, service: service, tmpl: tmpl, logf: log.Printf}, nil
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServer(http.FS(content)))
	mux.HandleFunc("/favicon.ico", a.handleFavicon)
	mux.HandleFunc("/opensearch.xml", a.handleOpenSearch)
	mux.HandleFunc("/lookup", a.handleLookup)
	mux.HandleFunc("/whois", a.handleLegacyWhois)
	mux.HandleFunc("/", a.handleIndex)
	return mux
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !allowGet(w, r) {
		return
	}
	if query := r.URL.Query().Get("q"); query != "" {
		a.redirectLookup(w, r, query, r.URL.Query().Get("protocol"), http.StatusPermanentRedirect)
		return
	}
	a.renderPage(w, http.StatusOK, pageData{Protocol: lookup.Auto, AutoChecked: true}, "no-cache, no-store, must-revalidate")
}

func (a *App) handleLegacyWhois(w http.ResponseWriter, r *http.Request) {
	if !allowGet(w, r) {
		return
	}
	a.redirectLookup(w, r, r.URL.Query().Get("q"), r.URL.Query().Get("protocol"), http.StatusPermanentRedirect)
}

func (a *App) redirectLookup(w http.ResponseWriter, r *http.Request, query, protocolValue string, status int) {
	values := url.Values{}
	if query != "" {
		values.Set("q", query)
	}
	if protocolValue != "" {
		values.Set("protocol", protocolValue)
	}
	location := "/lookup"
	if encoded := values.Encode(); encoded != "" {
		location += "?" + encoded
	}
	http.Redirect(w, r, location, status)
}

func (a *App) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/lookup" {
		http.NotFound(w, r)
		return
	}
	if !allowGet(w, r) {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	mode, err := lookup.ParseProtocol(r.URL.Query().Get("protocol"))
	data := newPageData(query, mode)
	if err != nil {
		data.Error = err.Error() + ". Choose Auto, RDAP, or WHOIS."
		a.renderPage(w, http.StatusBadRequest, data, "no-cache, no-store, must-revalidate")
		return
	}

	outcome, err := a.service.Lookup(r.Context(), lookup.Request{
		Query:    query,
		Protocol: mode,
		Limiter:  a.config.Limiter,
		Client:   forwarded.ClientIP(r, a.config.TrustProxyHeaders),
	})
	var rateLimitErr *lookup.RateLimitError
	switch {
	case errors.Is(err, lookup.ErrQueryTooLong):
		data.Error = "Query is too long. Please limit it to 256 characters."
		a.renderPage(w, http.StatusBadRequest, data, "no-cache, no-store, must-revalidate")
		return
	case errors.Is(err, lookup.ErrInvalidTarget):
		data.Error = "Invalid lookup target: " + err.Error()
		a.renderPage(w, http.StatusBadRequest, data, "no-cache, no-store, must-revalidate")
		return
	case errors.As(err, &rateLimitErr):
		data.Error = "Rate limit exceeded. Please wait a moment and try again."
		w.Header().Set("Retry-After", "30")
		a.renderPage(w, http.StatusTooManyRequests, data, "no-cache, no-store, must-revalidate")
		return
	case err != nil:
		// The client went away or the lookup exceeded its time budget.
		return
	}

	cacheControl := "no-cache, no-store, must-revalidate"
	if outcome.CacheHit || outcome.MaxAge > 0 {
		cacheControl = fmt.Sprintf("public, max-age=%d", int(outcome.MaxAge.Seconds()))
	}
	if outcome.CacheHit {
		w.Header().Set("Whodis-Cache", "HIT")
	} else {
		w.Header().Set("Whodis-Cache", "MISS")
	}
	a.populatePage(&data, outcome.Result, outcome.FetchedAt)
	data.LookupTime = formatDuration(lookupResultDuration(outcome.Result))
	data.CacheHit = outcome.CacheHit
	a.renderPage(w, http.StatusOK, data, cacheControl)
}

func (a *App) populatePage(data *pageData, result lookup.Result, fetchedAt time.Time) {
	data.Error = result.Error
	data.Notice = result.Notice
	data.FetchedAt = fetchedAt.Format(time.RFC1123)
	for hop, item := range result.Items {
		view := viewResult{Hop: hop + 1, Source: item.Source, Duration: formatDuration(item.Duration), Error: item.Error, Warning: item.Warning}
		if item.Error != "" {
			data.HasFailedHop = true
		}
		switch item.Protocol {
		case lookup.RDAP:
			view.Protocol = "RDAP"
			view.SourceLabel = "Queried URL"
			view.SourceURL = item.Source
			if item.StatusCode != 0 {
				view.Status = fmt.Sprintf("%d %s", item.StatusCode, http.StatusText(item.StatusCode))
			}
			if item.JSON {
				view.RawBody = string(item.Body)
				if tokens, err := highlightJSON(item.Body); err == nil {
					view.Tokens = tokens
				} else {
					view.Body = strings.ToValidUTF8(string(item.Body), "\uFFFD")
					view.Warning = "The RDAP response could not be highlighted; showing its original body."
				}
			} else {
				view.Body = strings.ToValidUTF8(string(item.Body), "\uFFFD")
			}
		default:
			view.Protocol = "WHOIS"
			view.SourceLabel = "Queried server"
			view.Body = string(item.Body)
		}
		data.Results = append(data.Results, view)
	}
}

func formatDuration(duration time.Duration) string {
	if duration < time.Second {
		milliseconds := duration.Round(time.Millisecond) / time.Millisecond
		if milliseconds < 1 {
			milliseconds = 1
		}
		return fmt.Sprintf("%d ms", milliseconds)
	}
	return fmt.Sprintf("%.2f s", duration.Round(10*time.Millisecond).Seconds())
}

func lookupResultDuration(result lookup.Result) time.Duration {
	if result.Duration > 0 {
		return result.Duration
	}
	var total time.Duration
	for _, item := range result.Items {
		total += item.Duration
	}
	return total
}

func newPageData(query string, mode lookup.Protocol) pageData {
	return pageData{
		Query:        query,
		Protocol:     mode,
		AutoChecked:  mode == lookup.Auto,
		RDAPChecked:  mode == lookup.RDAP,
		WHOISChecked: mode == lookup.WHOIS,
	}
}

func (a *App) renderPage(w http.ResponseWriter, status int, data pageData, cacheControl string) {
	var body bytes.Buffer
	if err := a.tmpl.ExecuteTemplate(&body, "index.html", data); err != nil {
		a.logf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", cacheControl)
	w.WriteHeader(status)
	_, _ = io.Copy(w, &body)
}

func (a *App) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if !allowGet(w, r) {
		return
	}
	file, err := content.ReadFile("static/favicon.ico")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	_, _ = w.Write(file)
}

func allowGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	return false
}
