package web

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"foundry.fsky.io/fsky/whodis/internal/target"
)

//go:embed templates/* static/*
var content embed.FS

type App struct {
	config  Config
	whois   whoisLookupClient
	rdap    rdapLookupClient
	cache   *cacheStore
	limiter *rateLimiter
	tmpl    *template.Template
	now     func() time.Time
	logf    func(string, ...any)
}

type pageData struct {
	Query        string
	Protocol     protocol
	AutoChecked  bool
	RDAPChecked  bool
	WHOISChecked bool
	Results      []viewResult
	Error        string
	Notice       string
	FetchedAt    string
}

type viewResult struct {
	Protocol    string
	SourceLabel string
	Source      string
	Status      string
	Tokens      []jsonToken
	Body        string
	RawBody     string
	Warning     string
}

func New(config Config, whoisClient whoisLookupClient, rdapClient rdapLookupClient) (*App, error) {
	if whoisClient == nil || rdapClient == nil {
		return nil, fmt.Errorf("lookup clients must not be nil")
	}
	tmpl, err := template.ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, err
	}
	now := time.Now
	app := &App{
		config: config,
		whois:  whoisClient,
		rdap:   rdapClient,
		tmpl:   tmpl,
		now:    now,
		logf:   log.Printf,
	}
	app.cache = newCache(now)
	if config.RateLimitPerMinute > 0 {
		app.limiter = newRateLimiter(config.RateLimitPerMinute, config.RateLimitBurst, now)
	}
	return app, nil
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

func (a *App) RunMaintenance(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.cache.Cleanup()
			if a.limiter != nil {
				a.limiter.Cleanup(time.Hour)
			}
		}
	}
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
	a.renderPage(w, http.StatusOK, pageData{Protocol: protocolAuto, AutoChecked: true}, "no-cache, no-store, must-revalidate")
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
	mode, err := parseProtocol(r.URL.Query().Get("protocol"))
	data := newPageData(query, mode)
	if err != nil {
		data.Error = err.Error() + ". Choose Auto, RDAP, or WHOIS."
		a.renderPage(w, http.StatusBadRequest, data, "no-cache, no-store, must-revalidate")
		return
	}
	if len(query) > 256 {
		data.Error = "Query is too long. Please limit it to 256 characters."
		a.renderPage(w, http.StatusBadRequest, data, "no-cache, no-store, must-revalidate")
		return
	}
	if _, err := target.Parse(query, 256); err != nil {
		data.Error = "Invalid lookup target: " + err.Error()
		a.renderPage(w, http.StatusBadRequest, data, "no-cache, no-store, must-revalidate")
		return
	}

	key := normalizedCacheKey(mode, query)
	if entry, found := a.cache.Get(key); found {
		w.Header().Set("Whodis-Cache", "HIT")
		remaining := entry.ExpiresAt.Sub(a.now())
		a.populatePage(&data, entry.Result, entry.FetchedAt)
		a.renderPage(w, http.StatusOK, data, fmt.Sprintf("public, max-age=%d", int(remaining.Seconds())))
		return
	}

	if a.limiter != nil && !a.limiter.Allow(a.clientIP(r)) {
		data.Error = "Rate limit exceeded. Please wait a moment and try again."
		w.Header().Set("Retry-After", "30")
		a.renderPage(w, http.StatusTooManyRequests, data, "no-cache, no-store, must-revalidate")
		return
	}

	w.Header().Set("Whodis-Cache", "MISS")
	lookupCtx, cancel := context.WithTimeout(r.Context(), a.config.LookupTimeout)
	result, lookupErr := a.performLookup(lookupCtx, query, mode)
	cancel()
	if lookupErr != nil && (errorsIsCancellation(lookupErr) || r.Context().Err() != nil) {
		return
	}

	fetchedAt := a.now()
	cacheControl := "no-cache, no-store, must-revalidate"
	if result.Cacheable && result.TTL > 0 {
		entry := cacheEntry{Result: result, FetchedAt: fetchedAt, ExpiresAt: fetchedAt.Add(result.TTL)}
		a.cache.Set(key, entry)
		cacheControl = fmt.Sprintf("public, max-age=%d", int(result.TTL.Seconds()))
	}
	a.populatePage(&data, result, fetchedAt)
	a.renderPage(w, http.StatusOK, data, cacheControl)
}

func (a *App) populatePage(data *pageData, result lookupResult, fetchedAt time.Time) {
	data.Error = result.Error
	data.Notice = result.Notice
	data.FetchedAt = fetchedAt.Format(time.RFC1123)
	for _, item := range result.Items {
		view := viewResult{Source: item.Source, Warning: item.Warning}
		switch item.Protocol {
		case protocolRDAP:
			view.Protocol = "RDAP"
			view.SourceLabel = "Queried URL"
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

func newPageData(query string, mode protocol) pageData {
	return pageData{
		Query:        query,
		Protocol:     mode,
		AutoChecked:  mode == protocolAuto,
		RDAPChecked:  mode == protocolRDAP,
		WHOISChecked: mode == protocolWHOIS,
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

func (a *App) clientIP(r *http.Request) string {
	if a.config.TrustProxyHeaders {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			if index := strings.Index(forwarded, ","); index >= 0 {
				return strings.TrimSpace(forwarded[:index])
			}
			return strings.TrimSpace(forwarded)
		}
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return strings.TrimSpace(realIP)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func allowGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	return false
}

func errorsIsCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
