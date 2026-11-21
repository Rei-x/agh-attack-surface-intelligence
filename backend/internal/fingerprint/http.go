package fingerprint

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const (
	DefaultUserAgent    = "Dzieciol-Discovery/1.0 (+CBI-AGH; safe-readonly)"
	DefaultTimeout      = 8 * time.Second
	DefaultMaxRedirects = 5
	DefaultMaxBodyBytes = 256 * 1024 // 256 KB
	maxBodySnippetBytes = 4096
)

// DefaultSafePaths lists read-only paths probed with GET/HEAD only.
var DefaultSafePaths = []string{
	"/admin",
	"/login",
	"/version",
	"/robots.txt",
	"/wp-login.php",
	"/phpmyadmin",
	"/metrics",
	"/health",
	"/api/version",
	"/actuator/info",
}

// Options configures safe HTTP/HTTPS/TLS fingerprinting.
type Options struct {
	UserAgent      string
	Timeout        time.Duration
	MaxRedirects   int
	MaxBodyBytes   int64
	ProbeSafePaths bool
	SafePaths      []string
	Scheme         string // optional forced "http" or "https"
	RateLimiter    func(ctx context.Context, host string) error
	OnThrottle     func(host string, statusCode int, err error)
	Now            func() time.Time
	DisableJARM    bool // skip the 10-probe JARM TLS fingerprint (see jarm.go)
}

// DefaultOptions returns safe read-only defaults.
func DefaultOptions() Options {
	return Options{
		UserAgent:      DefaultUserAgent,
		Timeout:        DefaultTimeout,
		MaxRedirects:   DefaultMaxRedirects,
		MaxBodyBytes:   DefaultMaxBodyBytes,
		ProbeSafePaths: true,
		SafePaths:      append([]string(nil), DefaultSafePaths...),
	}
}

// Fingerprinter performs safe read-only HTTP/HTTPS/TLS metadata collection.
type Fingerprinter struct {
	defaults Options
}

// New creates a Fingerprinter with normalized safe defaults.
func New(opts Options) *Fingerprinter {
	return &Fingerprinter{defaults: normalizeOptions(opts)}
}

func normalizeOptions(opts Options) Options {
	if strings.TrimSpace(opts.UserAgent) == "" {
		opts.UserAgent = DefaultUserAgent
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = DefaultMaxRedirects
	}
	if opts.MaxRedirects > 10 {
		opts.MaxRedirects = 10
	}
	if opts.MaxBodyBytes <= 0 || opts.MaxBodyBytes > DefaultMaxBodyBytes {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.ProbeSafePaths && len(opts.SafePaths) == 0 {
		opts.SafePaths = append([]string(nil), DefaultSafePaths...)
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	return opts
}

// Probe runs a safe read-only HTTP/HTTPS/TLS probe using the provided options.
func Probe(ctx context.Context, ip string, port int, domainName string, opts *Options) (*domain.HTTPFingerprint, error) {
	o := DefaultOptions()
	if opts != nil {
		o = mergeOptions(o, *opts)
	}
	return New(o).Probe(ctx, ip, port, domainName, nil)
}

func mergeOptions(base, override Options) Options {
	out := base
	if override.UserAgent != "" {
		out.UserAgent = override.UserAgent
	}
	if override.Timeout > 0 {
		out.Timeout = override.Timeout
	}
	if override.MaxRedirects > 0 {
		out.MaxRedirects = override.MaxRedirects
	}
	if override.MaxBodyBytes > 0 {
		out.MaxBodyBytes = override.MaxBodyBytes
	}
	out.ProbeSafePaths = override.ProbeSafePaths
	if len(override.SafePaths) > 0 {
		out.SafePaths = override.SafePaths
	}
	if override.Scheme != "" {
		out.Scheme = override.Scheme
	}
	if override.RateLimiter != nil {
		out.RateLimiter = override.RateLimiter
	}
	if override.OnThrottle != nil {
		out.OnThrottle = override.OnThrottle
	}
	if override.Now != nil {
		out.Now = override.Now
	}
	out.DisableJARM = out.DisableJARM || override.DisableJARM
	return normalizeOptions(out)
}

// Probe inspects a single HTTP/HTTPS endpoint using strictly GET/HEAD requests.
func (f *Fingerprinter) Probe(ctx context.Context, ip string, port int, domainName string, override *Options) (*domain.HTTPFingerprint, error) {
	opts := f.defaults
	if override != nil {
		opts = mergeOptions(opts, *override)
	}

	schemes := candidateSchemes(port, opts.Scheme)
	var lastErr error
	for _, scheme := range schemes {
		fp, err := f.probeWithScheme(ctx, scheme, ip, port, domainName, opts)
		if err == nil {
			return fp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no scheme succeeded")
	}
	return nil, lastErr
}

func candidateSchemes(port int, forced string) []string {
	forced = strings.ToLower(strings.TrimSpace(forced))
	if forced == "http" || forced == "https" {
		return []string{forced}
	}
	switch port {
	case 443, 8443, 9443, 4443, 10443:
		return []string{"https", "http"}
	default:
		return []string{"http", "https"}
	}
}

func (f *Fingerprinter) probeWithScheme(ctx context.Context, scheme, ip string, port int, domainName string, opts Options) (*domain.HTTPFingerprint, error) {
	hostForURL := ip
	if domainName != "" {
		hostForURL = domainName
	}
	hostHeader := hostForURL
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		hostHeader = net.JoinHostPort(hostForURL, strconv.Itoa(port))
	} else if strings.Contains(hostForURL, ":") {
		hostHeader = "[" + hostForURL + "]"
	}

	targetAddr := net.JoinHostPort(ip, strconv.Itoa(port))
	serverName := domainName
	if serverName == "" {
		serverName = ip
	}

	dialer := &net.Dialer{
		Timeout: opts.Timeout,
	}

	transport := &http.Transport{
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			// Pin initial host to the scanned IP when Host header uses a domain name.
			h, p, err := net.SplitHostPort(addr)
			if err == nil && (h == domainName || h == ip) && p == strconv.Itoa(port) {
				return dialer.DialContext(dctx, network, targetAddr)
			}
			return dialer.DialContext(dctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Discovery inspects self-signed/expired certs safely.
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		MaxIdleConns:          4,
	}
	defer transport.CloseIdleConnections()

	var redirectChain []domain.RedirectHop
	var lastTLS *tls.ConnectionState

	errTooManyRedirects := errors.New("max redirects reached")
	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Enforce read-only method on every redirect hop.
			if req.Method != http.MethodGet && req.Method != http.MethodHead {
				req.Method = http.MethodGet
			}
			req.Header.Set("User-Agent", opts.UserAgent)
			if req.Response != nil {
				redirectChain = append(redirectChain, domain.RedirectHop{
					URL:        req.Response.Request.URL.String(),
					StatusCode: req.Response.StatusCode,
				})
				if req.Response.TLS != nil {
					cp := *req.Response.TLS
					lastTLS = &cp
				}
			}
			if len(via) >= opts.MaxRedirects {
				return errTooManyRedirects
			}
			return nil
		},
	}

	rootURL := fmt.Sprintf("%s://%s/", scheme, hostHeader)
	if opts.RateLimiter != nil {
		if err := opts.RateLimiter(ctx, ip); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rootURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	start := time.Now()
	resp, err := client.Do(req)
	elapsedMs := time.Since(start).Milliseconds()

	if err != nil {
		// If we hit max redirects, http.Client still returns the last response.
		if !errors.Is(err, errTooManyRedirects) || resp == nil {
			if opts.OnThrottle != nil && isNetworkThrottleErr(err) {
				opts.OnThrottle(ip, 0, err)
			}
			return nil, err
		}
	}
	defer resp.Body.Close()

	if opts.OnThrottle != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
		opts.OnThrottle(ip, resp.StatusCode, nil)
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	bodyStr := string(bodyBytes)

	if resp.TLS != nil {
		cp := *resp.TLS
		lastTLS = &cp
	}

	finalURL := rootURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	finalScheme := scheme
	if u, err := url.Parse(finalURL); err == nil && u.Scheme != "" {
		finalScheme = u.Scheme
	}

	headersMap := flattenHeaders(resp.Header)
	title := extractTitle(bodyStr)
	metaGen := extractMetaGenerator(bodyStr)
	footerVer := extractFooterVersion(bodyStr)

	fp := &domain.HTTPFingerprint{
		URL:                finalURL,
		Scheme:             finalScheme,
		StatusCode:         resp.StatusCode,
		Title:              title,
		ServerHeader:       strings.TrimSpace(resp.Header.Get("Server")),
		Headers:            headersMap,
		MissingSecHeaders:  detectMissingSecurityHeaders(resp.Header),
		InterestingHeaders: detectInterestingHeaders(resp.Header),
		Cookies:            parseCookies(resp.Header),
		RedirectChain:      redirectChain,
		TLS:                ExtractTLSInfo(lastTLS, opts.Now()),
		MetaGenerator:      metaGen,
		FooterVersion:      footerVer,
		BodySnippet:        cleanBodySnippet(bodyStr),
		LoginForm:          hasPasswordField(bodyStr),
		ResponseTimeMs:     elapsedMs,
	}

	// JARM TLS server fingerprint (jarm.go); rate-limited, bounded budget.
	f.attachJARM(ctx, fp, scheme, ip, port, serverName, opts)

	// Fetch favicon via safe GET.
	f.fetchFavicon(ctx, client, finalURL, bodyStr, ip, opts, fp)

	// Probe safe read-only paths if enabled.
	if opts.ProbeSafePaths && len(opts.SafePaths) > 0 {
		po := opts
		po.SafePaths = append(append([]string(nil), opts.SafePaths...), followupPaths(fp, opts.SafePaths)...)
		fp.SafePathHits, fp.CatchAll = f.probeSafePaths(ctx, client, rootURL, ip, po)
	}

	return fp, nil
}

func (f *Fingerprinter) fetchFavicon(ctx context.Context, client *http.Client, baseURL, body, ip string, opts Options, fp *domain.HTTPFingerprint) {
	candidates := extractFaviconURLs(baseURL, body)
	if len(candidates) == 0 {
		candidates = []string{resolveRelativeURL(baseURL, "/favicon.ico")}
	} else {
		fallback := resolveRelativeURL(baseURL, "/favicon.ico")
		found := false
		for _, c := range candidates {
			if c == fallback {
				found = true
				break
			}
		}
		if !found {
			candidates = append(candidates, fallback)
		}
	}

	for _, favURL := range candidates {
		if favURL == "" {
			continue
		}
		if opts.RateLimiter != nil {
			if err := opts.RateLimiter(ctx, ip); err != nil {
				return
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, favURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", opts.UserAgent)
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK || len(data) == 0 {
			continue
		}
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(ct, "text/html") && !looksLikeIcon(data) {
			continue
		}
		fp.FaviconMMH3 = FaviconMMH3(data)
		fp.FaviconSHA256 = FaviconSHA256(data)
		return
	}
}

func looksLikeIcon(data []byte) bool {
	if len(data) >= 4 {
		// ICO, PNG, GIF, JPEG, SVG
		if (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00) ||
			(data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') ||
			(data[0] == 'G' && data[1] == 'I' && data[2] == 'F') ||
			(data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
			return true
		}
	}
	trimmed := strings.TrimSpace(strings.ToLower(string(data[:minInt(len(data), 128)])))
	return strings.Contains(trimmed, "<svg")
}

// pathResponse is the comparable shape of one safe-path response.
type pathResponse struct {
	status   int
	location string // redirect target with the probed path removed
	bodyKey  string // normalized body (probed path removed, whitespace collapsed)
	title    string
}

// softNotFound reports whether r looks like the server's answer to a path that doesn't exist.
func softNotFound(r, baseline pathResponse) bool {
	if baseline.status == 0 || !isInterestingPathStatus(baseline.status) || r.status != baseline.status {
		return false
	}
	if r.location != "" || baseline.location != "" {
		return r.location == baseline.location
	}
	if r.bodyKey == baseline.bodyKey {
		return true
	}
	// Templated error pages / SPAs that echo something request-specific: same title and a
	// body length within 10% of the baseline.
	if r.title == baseline.title {
		a, b := len(r.bodyKey), len(baseline.bodyKey)
		if a == 0 && b == 0 {
			return true
		}
		diff := a - b
		if diff < 0 {
			diff = -diff
		}
		max := a
		if b > max {
			max = b
		}
		return max > 0 && float64(diff)/float64(max) <= 0.10
	}
	return false
}

var wsRe = regexp.MustCompile(`\s+`)

func normalizePathResponse(status int, location, body, probedPath string) pathResponse {
	strip := func(s string) string {
		if probedPath != "" && probedPath != "/" {
			s = strings.ReplaceAll(s, probedPath, "")
			s = strings.ReplaceAll(s, url.PathEscape(strings.TrimPrefix(probedPath, "/")), "")
		}
		return s
	}
	return pathResponse{
		status:   status,
		location: strip(location),
		bodyKey:  strings.TrimSpace(wsRe.ReplaceAllString(strip(body), " ")),
		title:    extractTitle(body),
	}
}

func (f *Fingerprinter) probeSafePaths(ctx context.Context, client *http.Client, rootURL, ip string, opts Options) ([]domain.SafePathHit, bool) {
	// Do not follow redirects automatically for safe path checks so we observe 301/302/401/403/200 cleanly.
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	fetch := func(p string) (pathResponse, string, http.Header, bool) {
		if opts.RateLimiter != nil {
			if err := opts.RateLimiter(ctx, ip); err != nil {
				return pathResponse{}, "", nil, false
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, resolveRelativeURL(rootURL, p), nil)
		if err != nil {
			return pathResponse{}, "", nil, false
		}
		req.Header.Set("User-Agent", opts.UserAgent)
		resp, err := noRedirectClient.Do(req)
		if err != nil || resp == nil {
			if opts.OnThrottle != nil && isNetworkThrottleErr(err) {
				opts.OnThrottle(ip, 0, err)
			}
			return pathResponse{}, "", nil, false
		}
		if opts.OnThrottle != nil && resp.StatusCode == http.StatusTooManyRequests {
			opts.OnThrottle(ip, resp.StatusCode, nil)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		bodyStr := string(body)
		return normalizePathResponse(resp.StatusCode, resp.Header.Get("Location"), bodyStr, p), bodyStr, resp.Header, true
	}

	// Soft-404 baseline: one random path that certainly doesn't exist.
	var baseline pathResponse
	catchAll := false
	if len(opts.SafePaths) > 0 && ctx.Err() == nil {
		if b, _, _, ok := fetch(fmt.Sprintf("/dzieciol-%x-notfound", time.Now().UnixNano())); ok {
			baseline = b
			catchAll = isInterestingPathStatus(b.status)
		}
	}

	var hits []domain.SafePathHit
	for _, p := range opts.SafePaths {
		if ctx.Err() != nil {
			break
		}
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			continue
		}
		r, bodyStr, hdr, ok := fetch(p)
		if !ok {
			if opts.RateLimiter != nil && ctx.Err() != nil {
				break
			}
			continue
		}
		// Record meaningful non-404 responses (200, 301, 302, 307, 401, 403) that differ from
		// what the server returns for a non-existent path.
		if !isInterestingPathStatus(r.status) || softNotFound(r, baseline) {
			continue
		}
		snippet := cleanSnippetLen(bodyStr, 300)
		if loc := hdr.Get("Location"); loc != "" && snippet == "" {
			snippet = "Location: " + loc
		}
		hit := domain.SafePathHit{
			Path:       p,
			StatusCode: r.status,
			Title:      r.title,
			Snippet:    snippet,
			LoginForm:  hasPasswordField(bodyStr),
		}
		if r.status == 401 {
			hit.AuthChallenge = truncateHeader(hdr.Get("WWW-Authenticate"), 200)
		}
		hits = append(hits, hit)
	}
	return hits, catchAll
}

func isInterestingPathStatus(code int) bool {
	switch code {
	case http.StatusOK,
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusUnauthorized,
		http.StatusForbidden:
		return true
	default:
		return false
	}
}

func isNetworkThrottleErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "timeout")
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		if len(vals) == 0 {
			continue
		}
		out[k] = strings.Join(vals, "; ")
	}
	return out
}

var requiredSecurityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
}

func detectMissingSecurityHeaders(h http.Header) []string {
	var missing []string
	for _, name := range requiredSecurityHeaders {
		if strings.TrimSpace(h.Get(name)) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

var interestingHeaderExact = map[string]bool{
	"server":                true,
	"x-powered-by":          true,
	"x-aspnet-version":      true,
	"x-aspnetmvc-version":   true,
	"x-generator":           true,
	"x-drupal-cache":        true,
	"x-jenkins":             true,
	"x-runtime":             true,
	"x-version":             true,
	"x-application-context": true,
	"www-authenticate":      true,
	"via":                   true,
	"x-varnish":             true,
	"x-backend-server":      true,
	"x-server":              true,
	"x-forwarded-server":    true,
}

var interestingHeaderPrefixes = []string{
	"x-debug",
	"x-grafana",
	"x-gitlab",
	"x-jenkins",
	"x-drupal",
	"x-powered",
}

func detectInterestingHeaders(h http.Header) []string {
	var keys []string
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var interesting []string
	for _, k := range keys {
		kl := strings.ToLower(k)
		matched := interestingHeaderExact[kl]
		if !matched {
			for _, pfx := range interestingHeaderPrefixes {
				if strings.HasPrefix(kl, pfx) {
					matched = true
					break
				}
			}
		}
		if matched {
			val := strings.TrimSpace(strings.Join(h.Values(k), "; "))
			if val != "" {
				interesting = append(interesting, fmt.Sprintf("%s: %s", k, val))
			}
		}
	}
	return interesting
}

func parseCookies(h http.Header) []domain.CookieInfo {
	rawCookies := h.Values("Set-Cookie")
	if len(rawCookies) == 0 {
		return nil
	}
	resp := &http.Response{Header: http.Header{"Set-Cookie": rawCookies}}
	parsed := resp.Cookies()
	out := make([]domain.CookieInfo, 0, len(parsed))
	for _, c := range parsed {
		ci := domain.CookieInfo{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			HttpOnly: c.HttpOnly,
			Secure:   c.Secure,
			SameSite: sameSiteString(c.SameSite),
		}
		if !ci.HttpOnly {
			ci.Flags = append(ci.Flags, "missing_httponly")
		}
		if !ci.Secure {
			ci.Flags = append(ci.Flags, "missing_secure")
		}
		if ci.SameSite == "" || ci.SameSite == "None" {
			ci.Flags = append(ci.Flags, "weak_samesite")
		}
		out = append(out, ci)
	}
	return out
}

func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

var (
	reTitle        = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reMetaTag      = regexp.MustCompile(`(?is)<meta\s+[^>]*>`)
	reAttrName     = regexp.MustCompile(`(?is)\bname\s*=\s*["']?generator["']?`)
	reAttrContent  = regexp.MustCompile(`(?is)\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	reLinkTag      = regexp.MustCompile(`(?is)<link\s+[^>]*>`)
	reLinkIconRel  = regexp.MustCompile(`(?is)\brel\s*=\s*["'][^"']*icon[^"']*["']`)
	reLinkHref     = regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	reFooterBlock  = regexp.MustCompile(`(?is)<footer[^>]*>(.*?)</footer>`)
	reTagStrip     = regexp.MustCompile(`(?is)<[^>]+>`)
	reSpaces       = regexp.MustCompile(`\s+`)
	reFooterVerPat = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:WordPress|Drupal|Joomla!?|Moodle|MediaWiki|Ghost|TYPO3|Grafana|GitLab|Jenkins|phpMyAdmin|Roundcube|Zabbix|Keycloak|Portainer|Prometheus|Kibana|Apache|nginx|Tomcat|OpenSSH)\s*(?:Community Edition|Enterprise Edition|Webmail|v|/)?\s*v?(\d+\.\d+(?:\.\d+)*(?:-[a-zA-Z0-9._-]+)?)`),
		regexp.MustCompile(`(?i)(?:powered by|version|ver\.?)\s*[:\-]?\s*([a-zA-Z0-9 ._-]{0,30}\bv?\d+\.\d+(?:\.\d+)*)`),
	}
)

func extractTitle(body string) string {
	m := reTitle.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := html.UnescapeString(reTagStrip.ReplaceAllString(m[1], " "))
	t = strings.TrimSpace(reSpaces.ReplaceAllString(t, " "))
	if len(t) > 256 {
		t = t[:256]
	}
	return t
}

func extractMetaGenerator(body string) string {
	tags := reMetaTag.FindAllString(body, 64)
	for _, tag := range tags {
		if !reAttrName.MatchString(tag) {
			continue
		}
		m := reAttrContent.FindStringSubmatch(tag)
		if len(m) >= 4 {
			val := firstNonEmpty(m[1], m[2], m[3])
			return strings.TrimSpace(html.UnescapeString(val))
		}
	}
	return ""
}

func extractFaviconURLs(baseURL, body string) []string {
	tags := reLinkTag.FindAllString(body, 64)
	var urls []string
	seen := make(map[string]struct{})
	for _, tag := range tags {
		if !reLinkIconRel.MatchString(tag) {
			continue
		}
		m := reLinkHref.FindStringSubmatch(tag)
		if len(m) >= 4 {
			href := strings.TrimSpace(html.UnescapeString(firstNonEmpty(m[1], m[2], m[3])))
			if href == "" || strings.HasPrefix(strings.ToLower(href), "data:") {
				continue
			}
			resolved := resolveRelativeURL(baseURL, href)
			if resolved != "" {
				if _, ok := seen[resolved]; !ok {
					seen[resolved] = struct{}{}
					urls = append(urls, resolved)
				}
			}
		}
	}
	return urls
}

func extractFooterVersion(body string) string {
	// First check inside <footer> tags.
	if m := reFooterBlock.FindStringSubmatch(body); len(m) >= 2 {
		footerText := strings.TrimSpace(reSpaces.ReplaceAllString(reTagStrip.ReplaceAllString(m[1], " "), " "))
		if v := matchVersionString(footerText); v != "" {
			return v
		}
	}
	// Fallback: check the bottom 4KB of HTML where footers usually live.
	tail := body
	if len(tail) > 4096 {
		tail = tail[len(tail)-4096:]
	}
	plain := strings.TrimSpace(reSpaces.ReplaceAllString(reTagStrip.ReplaceAllString(tail, " "), " "))
	return matchVersionString(plain)
}

func matchVersionString(text string) string {
	for _, re := range reFooterVerPat {
		if m := re.FindStringSubmatch(text); len(m) >= 1 {
			return strings.TrimSpace(m[0])
		}
	}
	return ""
}

func cleanBodySnippet(body string) string {
	return cleanSnippetLen(body, maxBodySnippetBytes)
}

func cleanSnippetLen(body string, maxLen int) string {
	s := strings.TrimSpace(body)
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

func resolveRelativeURL(baseStr, ref string) string {
	base, err := url.Parse(baseStr)
	if err != nil {
		return ""
	}
	rel, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(rel).String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
