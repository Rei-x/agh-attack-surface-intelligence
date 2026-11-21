package fingerprint

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMurmurHash3AndShodanFavicon(t *testing.T) {
	// Standard MurmurHash3_32 test vector: MurmurHash3_32("hello", 0) == 613153351
	if got := MurmurHash3_32([]byte("hello"), 0); got != 613153351 {
		t.Fatalf("MurmurHash3_32(\"hello\", 0) = %d, want 613153351", got)
	}
	if got := MurmurHash3_32([]byte(""), 0); got != 0 {
		t.Fatalf("MurmurHash3_32(\"\", 0) = %d, want 0", got)
	}

	// Verify ShodanBase64 wraps at 76 chars with trailing newline.
	raw := bytes.Repeat([]byte("Dzieciol-Favicon-Test-"), 5)
	b64 := ShodanBase64(raw)
	if !bytes.HasSuffix(b64, []byte("\n")) {
		t.Fatalf("ShodanBase64 missing trailing newline")
	}
	lines := bytes.Split(bytes.TrimSuffix(b64, []byte("\n")), []byte("\n"))
	if len(lines) < 2 || len(lines[0]) != 76 {
		t.Fatalf("ShodanBase64 expected 76-char line wrapping, got lines=%d firstLen=%d", len(lines), len(lines[0]))
	}

	// Deterministic Shodan favicon MMH3 & SHA256.
	ico := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00, 0x01, 0x00}
	mmh3Hash := FaviconMMH3(ico)
	sha := FaviconSHA256(ico)
	if mmh3Hash == "" || len(sha) != 64 {
		t.Fatalf("invalid favicon hashes: mmh3=%q sha=%q", mmh3Hash, sha)
	}
	// Verify mmh3 matches direct computation over ShodanBase64(ico).
	wantMMH3 := strconv.FormatInt(int64(MurmurHash3_32(ShodanBase64(ico), 0)), 10)
	if mmh3Hash != wantMMH3 {
		t.Fatalf("FaviconMMH3 = %s, want %s", mmh3Hash, wantMMH3)
	}
}

func TestHTTPProbeExtractsFullEvidenceAndEnforcesReadOnly(t *testing.T) {
	var mu sync.Mutex
	var seenMethods []string
	var seenUA string

	icoBytes := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x02, 0x00, 0x01, 0x00}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenMethods = append(seenMethods, r.Method)
		seenUA = r.Header.Get("User-Agent")
		mu.Unlock()

		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/portal", http.StatusFound)
		case "/portal":
			w.Header().Set("Server", "nginx/1.24.0")
			w.Header().Set("X-Powered-By", "PHP/8.2.10")
			w.Header().Set("X-Debug-Mode", "enabled")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			http.SetCookie(w, &http.Cookie{
				Name:     "PHPSESSID",
				Value:    "abc123",
				Path:     "/",
				HttpOnly: false,
				Secure:   false,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "__Host-secure",
				Value:    "xyz",
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html>
<html>
<head>
  <title>AGH Staging Portal &amp; Dashboard</title>
  <meta name="generator" content="WordPress 6.4.2">
  <link rel="shortcut icon" href="/assets/favicon.ico">
</head>
<body>
  <h1>Welcome</h1>
  <footer>Powered by WordPress 6.4.2 | CBI AGH</footer>
</body>
</html>`))
		case "/assets/favicon.ico":
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(icoBytes)
		case "/admin":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`<title>Admin Login Required</title>`))
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	opts := DefaultOptions()
	opts.Scheme = "http"
	opts.UserAgent = "Dzieciol-Test/1.0"
	opts.SafePaths = []string{"/admin", "/robots.txt", "/nonexistent"}

	fp, err := Probe(context.Background(), host, port, "", &opts)
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}

	if fp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", fp.StatusCode)
	}
	if fp.Title != "AGH Staging Portal & Dashboard" {
		t.Fatalf("Title = %q, want %q", fp.Title, "AGH Staging Portal & Dashboard")
	}
	if fp.ServerHeader != "nginx/1.24.0" {
		t.Fatalf("ServerHeader = %q, want nginx/1.24.0", fp.ServerHeader)
	}
	if fp.MetaGenerator != "WordPress 6.4.2" {
		t.Fatalf("MetaGenerator = %q, want WordPress 6.4.2", fp.MetaGenerator)
	}
	if !strings.Contains(fp.FooterVersion, "6.4.2") {
		t.Fatalf("FooterVersion = %q, expected 6.4.2", fp.FooterVersion)
	}
	if len(fp.RedirectChain) != 1 || fp.RedirectChain[0].StatusCode != http.StatusFound {
		t.Fatalf("RedirectChain = %+v, want 1 hop with 302", fp.RedirectChain)
	}
	// Missing security headers should contain HSTS, CSP, X-Frame-Options (not X-Content-Type-Options).
	if len(fp.MissingSecHeaders) != 3 {
		t.Fatalf("MissingSecHeaders = %v, want 3 entries", fp.MissingSecHeaders)
	}
	// Interesting headers should include Server, X-Powered-By, X-Debug-Mode.
	if len(fp.InterestingHeaders) < 3 {
		t.Fatalf("InterestingHeaders = %v, expected >= 3", fp.InterestingHeaders)
	}
	// Cookies parsed with security flags.
	if len(fp.Cookies) != 2 {
		t.Fatalf("Cookies count = %d, want 2", len(fp.Cookies))
	}
	var phpCookieFound bool
	for _, c := range fp.Cookies {
		if c.Name == "PHPSESSID" {
			phpCookieFound = true
			if c.HttpOnly || c.Secure {
				t.Fatalf("PHPSESSID expected HttpOnly=false Secure=false, got %+v", c)
			}
			joined := strings.Join(c.Flags, ",")
			if !strings.Contains(joined, "missing_httponly") || !strings.Contains(joined, "missing_secure") {
				t.Fatalf("PHPSESSID flags = %v, want missing_httponly & missing_secure", c.Flags)
			}
		}
	}
	if !phpCookieFound {
		t.Fatalf("PHPSESSID cookie not found")
	}
	// Favicon hashes.
	if fp.FaviconMMH3 != FaviconMMH3(icoBytes) {
		t.Fatalf("FaviconMMH3 = %q, want %q", fp.FaviconMMH3, FaviconMMH3(icoBytes))
	}
	if fp.FaviconSHA256 != FaviconSHA256(icoBytes) {
		t.Fatalf("FaviconSHA256 = %q, want %q", fp.FaviconSHA256, FaviconSHA256(icoBytes))
	}
	// Safe path hits.
	if len(fp.SafePathHits) != 2 {
		t.Fatalf("SafePathHits = %+v, want 2 (/admin and /robots.txt)", fp.SafePathHits)
	}

	// Verify strictly read-only methods and custom User-Agent.
	mu.Lock()
	defer mu.Unlock()
	if seenUA != "Dzieciol-Test/1.0" {
		t.Fatalf("User-Agent = %q, want Dzieciol-Test/1.0", seenUA)
	}
	for _, m := range seenMethods {
		if m != http.MethodGet && m != http.MethodHead {
			t.Fatalf("unsafe HTTP method sent: %s", m)
		}
	}
}

func TestHTTPSProbeExtractsTLSAndThrottleCallback(t *testing.T) {
	var throttled int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<title>TLS Lab</title>`))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	opts := DefaultOptions()
	opts.Scheme = "https"
	opts.SafePaths = []string{"/admin"}
	opts.Now = func() time.Time { return time.Now().UTC() }
	opts.OnThrottle = func(h string, code int, err error) {
		if code == http.StatusTooManyRequests {
			throttled++
		}
	}

	fp, err := Probe(context.Background(), host, port, "", &opts)
	if err != nil {
		t.Fatalf("HTTPS Probe failed: %v", err)
	}
	if fp.TLS == nil {
		t.Fatalf("expected non-nil TLSInfo")
	}
	if fp.TLS.SHA256 == "" || len(fp.TLS.SHA256) != 64 {
		t.Fatalf("expected valid TLS SHA256, got %q", fp.TLS.SHA256)
	}
	if !strings.HasPrefix(fp.TLS.Version, "TLS 1.") {
		t.Fatalf("unexpected TLS version: %q", fp.TLS.Version)
	}
	if fp.TLS.IsExpired {
		t.Fatalf("httptest cert should not be expired")
	}
	if len(fp.MissingSecHeaders) != 0 {
		t.Fatalf("expected 0 missing security headers, got %v", fp.MissingSecHeaders)
	}
	if throttled != 1 {
		t.Fatalf("expected OnThrottle called once for 429, got %d", throttled)
	}
}

func TestHTTPProbeBodySizeLimitAndMaxRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/loop") {
			http.Redirect(w, r, "/loop?next=1", http.StatusFound)
			return
		}
		// Return 400KB body to verify 256KB cap.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title>Big</title>"))
		_, _ = w.Write(bytes.Repeat([]byte("X"), 400*1024))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	opts := DefaultOptions()
	opts.Scheme = "http"
	opts.ProbeSafePaths = false
	fp, err := Probe(context.Background(), host, port, "", &opts)
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if fp.Title != "Big" {
		t.Fatalf("Title = %q, want Big", fp.Title)
	}
	if len(fp.BodySnippet) > maxBodySnippetBytes {
		t.Fatalf("BodySnippet exceeded cap: %d", len(fp.BodySnippet))
	}

	// Verify redirect loop stops at MaxRedirects = 5.
	loopSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer loopSrv.Close()
	lHost, lPortStr, _ := net.SplitHostPort(loopSrv.Listener.Addr().String())
	lPort, _ := strconv.Atoi(lPortStr)
	fpLoop, err := Probe(context.Background(), lHost, lPort, "", &opts)
	if err != nil {
		t.Fatalf("Redirect loop probe returned unexpected err: %v", err)
	}
	if len(fpLoop.RedirectChain) != 5 {
		t.Fatalf("RedirectChain len = %d, want 5", len(fpLoop.RedirectChain))
	}
}
