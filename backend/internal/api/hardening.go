package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Request body limits. Uploads (scan imports, signature packs) get a larger budget; every other
// endpoint takes small JSON documents.
const (
	maxJSONBodyBytes   int64 = 8 << 20  // 8 MiB: a profile may list ~100k individual IPs
	maxImportFileBytes int64 = 64 << 20 // 64 MiB of CSV / JSON / nmap XML
	maxUploadBodyBytes       = maxImportFileBytes + 1<<20
)

// publicRoutes are the only API patterns reachable without a bearer token
// (enforced by TestEveryRouteRequiresAuth).
var publicRoutes = map[string]bool{
	"GET /api/v1/health":             true,
	"GET /api/v1/auth/demo-accounts": true,
	"POST /api/v1/auth/login":        true,
	"POST /api/v1/agent/enroll":      true, // authenticated by the one-time enrollment token
	"/":                              true, // SPA static files
	"GET /install.sh":                true, // agent installer, fetched by curl on a fresh machine
	"GET /download/{file}":           true, // the public dzieciol binaries and checksums.txt
}

// handle registers a route and remembers its pattern so tests can walk every route.
func (s *Server) handle(pattern string, h http.HandlerFunc) {
	s.routes = append(s.routes, pattern)
	s.mux.HandleFunc(pattern, h)
}

// Routes returns every registered mux pattern (e.g. "GET /api/v1/hosts/{id}").
func (s *Server) Routes() []string { return append([]string(nil), s.routes...) }

func bodyLimitFor(r *http.Request) int64 {
	switch r.URL.Path {
	case "/api/v1/ingest/import", "/api/v1/signatures/import":
		return maxUploadBodyBytes
	}
	// Agent result uploads carry chunk observations and a segment's merged nmap XML.
	if strings.HasPrefix(r.URL.Path, "/api/v1/agent/jobs/") {
		return maxUploadBodyBytes
	}
	return maxJSONBodyBytes
}

// hardeningMiddleware applies security headers, CORS policy and request body limits.
func (s *Server) hardeningMiddleware(next http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, o := range strings.Split(s.cfg.AllowedOrigin, ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			allowed[o] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		csp := "default-src 'self'; script-src 'self'; " +
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
			"font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob:; " +
			"connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
		if strings.HasPrefix(r.URL.Path, "/deck/") {
			// The pitch deck embeds the launch film; nothing else may load frames.
			csp += "; frame-src https://www.youtube-nocookie.com"
		}
		h.Set("Content-Security-Policy", csp)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}

		// CORS: the bundled UI is same-origin and needs none. Cross-origin access is granted only
		// to origins listed in DZIECIOL_CORS_ORIGINS (never "*"; auth is a bearer token, no cookies).
		if origin := strings.TrimRight(r.Header.Get("Origin"), "/"); origin != "" && allowed[origin] {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Vary", "Origin")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
			h.Set("Access-Control-Max-Age", "600")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		if r.Body != nil && r.Body != http.NoBody {
			limit := bodyLimitFor(r)
			if r.ContentLength > limit {
				writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
					"request body too large (limit %d MB)", limit>>20))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// isBodyTooLarge reports whether err came from http.MaxBytesReader.
func isBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// loginLimiter blocks brute force: after loginMaxFailures failed logins for the same
// username (loginMaxIPFailures from the same client address) within loginWindow, further attempts get
// 429 until the window has passed. A successful login clears the username's counter.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	now      func() time.Time
}

const (
	loginMaxFailures   = 10 // per username
	loginMaxIPFailures = 30 // per client address (a lab behind one NAT shares it)
	loginWindow        = 5 * time.Minute
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: map[string][]time.Time{}, now: time.Now}
}

func loginKeys(r *http.Request, username string) []string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return []string{"ip:" + host, "user:" + strings.ToLower(strings.TrimSpace(username))}
}

func (l *loginLimiter) prune(key string, now time.Time) []time.Time {
	kept := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if now.Sub(t) < loginWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = kept
	return kept
}

// blocked returns the remaining lockout duration (0 if the attempt may proceed).
func (l *loginLimiter) blocked(keys []string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var wait time.Duration
	for _, k := range keys {
		f := l.prune(k, now)
		limit := loginMaxFailures
		if strings.HasPrefix(k, "ip:") {
			limit = loginMaxIPFailures
		}
		if len(f) >= limit {
			if d := loginWindow - now.Sub(f[0]); d > wait {
				wait = d
			}
		}
	}
	return wait
}

func (l *loginLimiter) fail(keys []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, k := range keys {
		l.failures[k] = append(l.prune(k, now), now)
	}
	// Bound memory under a spray of random usernames.
	if len(l.failures) > 10000 {
		for k := range l.failures {
			l.prune(k, now)
		}
	}
}

func (l *loginLimiter) succeed(keys []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		if strings.HasPrefix(k, "user:") {
			delete(l.failures, k)
		}
	}
}

func writeTooManyLogins(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, fmt.Sprintf(
		"too many failed logins - retry in %d s", secs))
}
