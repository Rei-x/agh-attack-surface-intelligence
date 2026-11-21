package api

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// routeRequest turns a mux pattern like "PATCH /api/v1/hosts/{id}/overrides" into a request.
func routeRequest(pattern, token string) *http.Request {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		method, path = http.MethodGet, pattern
	}
	path = strings.NewReplacer("{id}", "00000000-0000-0000-0000-000000000000").Replace(path)
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestEveryRouteRequiresAuth(t *testing.T) {
	srv, _, h := setupTestServer(t)
	routes := srv.Routes()
	if len(routes) < 50 {
		t.Fatalf("expected the full route table, got %d routes", len(routes))
	}
	// Forged tokens: alg=none, wrong signature, expired-looking garbage.
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x","exp":9999999999}`)) + "."
	tokens := map[string]string{"no token": "", "alg none": none, "garbage": "a.b.c"}
	for _, pattern := range routes {
		if publicRoutes[pattern] {
			continue
		}
		for name, tok := range tokens {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, routeRequest(pattern, tok))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s with %s: got %d, want 401", pattern, name, rec.Code)
			}
		}
	}
	for p := range publicRoutes {
		found := false
		for _, r := range routes {
			found = found || r == p
		}
		if !found {
			t.Errorf("public allowlist entry %q is not a registered route", p)
		}
	}
}

// The viewer role is read-only: every mutating route must answer 403 (never run the action).
func TestViewerCannotMutateAnything(t *testing.T) {
	srv, _, h := setupTestServer(t)
	tok := loginTest(t, h, "viewer", "Viewer123!")
	for _, pattern := range srv.Routes() {
		method, path, _ := strings.Cut(pattern, " ")
		if publicRoutes[pattern] || method == http.MethodGet || path == "" {
			continue
		}
		switch path { // read-only POSTs (dry runs) the viewer may use
		case "/api/v1/targets/estimate", "/api/v1/signatures/validate", "/api/v1/signatures/test":
			continue
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, routeRequest(pattern, tok))
		if rec.Code != http.StatusForbidden {
			t.Errorf("viewer %s: got %d, want 403", pattern, rec.Code)
		}
	}
}

func TestRoleMatrixAdminOnlyRoutes(t *testing.T) {
	_, _, h := setupTestServer(t)
	adminOnly := []string{
		"GET /api/v1/admin/users", "GET /api/v1/admin/roles", "GET /api/v1/admin/audit",
		"GET /api/v1/admin/crypto/status", "PUT /api/v1/integrations/defectdojo", "GET /api/v1/integrations/webhook",
	}
	for _, u := range []struct{ name, pass string }{{"operator", "Operator123!"}, {"analyst", "Analyst123!"}, {"viewer", "Viewer123!"}} {
		tok := loginTest(t, h, u.name, u.pass)
		for _, p := range adminOnly {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, routeRequest(p, tok))
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s: got %d, want 403", u.name, p, rec.Code)
			}
		}
	}
	// Analyst may edit but not delete or run scans / import.
	tok := loginTest(t, h, "analyst", "Analyst123!")
	for _, p := range []string{"DELETE /api/v1/hosts/{id}", "POST /api/v1/scans", "POST /api/v1/ingest/import", "DELETE /api/v1/scans/{id}"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, routeRequest(p, tok))
		if rec.Code != http.StatusForbidden {
			t.Errorf("analyst %s: got %d, want 403", p, rec.Code)
		}
	}
}

func TestSecurityHeadersAndNoWildcardCORS(t *testing.T) {
	_, _, h := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("foreign origin must not be allowed, got ACAO=%q", got)
	}
	for _, hdr := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("missing security header %s", hdr)
		}
	}
}

func TestCORSAllowsOnlyConfiguredOrigin(t *testing.T) {
	srv, _, _ := setupTestServer(t)
	srv.cfg.AllowedOrigin = "http://localhost:5173"
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/hosts", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Fatalf("configured origin preflight: %d %v", rec.Code, rec.Header())
	}
}

func TestOversizedBodyRejectedWith413(t *testing.T) {
	_, _, h := setupTestServer(t)
	tok := loginTest(t, h, "admin", "Admin123!")
	big := bytes.Repeat([]byte("a"), int(maxJSONBodyBytes)+10)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/targets", bytes.NewReader(big))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413", rec.Code)
	}
}

func TestLoginLockoutAfterRepeatedFailures(t *testing.T) {
	srv, _, h := setupTestServer(t)
	for i := 0; i < loginMaxFailures; i++ {
		rec := doJSON(h, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "wrong"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d", i, rec.Code)
		}
	}
	// Locked now, even with the right password.
	rec := doJSON(h, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "Admin123!"})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After, got %d %s", rec.Code, rec.Body.String())
	}
	// Other users are not locked by admin's failures (below the per-IP limit).
	if rec := doJSON(h, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "viewer", "password": "Viewer123!"}); rec.Code != http.StatusOK {
		t.Fatalf("viewer login should still work: %d", rec.Code)
	}
	// Lockout expires.
	srv.logins.now = func() time.Time { return time.Now().Add(loginWindow + time.Second) }
	if rec := doJSON(h, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "Admin123!"}); rec.Code != http.StatusOK {
		t.Fatalf("lockout should expire: %d", rec.Code)
	}
}

func TestQueryTokenOnlyAcceptedForSSE(t *testing.T) {
	_, _, h := setupTestServer(t)
	tok := loginTest(t, h, "admin", "Admin123!")
	rec := doJSON(h, http.MethodGet, "/api/v1/hosts?token="+tok, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("?token= on a normal endpoint must be rejected, got %d", rec.Code)
	}
}
