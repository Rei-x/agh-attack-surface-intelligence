package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
)

// TestEveryRouteSurvivesGarbageBodies sends malformed / wrongly typed JSON to every route as
// admin: the server must answer without panicking and without a 5xx.
func TestEveryRouteSurvivesGarbageBodies(t *testing.T) {
	srv, store, h := setupTestServer(t)
	tok := loginTest(t, h, "admin", "Admin123!")
	// A real host/scan id so {id} routes reach their body handling.
	if rec := doJSON(h, http.MethodPost, "/api/v1/ingest/manual", tok, map[string]any{"ip": "10.66.0.1", "port": 22}); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}
	hosts, _, _ := store.ListHosts(t.Context(), db.HostFilter{})
	hostID := hosts[0].ID

	long := strings.Repeat("A", 200000)
	bodies := []string{
		``, `{}`, `null`, `[]`, `"x"`, `123`, `{"a":`, "\x00\xff\xfe",
		`{"id":1e400,"name":[1,2],"value":{"x":1},"targets":"10.0.0.1","permissions":"*","active":"yes"}`,
		`{"name":"` + long + `","value":"` + long + `","notes":"` + long + `"}`,
		`{"username":null,"password":null,"role_id":null,"targets":[null,1,{}],"allowed_ports":5}`,
		`{"schedule_cron":"` + long + `","window_start":"99:99","timezone":"../../etc/passwd"}`,
		`{"matchers":[{"type":"body","pattern":"(a+)+$","regex":true}],"name":"x"}`,
		`{"url":"file:///etc/passwd","api_token":"x","product_id":-1}`,
	}
	for _, pattern := range srv.Routes() {
		if pattern == "/" || strings.HasSuffix(pattern, "/events/stream") { // SPA files; SSE never ends
			continue
		}
		method, path, _ := strings.Cut(pattern, " ")
		path = strings.ReplaceAll(path, "{id}", hostID)
		for _, b := range bodies {
			req := httptest.NewRequest(method, path+"?limit=-5&page=99999999999&format=%00", bytes.NewReader([]byte(b)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("PANIC %s body=%.40q: %v", pattern, b, p)
					}
				}()
				h.ServeHTTP(rec, req)
			}()
			if rec.Code >= 500 {
				t.Errorf("%s body=%.60q -> %d %.200s", pattern, b, rec.Code, rec.Body.String())
			}
		}
	}
}
