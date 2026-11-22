package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func dojoStatusLogin(t *testing.T, h http.Handler, tok string) map[string]string {
	t.Helper()
	rec := doJSON(h, http.MethodGet, "/api/v1/integrations/defectdojo/status", tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Login map[string]string `json:"login"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Login
}

// The admin types in a DefectDojo account; every signed-in user reading the header chip
// gets it, only admins can change it, and clearing it removes it from the chip.
func TestDefectDojoLoginShownInChip(t *testing.T) {
	_, _, h := setupTestServer(t)
	adminTok := loginTest(t, h, "admin", "Admin123!")
	viewerTok := loginTest(t, h, "viewer", "Viewer123!")
	const path = "/api/v1/integrations/defectdojo/login"

	if l := dojoStatusLogin(t, h, viewerTok); l != nil {
		t.Fatalf("no login set yet, got %v", l)
	}
	rec := doJSON(h, http.MethodPut, path, adminTok, map[string]string{"username": "  jury ", "password": "Kx7m-Pq3w-Zr8t-Hn4v"})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	l := dojoStatusLogin(t, h, viewerTok)
	if l["username"] != "jury" || l["password"] != "Kx7m-Pq3w-Zr8t-Hn4v" {
		t.Fatalf("viewer should see the login, got %v", l)
	}

	for _, u := range []struct{ name, pass string }{{"operator", "Operator123!"}, {"analyst", "Analyst123!"}, {"viewer", "Viewer123!"}} {
		tok := loginTest(t, h, u.name, u.pass)
		if rec := doJSON(h, http.MethodPut, path, tok, map[string]string{"username": "x", "password": "y"}); rec.Code != http.StatusForbidden {
			t.Errorf("%s PUT login: got %d, want 403", u.name, rec.Code)
		}
		if rec := doJSON(h, http.MethodDelete, path, tok, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s DELETE login: got %d, want 403", u.name, rec.Code)
		}
	}

	for _, bad := range []map[string]string{
		{"username": "jury", "password": ""},
		{"username": "", "password": "secret"},
		{"username": "jury", "password": "line\nbreak"},
	} {
		if rec := doJSON(h, http.MethodPut, path, adminTok, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %v: got %d, want 400", bad, rec.Code)
		}
	}
	if l := dojoStatusLogin(t, h, viewerTok); l["username"] != "jury" {
		t.Fatalf("rejected saves must keep the login, got %v", l)
	}

	if rec := doJSON(h, http.MethodDelete, path, adminTok, nil); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	if l := dojoStatusLogin(t, h, viewerTok); l != nil {
		t.Fatalf("cleared login still shown: %v", l)
	}

	doJSON(h, http.MethodPut, path, adminTok, map[string]string{"username": "jury", "password": "pw"})
	if rec := doJSON(h, http.MethodPut, path, adminTok, map[string]string{"username": "", "password": ""}); rec.Code != http.StatusOK {
		t.Fatalf("clear by empty PUT: %d %s", rec.Code, rec.Body.String())
	}
	if l := dojoStatusLogin(t, h, viewerTok); l != nil {
		t.Fatalf("empty PUT should clear, got %v", l)
	}
}
