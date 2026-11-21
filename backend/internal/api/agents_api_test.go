package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// enrollViaAPI creates a token as admin and enrolls an agent over HTTP.
func enrollViaAPI(t *testing.T, h http.Handler, adminTok, name string) agenthub.EnrollResponse {
	t.Helper()
	rec := doJSON(h, http.MethodPost, "/api/v1/agents/tokens", adminTok, map[string]any{"name": name, "site": "lab", "ttl_hours": 1})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create token: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		Token          string `json:"token"`
		InstallCommand string `json:"install_command"`
		RunCommand     string `json:"run_command"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !strings.HasPrefix(created.Token, "aet_") || !strings.Contains(created.InstallCommand, created.Token) || !strings.Contains(created.RunCommand, "dzieciol agent --server") {
		t.Fatalf("token response: %s", rec.Body)
	}
	rec = doJSON(h, http.MethodPost, "/api/v1/agent/enroll", "", map[string]any{"token": created.Token, "version": "test"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	var resp agenthub.EnrollResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	// The same token cannot enroll twice.
	if rec := doJSON(h, http.MethodPost, "/api/v1/agent/enroll", "", map[string]any{"token": created.Token}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token reuse: %d", rec.Code)
	}
	return resp
}

func TestAgentAuthIsolation(t *testing.T) {
	srv, _, h := setupTestServer(t)
	admin := loginTest(t, h, "admin", "Admin123!")
	enr := enrollViaAPI(t, h, admin, "iso")

	// The agent credential opens no user endpoint (not even read-only ones).
	for _, pattern := range srv.Routes() {
		method, path, _ := strings.Cut(pattern, " ")
		if publicRoutes[pattern] || path == "" || strings.HasPrefix(path, agenthub.PathPrefix) {
			continue
		}
		_ = method
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, routeRequest(pattern, enr.Credential))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("agent credential on %s: got %d, want 401", pattern, rec.Code)
		}
	}
	// A user token (even admin) opens no agent endpoint.
	for _, pattern := range srv.Routes() {
		_, path, _ := strings.Cut(pattern, " ")
		if !strings.HasPrefix(path, agenthub.PathPrefix) || publicRoutes[pattern] {
			continue
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, routeRequest(pattern, admin))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("admin JWT on %s: got %d, want 401", pattern, rec.Code)
		}
	}
	// The agent credential does work on agent endpoints.
	rec := doJSON(h, http.MethodPost, "/api/v1/agent/heartbeat", enr.Credential, map[string]any{"version": "test"})
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body)
	}
	rec = doJSON(h, http.MethodPost, "/api/v1/agent/jobs/next", enr.Credential, map[string]any{})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("empty queue: %d %s", rec.Code, rec.Body)
	}
}

func TestAgentManagementRBAC(t *testing.T) {
	_, _, h := setupTestServer(t)
	admin := loginTest(t, h, "admin", "Admin123!")
	enr := enrollViaAPI(t, h, admin, "rbac")
	viewer := loginTest(t, h, "viewer", "Viewer123!")
	operator := loginTest(t, h, "operator", "Operator123!")

	rec := doJSON(h, http.MethodGet, "/api/v1/agents", viewer, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), enr.AgentID) || strings.Contains(rec.Body.String(), "credential_hash") {
		t.Fatalf("viewer list agents: %d %s", rec.Code, rec.Body)
	}
	for _, tok := range []string{viewer, operator} {
		for _, req := range []struct{ m, p string }{
			{http.MethodPost, "/api/v1/agents/tokens"},
			{http.MethodGet, "/api/v1/agents/tokens"},
			{http.MethodPut, "/api/v1/agents/" + enr.AgentID},
			{http.MethodDelete, "/api/v1/agents/" + enr.AgentID},
		} {
			if rec := doJSON(h, req.m, req.p, tok, map[string]any{}); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s by non-admin: %d", req.m, req.p, rec.Code)
			}
		}
	}
	rec = doJSON(h, http.MethodGet, "/api/v1/agents/tokens", admin, nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "token_hash") || !strings.Contains(rec.Body.String(), `"used_at"`) {
		t.Fatalf("admin list tokens: %d %s", rec.Code, rec.Body)
	}
	// Disable -> the agent is locked out; enable -> back.
	if rec := doJSON(h, http.MethodPut, "/api/v1/agents/"+enr.AgentID, admin, map[string]any{"disabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d", rec.Code)
	}
	if rec := doJSON(h, http.MethodPost, "/api/v1/agent/heartbeat", enr.Credential, map[string]any{}); rec.Code != http.StatusForbidden {
		t.Fatalf("disabled agent heartbeat: %d", rec.Code)
	}
	if rec := doJSON(h, http.MethodDelete, "/api/v1/agents/"+enr.AgentID, admin, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := doJSON(h, http.MethodPost, "/api/v1/agent/heartbeat", enr.Credential, map[string]any{}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("deleted agent heartbeat: %d", rec.Code)
	}
}

// A profile bound to an agent is queued for it (never run locally) by run-now, and pause /
// resume / stop on that run go to the agent coordinator.
func TestAgentProfileRunNowQueuesForAgent(t *testing.T) {
	_, store, h := setupTestServer(t)
	admin := loginTest(t, h, "admin", "Admin123!")
	enr := enrollViaAPI(t, h, admin, "q")

	rec := doJSON(h, http.MethodPost, "/api/v1/profiles", admin, map[string]any{"name": "bad", "targets": []string{"10.0.0.1"}, "allowed_ports": "80", "agent_id": "nope"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown agent accepted: %d", rec.Code)
	}
	rec = doJSON(h, http.MethodPost, "/api/v1/profiles", admin, map[string]any{"name": "remote", "targets": []string{"10.0.0.1"}, "allowed_ports": "80", "agent_id": enr.AgentID})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", rec.Code, rec.Body)
	}
	var p domain.ScanProfile
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if p.AgentID != enr.AgentID {
		t.Fatalf("agent_id not stored: %+v", p)
	}
	rec = doJSON(h, http.MethodPost, "/api/v1/profiles/"+p.ID+"/run", admin, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("run now: %d %s", rec.Code, rec.Body)
	}
	var run domain.ScanRun
	_ = json.Unmarshal(rec.Body.Bytes(), &run)

	// The agent receives it (long-poll returns at once).
	var spec agenthub.JobSpec
	for i := 0; i < 50 && spec.RunID == ""; i++ {
		rec = doJSON(h, http.MethodPost, "/api/v1/agent/jobs/next?wait=1", enr.Credential, map[string]any{})
		if rec.Code == http.StatusOK {
			_ = json.Unmarshal(rec.Body.Bytes(), &spec)
		}
	}
	if spec.RunID != run.ID || spec.Profile.AllowedPorts != "80" {
		t.Fatalf("agent job: %+v", spec)
	}
	got, _ := store.GetScanRun(t.Context(), run.ID)
	if got.Status != domain.ScanStatusQueued || !strings.Contains(got.Notes, "agent") {
		t.Fatalf("run should wait for the agent's ledger: %s %q", got.Status, got.Notes)
	}
	// Second run-now while active -> 409 (no concurrent run per profile).
	if rec := doJSON(h, http.MethodPost, "/api/v1/profiles/"+p.ID+"/run", admin, nil); rec.Code != http.StatusConflict {
		t.Fatalf("concurrent run: %d", rec.Code)
	}
	if rec := doJSON(h, http.MethodPost, "/api/v1/scans/"+run.ID+"/pause", admin, nil); rec.Code != http.StatusOK {
		t.Fatalf("pause: %d %s", rec.Code, rec.Body)
	}
	rec = doJSON(h, http.MethodPost, "/api/v1/agent/heartbeat", enr.Credential, map[string]any{"current_run_id": run.ID})
	if !strings.Contains(rec.Body.String(), `"pause"`) {
		t.Fatalf("pause not delivered to the agent: %s", rec.Body)
	}
	if rec := doJSON(h, http.MethodPost, "/api/v1/scans/"+run.ID+"/stop", admin, nil); rec.Code != http.StatusOK {
		t.Fatalf("stop: %d %s", rec.Code, rec.Body)
	}
	got, _ = store.GetScanRun(t.Context(), run.ID)
	if got.Status != domain.ScanStatusStopped {
		t.Fatalf("status after stop: %s", got.Status)
	}
}
