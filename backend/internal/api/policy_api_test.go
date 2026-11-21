package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

func TestPolicyAPIZonesViolationsQueryAndBadge(t *testing.T) {
	srv, _, h := setupTestServer(t)
	ctx := context.Background()
	analystTok := loginTest(t, h, "analyst", "Analyst123!")
	viewerTok := loginTest(t, h, "viewer", "Viewer123!")

	obs := []domain.ObservedHost{{IP: "10.66.0.20", IsAlive: true, Services: []domain.ObservedService{
		{Port: 443, ServiceName: "https"}, {Port: 23, ServiceName: "telnet"},
	}}}
	if _, err := srv.pipeline.ProcessObservations(ctx, ingest.IngestRequest{ScanName: "s1", Observations: obs}); err != nil {
		t.Fatal(err)
	}

	zones := map[string]any{"zones": []map[string]any{{
		"name": "Server zone", "cidrs": []string{"10.66.0.0/24"}, "enabled": true, "preset": "server_web_only",
		"rules": map[string]any{"allowed_ports": []int{22, 80, 443}, "forbidden": []string{"cleartext_admin"}},
	}}}
	if r := doJSON(h, http.MethodPut, "/api/v1/policies", viewerTok, zones); r.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT policies expected 403, got %d", r.Code)
	}
	bad := map[string]any{"zones": []map[string]any{{"name": "x", "cidrs": []string{"nope"}}}}
	if r := doJSON(h, http.MethodPut, "/api/v1/policies", analystTok, bad); r.Code != http.StatusBadRequest {
		t.Fatalf("bad CIDR expected 400, got %d", r.Code)
	}
	r := doJSON(h, http.MethodPut, "/api/v1/policies", analystTok, zones)
	var saved struct {
		Zones     []domain.PolicyZone `json:"zones"`
		Changes   int                 `json:"changes"`
		OpenCount int                 `json:"open_count"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &saved)
	if r.Code != http.StatusOK || len(saved.Zones) != 1 || saved.Zones[0].ID == "" || saved.OpenCount != 1 || saved.Changes != 1 {
		t.Fatalf("PUT policies: %d %s", r.Code, r.Body.String())
	}

	r = doJSON(h, http.MethodGet, "/api/v1/policies", viewerTok, nil)
	var list struct {
		Zones   []domain.PolicyZone `json:"zones"`
		Presets []map[string]any    `json:"presets"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &list)
	if r.Code != http.StatusOK || len(list.Zones) != 1 || len(list.Presets) != 4 {
		t.Fatalf("GET policies: %d %s", r.Code, r.Body.String())
	}

	r = doJSON(h, http.MethodGet, "/api/v1/policies/violations", viewerTok, nil)
	var vs struct {
		Violations []domain.PolicyViolation `json:"violations"`
		ByZone     []violationGroup         `json:"by_zone"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &vs)
	if r.Code != http.StatusOK || len(vs.Violations) != 1 || vs.Violations[0].Port != 23 || len(vs.ByZone) != 1 || vs.ByZone[0].Open != 1 {
		t.Fatalf("violations: %d %s", r.Code, r.Body.String())
	}

	// Query language and the read-time badge on the host drawer.
	r = doJSON(h, http.MethodGet, "/api/v1/hosts?q="+urlq(`violation:true policy:"server zone"`), viewerTok, nil)
	var page struct {
		Hosts []domain.Host `json:"hosts"`
		Total int           `json:"total"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &page)
	if r.Code != http.StatusOK || page.Total != 1 {
		t.Fatalf("violation query: %d %s", r.Code, r.Body.String())
	}
	r = doJSON(h, http.MethodGet, "/api/v1/hosts/"+page.Hosts[0].ID, viewerTok, nil)
	var detail domain.Host
	_ = json.Unmarshal(r.Body.Bytes(), &detail)
	badges := 0
	for _, s := range detail.Services {
		badges += len(s.PolicyViolations)
	}
	if badges != 1 {
		t.Fatalf("host detail must carry one policy badge: %s", r.Body.String())
	}

	// Telnet closes on the next scan: the violation resolves and the change list shows it.
	obs[0].Services = obs[0].Services[:1]
	if _, err := srv.pipeline.ProcessObservations(ctx, ingest.IngestRequest{ScanName: "s2", Observations: obs}); err != nil {
		t.Fatal(err)
	}
	r = doJSON(h, http.MethodGet, "/api/v1/changes?event_type="+domain.EventPolicyResolved, viewerTok, nil)
	if r.Code != http.StatusOK || !json.Valid(r.Body.Bytes()) || len(r.Body.String()) < 50 {
		t.Fatalf("resolved change: %d %s", r.Code, r.Body.String())
	}
	if srv.policy.OpenCount() != 0 {
		t.Fatalf("violation must resolve when telnet is gone, open=%d", srv.policy.OpenCount())
	}
}
