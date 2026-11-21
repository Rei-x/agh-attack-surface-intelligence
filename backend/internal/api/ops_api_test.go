package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

func TestOpsAPITriageTimelineSearchTagRulesWebhook(t *testing.T) {
	srv, store, h := setupTestServer(t)
	ctx := context.Background()
	adminTok := loginTest(t, h, "admin", "Admin123!")
	analystTok := loginTest(t, h, "analyst", "Analyst123!")
	viewerTok := loginTest(t, h, "viewer", "Viewer123!")
	opTok := loginTest(t, h, "operator", "Operator123!")

	// Tag rule before ingest (analyst may manage ownership, viewer may not).
	rules := map[string]any{"rules": []map[string]any{{"cidr": "10.66.0.0/22", "tags": []string{"wydzial-wi"}, "owner": "admin@wi.agh.edu.pl", "enabled": true}}}
	if r := doJSON(h, http.MethodPut, "/api/v1/tag-rules", viewerTok, rules); r.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT tag-rules expected 403, got %d", r.Code)
	}
	if r := doJSON(h, http.MethodPut, "/api/v1/tag-rules", analystTok, map[string]any{"rules": []map[string]any{{"cidr": "nope", "tags": []string{"x"}}}}); r.Code != http.StatusBadRequest {
		t.Fatalf("invalid CIDR expected 400, got %d", r.Code)
	}
	if r := doJSON(h, http.MethodPut, "/api/v1/tag-rules", analystTok, rules); r.Code != http.StatusOK {
		t.Fatalf("PUT tag-rules: %d %s", r.Code, r.Body.String())
	}

	obs := func(ports ...int) []domain.ObservedHost {
		var svcs []domain.ObservedService
		for _, p := range ports {
			svcs = append(svcs, domain.ObservedService{Port: p, ServiceName: map[int]string{80: "http", 3389: "ms-wbt-server", 22: "ssh"}[p]})
		}
		return []domain.ObservedHost{{IP: "10.66.0.15", IsAlive: true, Services: svcs}}
	}
	if _, err := srv.pipeline.ProcessObservations(ctx, ingest.IngestRequest{ScanName: "s1", Observations: obs(80)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := srv.pipeline.ProcessObservations(ctx, ingest.IngestRequest{ScanName: "s2", Observations: obs(80, 3389)}); err != nil {
		t.Fatal(err)
	}

	// Search with the query language (server-side) + 400 on bad syntax.
	r := doJSON(h, http.MethodGet, "/api/v1/hosts?q="+urlq("port:3389 tag:wydzial-wi cidr:10.66.0.0/24"), viewerTok, nil)
	var page struct {
		Hosts []domain.Host `json:"hosts"`
		Total int           `json:"total"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &page)
	if r.Code != http.StatusOK || page.Total != 1 || page.Hosts[0].Owner != "admin@wi.agh.edu.pl" {
		t.Fatalf("query search: %d %s", r.Code, r.Body.String())
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/hosts?q="+urlq("port:99999"), viewerTok, nil); r.Code != http.StatusBadRequest {
		t.Fatalf("bad query expected 400, got %d", r.Code)
	}
	host := page.Hosts[0]
	var rdp domain.Service
	for _, s := range host.Services {
		if s.Port == 3389 {
			rdp = s
		}
	}

	// Timeline answers "when did 3389 first appear?"
	r = doJSON(h, http.MethodGet, "/api/v1/hosts/"+host.ID+"/timeline?port=3389", viewerTok, nil)
	var tl struct {
		Entries []domain.HostTimelineEntry `json:"entries"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &tl)
	if r.Code != http.StatusOK || len(tl.Entries) < 2 {
		t.Fatalf("timeline: %d %s", r.Code, r.Body.String())
	}
	sawNew, sawObs := false, false
	for _, e := range tl.Entries {
		if e.Port != 3389 {
			t.Fatalf("port filter leaked %+v", e)
		}
		if e.Kind == "change" && e.EventType == "NEW_SERVICE" && e.Severity == "high" {
			sawNew = true
		}
		if e.Kind == "observation" && e.Count == 1 {
			sawObs = true
		}
	}
	if !sawNew || !sawObs {
		t.Fatalf("timeline should contain the NEW_SERVICE change and the observation span: %+v", tl.Entries)
	}
	r = doJSON(h, http.MethodGet, "/api/v1/hosts/"+host.ID+"/timeline", viewerTok, nil)
	_ = json.Unmarshal(r.Body.Bytes(), &tl)
	for i := 1; i < len(tl.Entries); i++ {
		if tl.Entries[i].At.After(tl.Entries[i-1].At) {
			t.Fatalf("timeline must be newest first")
		}
	}

	// RDP is the top finding before triage.
	if !dashboardHasFinding(t, h, viewerTok, rdp.ID) {
		t.Fatalf("RDP should be among top findings before acceptance")
	}

	// Triage: reason mandatory, viewer forbidden, author set server-side.
	svcPath := "/api/v1/services/" + rdp.ID + "/overrides"
	if r := doJSON(h, http.MethodPatch, svcPath, viewerTok, map[string]any{"triage": map[string]any{"status": "accepted_risk", "reason": "x"}}); r.Code != http.StatusForbidden {
		t.Fatalf("viewer triage expected 403, got %d", r.Code)
	}
	if r := doJSON(h, http.MethodPatch, svcPath, analystTok, map[string]any{"triage": map[string]any{"status": "accepted_risk"}}); r.Code != http.StatusBadRequest {
		t.Fatalf("missing reason expected 400, got %d", r.Code)
	}
	if r := doJSON(h, http.MethodPatch, svcPath, analystTok, map[string]any{"triage_status": "accepted_risk"}); r.Code != http.StatusBadRequest {
		t.Fatalf("legacy accepted_risk without reason expected 400, got %d", r.Code)
	}
	if r := doJSON(h, http.MethodPatch, svcPath, analystTok, map[string]any{"triage": map[string]any{"status": "accepted_risk", "reason": "x", "expires_at": "2001-01-01"}}); r.Code != http.StatusBadRequest {
		t.Fatalf("past expiry expected 400, got %d", r.Code)
	}
	exp := time.Now().Add(30 * 24 * time.Hour).Format("2006-01-02")
	r = doJSON(h, http.MethodPatch, svcPath, analystTok, map[string]any{"triage": map[string]any{"status": "accepted_risk", "reason": "Jump host, VPN-only (ticket SOC-123)", "expires_at": exp, "by": "forged"}})
	var svc domain.Service
	_ = json.Unmarshal(r.Body.Bytes(), &svc)
	if r.Code != http.StatusOK || svc.TriageStatus != "accepted_risk" || svc.Triage == nil || svc.Triage.By != "analyst" || svc.Triage.ExpiresAt == nil {
		t.Fatalf("accept risk: %d %s", r.Code, r.Body.String())
	}
	if dashboardHasFinding(t, h, viewerTok, rdp.ID) {
		t.Fatalf("accepted finding must be excluded from top findings")
	}

	// Preserved across the next scan.
	if _, err := srv.pipeline.ProcessObservations(ctx, ingest.IngestRequest{ScanName: "s3", Observations: obs(80, 3389)}); err != nil {
		t.Fatal(err)
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/hosts?q="+urlq("triage:accepted_risk"), viewerTok, nil); !strings.Contains(r.Body.String(), rdp.ID) {
		t.Fatalf("acceptance lost after re-scan / triage: search broken: %s", r.Body.String())
	}

	// Expired acceptance (simulated by writing an already-expired decision) shows up again.
	past := time.Now().Add(-time.Hour)
	_ = store.PatchOverrides(ctx, "service", rdp.ID, map[string]any{"triage": domain.TriageInfo{Status: "accepted_risk", Reason: "old", By: "analyst", ExpiresAt: &past}}, nil, "analyst")
	if !dashboardHasFinding(t, h, viewerTok, rdp.ID) {
		t.Fatalf("expired acceptance must return to top findings")
	}
	r = doJSON(h, http.MethodGet, "/api/v1/dashboard/summary", viewerTok, nil)
	if !strings.Contains(r.Body.String(), `"expired_acceptances":[{`) {
		t.Fatalf("dashboard should list expired acceptances: %s", r.Body.String())
	}
	// Clearing.
	if r := doJSON(h, http.MethodPatch, svcPath, analystTok, map[string]any{"triage": nil}); r.Code != http.StatusOK || strings.Contains(r.Body.String(), `"triage":{`) {
		t.Fatalf("clear triage: %d %s", r.Code, r.Body.String())
	}

	// Host-level false positive.
	r = doJSON(h, http.MethodPatch, "/api/v1/hosts/"+host.ID+"/overrides", analystTok, map[string]any{"triage": map[string]any{"status": "false_positive", "reason": "honeypot"}})
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"triage_status":"false_positive"`) {
		t.Fatalf("host triage: %d %s", r.Code, r.Body.String())
	}
	if dashboardHasFinding(t, h, viewerTok, rdp.ID) {
		t.Fatalf("host-level false positive hides its services from top findings")
	}

	// Webhook: admin only, URL never returned, test button hits the receiver.
	var hits int
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer recv.Close()
	cfgBody := map[string]any{"url": recv.URL + "/hooks/SECRET", "enabled": true, "min_severity": "high"}
	if r := doJSON(h, http.MethodPut, "/api/v1/integrations/webhook", opTok, cfgBody); r.Code != http.StatusForbidden {
		t.Fatalf("operator webhook config expected 403, got %d", r.Code)
	}
	if r := doJSON(h, http.MethodPut, "/api/v1/integrations/webhook", adminTok, map[string]any{"url": "javascript:alert(1)"}); r.Code != http.StatusBadRequest {
		t.Fatalf("bad URL expected 400, got %d", r.Code)
	}
	r = doJSON(h, http.MethodPut, "/api/v1/integrations/webhook", adminTok, cfgBody)
	if r.Code != http.StatusOK || strings.Contains(r.Body.String(), "SECRET") || !strings.Contains(r.Body.String(), `"has_url":true`) {
		t.Fatalf("save webhook: %d %s", r.Code, r.Body.String())
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/integrations/webhook", adminTok, nil); strings.Contains(r.Body.String(), "SECRET") {
		t.Fatalf("GET webhook leaks URL: %s", r.Body.String())
	}
	if r := doJSON(h, http.MethodPost, "/api/v1/integrations/webhook/test", adminTok, nil); r.Code != http.StatusOK || hits != 1 {
		t.Fatalf("test webhook: %d %s hits=%d", r.Code, r.Body.String(), hits)
	}
	// Partial update keeps the stored secret.
	if r := doJSON(h, http.MethodPut, "/api/v1/integrations/webhook", adminTok, map[string]any{"min_severity": "medium"}); !strings.Contains(r.Body.String(), `"has_url":true`) {
		t.Fatalf("partial update dropped URL: %s", r.Body.String())
	}

	// Apply tag rules retroactively to hosts ingested before the rule existed.
	if _, err := srv.pipeline.ProcessObservations(ctx, ingest.IngestRequest{Observations: []domain.ObservedHost{{IP: "10.80.0.1", IsAlive: true, Services: []domain.ObservedService{{Port: 22}}}}}); err != nil {
		t.Fatal(err)
	}
	_ = doJSON(h, http.MethodPut, "/api/v1/tag-rules", analystTok, map[string]any{"rules": []map[string]any{
		{"cidr": "10.66.0.0/22", "tags": []string{"wydzial-wi"}, "owner": "admin@wi.agh.edu.pl", "enabled": true},
		{"cidr": "10.80.0.0/16", "tags": []string{"dc"}, "enabled": true},
	}})
	r = doJSON(h, http.MethodPost, "/api/v1/tag-rules/apply", analystTok, nil)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"updated":1`) {
		t.Fatalf("apply tag rules: %d %s", r.Code, r.Body.String())
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/hosts?q="+urlq("tag:dc"), viewerTok, nil); !strings.Contains(r.Body.String(), "10.80.0.1") {
		t.Fatalf("retroactive tag missing: %s", r.Body.String())
	}
}

func dashboardHasFinding(t *testing.T, h http.Handler, tok, serviceID string) bool {
	t.Helper()
	r := doJSON(h, http.MethodGet, "/api/v1/dashboard/summary", tok, nil)
	var d struct {
		TopFindings []domain.Service `json:"top_findings"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &d); err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	for _, s := range d.TopFindings {
		if s.ID == serviceID {
			return true
		}
	}
	return false
}

func urlq(s string) string {
	return url.QueryEscape(s)
}
