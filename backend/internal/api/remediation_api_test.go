package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/remediation"
)

func TestRemediationLoopVerifiedByNextScan(t *testing.T) {
	srv, store, h := setupTestServer(t)
	ctx := context.Background()
	analystTok := loginTest(t, h, "analyst", "Analyst123!")
	viewerTok := loginTest(t, h, "viewer", "Viewer123!")

	rules := map[string]any{"rules": []map[string]any{{"cidr": "10.66.0.0/22", "owner": "WI IT", "description": "contact it@wi.agh.edu.pl"}}}
	if r := doJSON(h, http.MethodPut, "/api/v1/tag-rules", analystTok, rules); r.Code != http.StatusOK {
		t.Fatalf("tag rules: %d %s", r.Code, r.Body.String())
	}
	obs := func(ports ...int) []domain.ObservedHost {
		var svcs []domain.ObservedService
		for _, p := range ports {
			svcs = append(svcs, domain.ObservedService{Port: p, ServiceName: map[int]string{22: "ssh", 23: "telnet"}[p]})
		}
		return []domain.ObservedHost{{IP: "10.66.0.20", IsAlive: true, Services: svcs}}
	}
	if _, err := srv.pipeline.ProcessObservations(ctx, ingest.IngestRequest{ScanName: "night 1", Observations: obs(22, 23)}); err != nil {
		t.Fatal(err)
	}
	host, err := store.GetHostByIP(ctx, "10.66.0.20")
	if err != nil {
		t.Fatal(err)
	}
	var telnetID string
	for _, s := range host.Services {
		if s.Port == 23 {
			telnetID = s.ID
		}
	}

	r := doJSON(h, http.MethodGet, "/api/v1/remediation/draft?host_id="+host.ID+"&service_id="+telnetID, viewerTok, nil)
	var draft remediation.DraftResponse
	_ = json.Unmarshal(r.Body.Bytes(), &draft)
	if r.Code != http.StatusOK || draft.Owner != "WI IT" || draft.OwnerEmail != "it@wi.agh.edu.pl" || draft.IssueKey != "cleartext-admin:telnet" {
		t.Fatalf("draft: %d %s", r.Code, r.Body.String())
	}
	// A new install writes Polish notices; the analyst can switch per message.
	if !strings.HasPrefix(draft.Body, "Szanowni Państwo,") || !strings.Contains(draft.Body, "(w naszej ewidencji: WI IT)") || draft.Language != "pl" {
		t.Fatalf("draft body: %s", draft.Body)
	}
	// Telnet is High in DefectDojo: 30 days.
	if draft.SLA.Severity != "high" || draft.SLA.Days != 30 || draft.DueDate == "" || !strings.Contains(draft.Body, "w terminie do "+draft.DueDate) {
		t.Fatalf("draft due: %+v %s", draft.SLA, draft.DueDate)
	}
	r = doJSON(h, http.MethodGet, "/api/v1/remediation/draft?host_id="+host.ID+"&service_id="+telnetID+"&lang=en", viewerTok, nil)
	var en remediation.DraftResponse
	_ = json.Unmarshal(r.Body.Bytes(), &en)
	if !strings.Contains(en.Body, "Hello WI IT,") || en.Language != "en" {
		t.Fatalf("english draft: %s", en.Body)
	}

	create := map[string]any{"host_id": host.ID, "service_id": telnetID, "issue_key": draft.IssueKey, "subject": draft.Subject, "body": draft.Body, "language": draft.Language, "due_date": draft.DueDate, "channel": "manual"}
	if r := doJSON(h, http.MethodPost, "/api/v1/remediation/tickets", viewerTok, create); r.Code != http.StatusForbidden {
		t.Fatalf("viewer create expected 403, got %d", r.Code)
	}
	r = doJSON(h, http.MethodPost, "/api/v1/remediation/tickets", analystTok, create)
	var sent remediation.SendResult
	_ = json.Unmarshal(r.Body.Bytes(), &sent)
	if r.Code != http.StatusCreated || sent.Ticket.Status != remediation.StatusNotified || !strings.HasPrefix(sent.Delivery.Mailto, "mailto:it@wi.agh.edu.pl") {
		t.Fatalf("create: %d %s", r.Code, r.Body.String())
	}
	if r := doJSON(h, http.MethodPost, "/api/v1/remediation/tickets/"+sent.Ticket.ID+"/status", analystTok, map[string]any{"status": "accepted_risk"}); r.Code != http.StatusBadRequest {
		t.Fatalf("accepted risk without reason expected 400, got %d", r.Code)
	}

	// The owner turns telnet off; the next scan's scan.completed triggers verification.
	if _, err := srv.pipeline.ProcessObservations(ctx, ingest.IngestRequest{ScanName: "night 2", Observations: obs(22)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var got remediation.Ticket
	for time.Now().Before(deadline) {
		r = doJSON(h, http.MethodGet, "/api/v1/remediation/tickets/"+sent.Ticket.ID, viewerTok, nil)
		_ = json.Unmarshal(r.Body.Bytes(), &got)
		if got.Status == remediation.StatusFixed {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got.Status != remediation.StatusFixed || !got.Verified || got.FixedScanID == "" {
		t.Fatalf("ticket not verified fixed: %+v", got)
	}
	// The closed port is reported as out of reach, not as a patch.
	var view struct {
		FixedReason string `json:"fixed_reason"`
		FixOutcome  string `json:"fix_outcome"`
		DueDate     string `json:"due_date"`
		Language    string `json:"language"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &view)
	if view.FixedReason != remediation.FixedServiceRemoved || view.FixOutcome != "Closed: not reachable" || view.DueDate != draft.DueDate || view.Language != "pl" {
		t.Fatalf("ticket view: %+v", view)
	}

	r = doJSON(h, http.MethodGet, "/api/v1/remediation/tickets?status=fixed", viewerTok, nil)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"fixed":1`) {
		t.Fatalf("list: %d %s", r.Code, r.Body.String())
	}
	logs, _ := store.ListAuditLogs(ctx, 50)
	seen := map[string]bool{}
	for _, l := range logs {
		seen[l.Action] = true
	}
	for _, a := range []string{"remediation.create", "remediation.notify", "remediation.verified_fixed"} {
		if !seen[a] {
			t.Errorf("audit log misses %s", a)
		}
	}

	// Digest: preview before any is stored, then build and download.
	r = doJSON(h, http.MethodGet, "/api/v1/digest/latest", viewerTok, nil)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"preview":true`) {
		t.Fatalf("latest digest: %d %s", r.Code, r.Body.String())
	}
	r = doJSON(h, http.MethodPost, "/api/v1/digest/build", analystTok, map[string]any{})
	var d struct {
		ID     string `json:"id"`
		Counts struct {
			Fixed int `json:"fixed"`
		} `json:"counts"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &d)
	if r.Code != http.StatusCreated || d.Counts.Fixed != 1 {
		t.Fatalf("build digest: %d %s", r.Code, r.Body.String())
	}
	r = doJSON(h, http.MethodGet, "/api/v1/digest/"+d.ID+"/markdown", viewerTok, nil)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "Closed (not reachable): Telnet (cleartext login)") {
		t.Fatalf("markdown: %d %s", r.Code, r.Body.String())
	}
	if r := doJSON(h, http.MethodPut, "/api/v1/digest/settings", analystTok, map[string]any{"enabled": true}); r.Code != http.StatusForbidden {
		t.Fatalf("analyst digest settings expected 403, got %d", r.Code)
	}

	// Notice settings are readable by every role (dates, SLA), writable by admins only.
	r = doJSON(h, http.MethodGet, "/api/v1/remediation/channels", viewerTok, nil)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"notice_language":"pl"`) || !strings.Contains(r.Body.String(), `"timezone":"Europe/Warsaw"`) || !strings.Contains(r.Body.String(), `"medium":90`) {
		t.Fatalf("channels: %d %s", r.Code, r.Body.String())
	}
	if r := doJSON(h, http.MethodPut, "/api/v1/remediation/channels", analystTok, map[string]any{"notice_language": "en"}); r.Code != http.StatusForbidden {
		t.Fatalf("analyst channels expected 403, got %d", r.Code)
	}
}

func TestMitigationNoteSaysWhatTheScanSaw(t *testing.T) {
	warsaw, _ := time.LoadLocation("Europe/Warsaw")
	at := time.Date(2026, 11, 21, 23, 39, 0, 0, time.UTC) // 00:39 on the 22nd in Warsaw
	closed := remediation.Ticket{Status: remediation.StatusFixed, FixedReason: remediation.FixedServiceRemoved, FixedAt: &at,
		LastCheckNote: "service no longer reachable from the scanner: port 23/tcp is closed (it may be firewalled rather than removed)"}
	note := mitigationNote(closed, "0123456789abcdef", warsaw)
	want := "Dzięcioł verification: Closed: not reachable (scan 01234567, 2026-11-22). Service no longer reachable from the scanner: port 23/tcp is closed (it may be firewalled rather than removed). This is not a confirmed patch: the service may only be blocked for the scanner."
	if note != want {
		t.Fatalf("note:\n got %q\nwant %q", note, want)
	}
	upgraded := remediation.Ticket{Status: remediation.StatusFixed, FixedReason: remediation.FixedUpgraded, FixedDetail: "nginx 1.30.1", FixedAt: &at,
		LastCheckNote: "upgraded to nginx 1.30.1, which is no longer end of life"}
	if note := mitigationNote(upgraded, "scan-9", warsaw); note != "Dzięcioł verification: Fixed: upgraded to nginx 1.30.1 (scan scan-9, 2026-11-22). Upgraded to nginx 1.30.1, which is no longer end of life." {
		t.Fatalf("upgrade note: %q", note)
	}
}
