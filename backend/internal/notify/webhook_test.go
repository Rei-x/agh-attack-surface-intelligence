package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

type receiver struct {
	mu     sync.Mutex
	bodies []map[string]any
}

func (rc *receiver) server(t *testing.T, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("payload is not JSON: %s", raw)
		}
		rc.mu.Lock()
		rc.bodies = append(rc.bodies, body)
		rc.mu.Unlock()
		w.WriteHeader(status)
	}))
}

func TestWebhookPayloadFilteringAndSuppression(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	rc := &receiver{}
	srv := rc.server(t, http.StatusOK)
	defer srv.Close()

	if err := SaveConfig(ctx, store, &domain.WebhookConfig{URL: srv.URL + "/services/T0/B0/token", Enabled: true, MinSeverity: "high", NotifyStateChanges: true}); err != nil {
		t.Fatal(err)
	}
	accepted, _ := store.UpsertObservedHost(ctx, &domain.Host{IP: "10.0.0.2", LifecycleState: "ACTIVE"})
	_ = store.PatchOverrides(ctx, "host", accepted.ID, map[string]any{"triage": domain.TriageInfo{Status: domain.TriageAcceptedRisk, Reason: "lab"}}, nil, "admin")

	n := New(store)
	n.Async = false
	run := &domain.ScanRun{ID: "run-1", Name: "nightly /16"}
	n.NotifyChanges(ctx, run, []domain.ChangeEvent{
		{ID: "e1", EventType: "NEW_SERVICE", Severity: "high", HostIP: "10.0.0.1", Port: 3389, Summary: "New RDP exposure 3389/tcp on 10.0.0.1"},
		{ID: "e2", EventType: "NEW_SERVICE", Severity: "low", HostIP: "10.0.0.1", Port: 22, Summary: "New service 22/tcp"},
		{ID: "e3", EventType: "HOST_MISSING", Severity: "low", HostIP: "10.0.0.3", Summary: "Host 10.0.0.3 not responding"},
		{ID: "e4", EventType: "ADMIN_PANEL_EXPOSED", Severity: "high", HostID: accepted.ID, HostIP: "10.0.0.2", Summary: "suppressed by acceptance"},
	})
	if len(rc.bodies) != 1 {
		t.Fatalf("expected exactly one webhook call, got %d", len(rc.bodies))
	}
	body := rc.bodies[0]
	text, _ := body["text"].(string)
	content, _ := body["content"].(string)
	if !strings.Contains(text, "RDP exposure") || !strings.Contains(text, "HOST_MISSING") || text != content {
		t.Fatalf("Slack/Teams text + Discord content must list alerts: %q", text)
	}
	if strings.Contains(text, "22/tcp") || strings.Contains(text, "suppressed") {
		t.Fatalf("low-severity and accepted-risk events must be filtered: %q", text)
	}
	events, _ := body["events"].([]any)
	if len(events) != 2 || body["scan_run"].(map[string]any)["name"] != "nightly /16" {
		t.Fatalf("structured events/scan_run wrong: %+v", body)
	}

	cfg, _ := LoadConfig(ctx, store)
	if cfg.LastStatus != "ok" || cfg.LastSentAt == nil {
		t.Fatalf("last status not recorded: %+v", cfg)
	}
	pub := Public(cfg)
	if pub.URL != "" || !pub.HasURL || strings.Contains(pub.URLMasked, "token") {
		t.Fatalf("public config must hide the secret URL: %+v", pub)
	}

	// Disabled webhook sends nothing.
	cfg.Enabled = false
	_ = SaveConfig(ctx, store, cfg)
	n.NotifyChanges(ctx, run, []domain.ChangeEvent{{EventType: "NEW_SERVICE", Severity: "high"}})
	if len(rc.bodies) != 1 {
		t.Fatalf("disabled webhook must not send")
	}
}

func TestWebhookTestAndErrorsDoNotLeakURL(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	rc := &receiver{}
	bad := rc.server(t, http.StatusForbidden)
	defer bad.Close()
	n := New(store)
	err := n.SendTest(ctx, bad.URL+"/secret-token")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected HTTP 403 error, got %v", err)
	}
	if len(rc.bodies) != 1 || !strings.Contains(rc.bodies[0]["text"].(string), "test webhook") {
		t.Fatalf("test payload not sent: %+v", rc.bodies)
	}
	err = n.Send(ctx, "http://127.0.0.1:1/secret-token", map[string]any{"text": "x"})
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("connection errors must mask the URL: %v", err)
	}
	if err := ValidateURL("ftp://x"); err == nil {
		t.Fatal("non-http URL must be rejected")
	}
	if got := SelectEvents(&domain.WebhookConfig{MinSeverity: "medium"}, []domain.ChangeEvent{{Severity: "medium"}, {Severity: "low", EventType: "HOST_INACTIVE"}}); len(got) != 1 {
		t.Fatalf("state changes must be opt-in: %+v", got)
	}
}
