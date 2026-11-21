package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestProfileScheduleValidationStatusAndRunNowRBAC(t *testing.T) {
	_, store, h := setupTestServer(t)
	opTok := loginTest(t, h, "operator", "Operator123!")
	analystTok := loginTest(t, h, "analyst", "Analyst123!")
	viewerTok := loginTest(t, h, "viewer", "Viewer123!")

	base := map[string]any{
		"name": "Nightly AGH", "targets": []string{"172.28.0.0/28"}, "allowed_ports": "22,80",
		"window_enabled": true, "window_start": "22:00", "window_end": "06:00", "timezone": "Europe/Warsaw",
		"enabled": true,
	}

	// Invalid cron -> 400 with a clear message.
	bad := map[string]any{}
	for k, v := range base {
		bad[k] = v
	}
	bad["schedule_cron"] = "0 25 * * *"
	if r := doJSON(h, http.MethodPost, "/api/v1/profiles", opTok, bad); r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "invalid schedule_cron") {
		t.Fatalf("expected 400 invalid schedule_cron, got %d %s", r.Code, r.Body.String())
	}
	bad["schedule_cron"] = "0 22 * * *"
	bad["window_start"] = "25:00"
	if r := doJSON(h, http.MethodPost, "/api/v1/profiles", opTok, bad); r.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid window, got %d", r.Code)
	}

	// Valid -> 201 with flattened profile fields (backward compatible) + schedule status.
	good := map[string]any{}
	for k, v := range base {
		good[k] = v
	}
	good["schedule_cron"] = "0 12 * * *" // outside window -> deferred to 22:00
	rec := doJSON(h, http.MethodPost, "/api/v1/profiles", opTok, good)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID           string `json:"id"`
		ScheduleCron string `json:"schedule_cron"`
		Schedule     struct {
			Scheduled        bool       `json:"scheduled"`
			NextRunAt        *time.Time `json:"next_run_at"`
			NextSlotAt       *time.Time `json:"next_slot_at"`
			DeferredByWindow bool       `json:"deferred_by_window"`
		} `json:"schedule"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" || created.ScheduleCron != "0 12 * * *" || !created.Schedule.Scheduled || created.Schedule.NextRunAt == nil || !created.Schedule.DeferredByWindow {
		t.Fatalf("unexpected create response: %s", rec.Body.String())
	}
	loc, _ := time.LoadLocation("Europe/Warsaw")
	if loc != nil {
		if hh := created.Schedule.NextRunAt.In(loc).Format("15:04"); hh != "22:00" {
			t.Fatalf("deferred next_run_at should be window open 22:00, got %s", hh)
		}
	}

	// List & get include schedule.
	if r := doJSON(h, http.MethodGet, "/api/v1/profiles", viewerTok, nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"schedule":{`) {
		t.Fatalf("list profiles missing schedule: %d %s", r.Code, r.Body.String())
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/profiles/"+created.ID, viewerTok, nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"next_run_at"`) {
		t.Fatalf("get profile: %d %s", r.Code, r.Body.String())
	}

	// Run-now RBAC: viewer & analyst lack scans:run.
	for _, tok := range []string{viewerTok, analystTok} {
		if r := doJSON(h, http.MethodPost, "/api/v1/profiles/"+created.ID+"/run", tok, nil); r.Code != http.StatusForbidden {
			t.Fatalf("run-now expected 403, got %d", r.Code)
		}
	}

	// Active run blocks run-now with 409.
	blocking := &domain.ScanRun{ID: "blocking-run", ProfileID: created.ID, Name: "blocking", RunType: domain.ScanTypeActive,
		Status: domain.ScanStatusPausedWindow, StartedAt: time.Now().UTC()}
	if err := store.CreateScanRun(context.Background(), blocking); err != nil {
		t.Fatal(err)
	}
	r := doJSON(h, http.MethodPost, "/api/v1/profiles/"+created.ID+"/run", opTok, nil)
	if r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "blocking-run") {
		t.Fatalf("expected 409 naming the active run, got %d %s", r.Code, r.Body.String())
	}
	blocking.Status = domain.ScanStatusCompleted
	_ = store.UpdateScanRun(context.Background(), blocking)

	r = doJSON(h, http.MethodPost, "/api/v1/profiles/"+created.ID+"/run", opTok, nil)
	if r.Code != http.StatusAccepted || !strings.Contains(r.Body.String(), `"triggered_by":"operator"`) {
		t.Fatalf("run-now expected 202, got %d %s", r.Code, r.Body.String())
	}
	if r := doJSON(h, http.MethodPost, "/api/v1/profiles/does-not-exist/run", opTok, nil); r.Code != http.StatusNotFound {
		t.Fatalf("run-now unknown profile expected 404, got %d", r.Code)
	}
}
