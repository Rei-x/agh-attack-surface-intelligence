package defectdojo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestSeverityMappingAndFindingDate(t *testing.T) {
	if ExposureSeverity("Telnet") != "High" || ExposureSeverity("MySQL") != "Medium" {
		t.Fatal("exposure severities")
	}
	if EOLSeverity(domain.OutdatedComponent{}) != "Medium" || EOLSeverity(domain.OutdatedComponent{DistroPackaged: true}) != "Low" {
		t.Fatal("EOL severities")
	}
	// The finding date stays the UTC day it has always been (DefectDojo's SLA start).
	if got := FindingDate(time.Date(2026, 11, 21, 23, 39, 0, 0, time.UTC), time.Time{}); got != "2026-11-21" {
		t.Fatalf("finding date: %s", got)
	}
	now := time.Date(2026, 11, 22, 7, 0, 0, 0, time.UTC)
	if got := FindingDate(time.Time{}, now); got != "2026-11-22" {
		t.Fatalf("fallback: %s", got)
	}
}

func TestAddFindingNote(t *testing.T) {
	var path, entry string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		path, entry = r.URL.Path, body["entry"]
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}
	note := VerificationNotePrefix + "Fixed: service removed (scan abcd1234, 2026-11-22)."
	if err := NewClient().AddFindingNote(context.Background(), cfg, 42, note); err != nil {
		t.Fatal(err)
	}
	if path != "/api/v2/findings/42/notes/" || entry != note {
		t.Fatalf("posted %s %q", path, entry)
	}
	// A verification note is not a triage decision.
	if decidedByDzieciol([]dojoNote{{ID: 1, Entry: note}}, DojoStateFalsePos) {
		t.Fatal("verification note mistaken for a triage note")
	}
}
