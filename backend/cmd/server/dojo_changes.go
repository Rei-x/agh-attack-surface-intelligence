package main

import (
	"context"
	"log"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// pushChangeFindings reimports the profile's actionable change findings into the
// "Dzięcioł changes: <profile>" test after a completed run and mirrors analyst triage onto
// them. Like the Nmap push, failures are logged and recorded in the export history, never
// fail the scan.
func (r *LiveScanRunner) pushChangeFindings(ctx context.Context, cfg *domain.DefectDojoConfig, run *domain.ScanRun, profile *domain.ScanProfile, profileName string) {
	hosts, _, err := r.store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		log.Printf("[WARN] DefectDojo change findings for scan %s: list hosts: %v", run.ID, err)
		return
	}
	if profile != nil {
		hosts = defectdojo.HostsInScope(ctx, hosts, profile.Targets)
	}
	title := defectdojo.ChangesTestTitle(profileName)
	res, err := defectdojo.SyncChangeFindings(ctx, r.store, r.dojo, cfg, hosts, title, run.Name, run.ID, "auto-push")
	payload := map[string]any{"scan_run_id": run.ID, "kind": "change_findings", "findings": res.Findings}
	if err != nil {
		payload["error"] = err.Error()
		log.Printf("[WARN] DefectDojo change findings for scan %s failed: %v", run.ID, err)
	} else {
		payload["external_url"] = res.Import.ExternalURL
		payload["triage_synced"] = res.TriageSynced
		if res.TriageError != "" {
			log.Printf("[WARN] DefectDojo triage sync for scan %s: %s", run.ID, res.TriageError)
		}
		log.Printf("[INFO] DefectDojo change findings for scan %s: %d findings (%d triage updates) -> %s", run.ID, res.Findings, res.TriageSynced, res.Import.ExternalURL)
	}
	r.PublishEvent(domain.LiveEvent{Type: "defectdojo_push", ScanRunID: run.ID, Timestamp: time.Now().UTC(), Payload: payload})
}
