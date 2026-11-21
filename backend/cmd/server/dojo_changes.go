package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// pushChangeFindings reimports the profile's actionable change findings into the
// "Dzięcioł changes: <profile>" test after a completed run (auto-push enabled). Like the Nmap
// push, failures are logged and recorded in the export history, never fail the scan.
func (r *LiveScanRunner) pushChangeFindings(ctx context.Context, cfg *domain.DefectDojoConfig, run *domain.ScanRun, profile *domain.ScanProfile, profileName string) {
	hosts, _, err := r.store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		log.Printf("[WARN] DefectDojo change findings for scan %s: list hosts: %v", run.ID, err)
		return
	}
	if profile != nil {
		hosts = hostsInScope(ctx, hosts, profile.Targets)
	}
	findings := defectdojo.BuildChangeFindings(hosts, time.Now().UTC())
	title := defectdojo.ChangesTestTitle(profileName)
	imp, err := r.dojo.ImportChangeFindings(ctx, cfg, 0, title, run.Name, findings)
	exp := &domain.DefectDojoExport{
		ExportType: "change_findings",
		SourceID:   run.ID,
		Title:      title + " (" + run.Name + ")",
		ExportedBy: "auto-push",
		CreatedAt:  time.Now().UTC(),
	}
	payload := map[string]any{"scan_run_id": run.ID, "kind": "change_findings", "findings": len(findings)}
	if err != nil {
		exp.Status, exp.ErrorMessage = "failed", err.Error()
		payload["error"] = err.Error()
		log.Printf("[WARN] DefectDojo change findings for scan %s failed: %v", run.ID, err)
	} else {
		exp.Status, exp.ExternalID, exp.ExternalURL = "success", imp.ExternalID, imp.ExternalURL
		payload["external_url"] = imp.ExternalURL
		log.Printf("[INFO] DefectDojo change findings for scan %s: %d findings -> %s", run.ID, len(findings), imp.ExternalURL)
	}
	_ = r.store.AddDefectDojoExport(ctx, exp)
	r.PublishEvent(domain.LiveEvent{Type: "defectdojo_push", ScanRunID: run.ID, Timestamp: time.Now().UTC(), Payload: payload})
}

// hostsInScope keeps the hosts inside the profile targets (IPs, CIDRs, ranges, names), so
// each profile's change test only covers what that profile scans. Unparseable scope keeps
// everything rather than closing every finding.
func hostsInScope(ctx context.Context, hosts []domain.Host, targets []string) []domain.Host {
	if len(targets) == 0 {
		return hosts
	}
	res, err := scanner.ParseAndNormalizeTargets(ctx, targets, nil, nil)
	if err != nil || res == nil || len(res.IPs) == 0 {
		return hosts
	}
	in := make(map[string]struct{}, len(res.IPs))
	for _, ip := range res.IPs {
		in[strings.TrimSpace(ip)] = struct{}{}
	}
	out := hosts[:0:0]
	for _, h := range hosts {
		if _, ok := in[h.IP]; ok {
			out = append(out, h)
		}
	}
	return out
}
