package defectdojo

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

var (
	// syncStateMu serialises read-modify-write of the stored sync state (runs can finish
	// concurrently, and the Nmap push records its link too).
	syncStateMu sync.Mutex
	// changeSyncMu serialises whole change syncs: every sync pushes the same inventory into
	// the same test, so two at once would only race each other in DefectDojo. A sync that
	// waits runs afterwards with the then current inventory.
	changeSyncMu sync.Mutex
)

// ChangeSyncResult is the outcome of one "Dzięcioł changes" push.
type ChangeSyncResult struct {
	Import       *ImportResult `json:"import,omitempty"`
	TestTitle    string        `json:"test_title"`
	Findings     int           `json:"findings"`
	TriageSynced int           `json:"triage_synced"`
	TriageError  string        `json:"triage_error,omitempty"`
	Warnings     []string      `json:"warnings,omitempty"`
}

// changesPush is what pushChanges did in DefectDojo.
type changesPush struct {
	Import        *ImportResult
	Context       string       // importContext.key() of the change test
	Refs          []FindingRef // one per finding; nil when the test could not be listed
	TriageChanged int
	TriageErr     error
	Warnings      []string
}

// SyncChanges builds the change findings of the whole inventory, reimports them into the
// one "Dzięcioł changes" test, mirrors analyst triage onto the DefectDojo findings and
// records the result (export history + sync state used by the header chip and the
// per-service status). Every trigger ends here: a completed run (runID set), push now,
// triage changes and scan-verified fixes, so they all agree on what is open.
func SyncChanges(ctx context.Context, store db.Store, c *Client, cfg *domain.DefectDojoConfig, runLabel, runID, exportedBy string) (*ChangeSyncResult, error) {
	changeSyncMu.Lock()
	defer changeSyncMu.Unlock()
	res := &ChangeSyncResult{TestTitle: ChangesTest}
	hosts, _, err := store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		return res, fmt.Errorf("list hosts: %w", err)
	}
	profiles, _ := store.ListProfiles(ctx)
	findings := InventoryChangeFindings(ctx, hosts, profiles, time.Now().UTC())
	findings = append(findings, PolicyFindingsFor(ctx, store, hosts)...) // zone policy violations (policy_findings.go)
	res.Findings = len(findings)

	prev := db.LoadDefectDojoSync(ctx, store)
	push, err := c.pushChanges(ctx, cfg, prev.TestID, prev.ChangesContext, runLabel, findings)

	now := time.Now().UTC()
	exp := &domain.DefectDojoExport{
		ExportType: "change_findings",
		SourceID:   runID,
		Title:      fmt.Sprintf("%s (%s, %d findings)", ChangesTest, runLabel, len(findings)),
		ExportedBy: exportedBy,
		CreatedAt:  now,
	}
	syncStateMu.Lock()
	defer syncStateMu.Unlock()
	st := db.LoadDefectDojoSync(ctx, store)
	st.LastSyncAt, st.LastRunID = &now, runID
	if err != nil {
		exp.Status, exp.ErrorMessage = "failed", err.Error()
		st.LastStatus, st.LastError = "failed", err.Error()
		_ = store.AddDefectDojoExport(ctx, exp)
		_ = db.SaveDefectDojoSync(ctx, store, st)
		return res, err
	}
	imp := push.Import
	res.Import, res.TriageSynced, res.Warnings = imp, push.TriageChanged, push.Warnings
	exp.Status, exp.ExternalID, exp.ExternalURL = "success", imp.ExternalID, imp.ExternalURL
	if push.TriageErr != nil {
		res.TriageError = push.TriageErr.Error()
		exp.ErrorMessage = "triage sync: " + res.TriageError
	}
	_ = store.AddDefectDojoExport(ctx, exp)

	st.LastStatus, st.LastError = "success", strings.Join(append(nonEmptyStrings(res.TriageError), push.Warnings...), "; ")
	st.TestID, st.TestURL, st.ChangesContext = imp.TestID, imp.ExternalURL, push.Context
	if imp.ProductID > 0 {
		st.ProductID, st.ProductURL = imp.ProductID, fmt.Sprintf("%s/product/%d", baseURL(cfg.URL), imp.ProductID)
	}
	st.Findings, st.TriageSynced = len(findings), push.TriageChanged
	// One test, so its links replace every earlier one (also those of the per-profile
	// tests of older versions). Without a listing the previous links are the best known.
	if push.Refs != nil {
		st.FindingsByKey = refsByKey(push.Refs)
		st.Findings = len(push.Refs)
	}
	_ = db.SaveDefectDojoSync(ctx, store, st)
	return res, nil
}

// pushChanges reimports findings into the change test and mirrors triage onto it. The test
// is addressed by id once known (knownTestID, found in the same product type / product /
// engagement as now), so renaming it in DefectDojo does not start a second one; a deleted
// test falls back to the title, which DefectDojo resolves or creates.
func (c *Client) pushChanges(ctx context.Context, cfg *domain.DefectDojoConfig, knownTestID int, knownContext, runLabel string, findings []ChangeFinding) (*changesPush, error) {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("defectdojo URL is not configured")
	}
	ic, err := c.resolveContext(ctx, cfg, 0)
	if err != nil {
		return nil, err
	}
	out := &changesPush{Context: ic.key()}
	target := reimportTarget{Context: ic, Title: ChangesTest}
	if knownTestID > 0 && knownContext == out.Context {
		target.TestID = knownTestID
	}
	imp, err := c.importChanges(ctx, cfg, target, runLabel, findings)
	if err != nil && target.TestID > 0 && isMissingTest(err) {
		out.Warnings = append(out.Warnings, fmt.Sprintf("change test #%d is gone from DefectDojo; reimported by title", target.TestID))
		target.TestID = 0
		imp, err = c.importChanges(ctx, cfg, target, runLabel, findings)
	}
	if err != nil {
		return nil, err
	}
	out.Import = imp
	if imp.TestID <= 0 {
		out.Refs, _, _ = c.SyncTriage(ctx, cfg, 0, imp.ProductID, findings)
		return out, nil
	}
	// Open findings only: after the reimport every finding of the payload is open.
	existing, lerr := c.listFindings(ctx, cfg, imp.TestID, "&is_mitigated=false")
	if lerr != nil {
		out.TriageErr = fmt.Errorf("list findings of test %d: %w", imp.TestID, lerr)
		return out, nil
	}
	out.Refs, out.TriageChanged, out.TriageErr = c.syncTriage(ctx, cfg, imp.TestID, imp.ProductID, findings, existing)
	return out, nil
}

// key identifies the DefectDojo context the change test lives in.
func (ic importContext) key() string {
	return ic.ProductType + " / " + ic.Product + " / " + ic.Engagement
}

// refsByKey groups finding links by "service:<id>" / "host:<id>".
func refsByKey(refs []FindingRef) map[string][]domain.DefectDojoFindingRef {
	out := make(map[string][]domain.DefectDojoFindingRef, len(refs))
	for _, r := range refs {
		key := "host:" + r.HostID
		if r.ServiceID != "" {
			key = "service:" + r.ServiceID
		}
		out[key] = append(out[key], r)
	}
	return out
}

func nonEmptyStrings(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// RecordNmapPush stores the last Nmap reimport link in the sync state.
func RecordNmapPush(ctx context.Context, store db.Store, testURL string) {
	syncStateMu.Lock()
	defer syncStateMu.Unlock()
	st := db.LoadDefectDojoSync(ctx, store)
	now := time.Now().UTC()
	st.NmapTestURL, st.NmapPushedAt = testURL, &now
	_ = db.SaveDefectDojoSync(ctx, store, st)
}

// SyncNow pushes the change findings of the whole inventory and syncs triage right away:
// the admin "push now" action (exportedBy is the user) and the debounced sync after triage
// changes and verified fixes (exportedBy "triage-sync").
func SyncNow(ctx context.Context, store db.Store, c *Client, cfg *domain.DefectDojoConfig, exportedBy string) (*ChangeSyncResult, error) {
	// The label lands in the DefectDojo test "version" field, so say what triggered the sync.
	label := "push now (" + exportedBy + ") " + time.Now().UTC().Format("2006-01-02 15:04")
	if exportedBy == "triage-sync" {
		label = "auto sync after triage change " + time.Now().UTC().Format("2006-01-02 15:04")
	}
	return SyncChanges(ctx, store, c, cfg, label, "", exportedBy)
}
