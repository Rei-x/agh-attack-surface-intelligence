package defectdojo

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// syncStateMu serialises read-modify-write of the stored sync state (runs can finish
// concurrently).
var syncStateMu sync.Mutex

// ChangeSyncResult is the outcome of one "Dzięcioł changes" push.
type ChangeSyncResult struct {
	Import       *ImportResult `json:"import,omitempty"`
	TestTitle    string        `json:"test_title"`
	Findings     int           `json:"findings"`
	TriageSynced int           `json:"triage_synced"`
	TriageError  string        `json:"triage_error,omitempty"`
}

// SyncChangeFindings builds the change findings for hosts, reimports them into testTitle,
// mirrors analyst triage onto the DefectDojo findings and records the result (export
// history + sync state used by the header chip and the per-service status).
func SyncChangeFindings(ctx context.Context, store db.Store, c *Client, cfg *domain.DefectDojoConfig, hosts []domain.Host, testTitle, runLabel, runID, exportedBy string) (*ChangeSyncResult, error) {
	findings := BuildChangeFindings(hosts, time.Now().UTC())
	findings = append(findings, PolicyFindingsFor(ctx, store, hosts)...) // zone policy violations (policy_findings.go)
	res := &ChangeSyncResult{TestTitle: testTitle, Findings: len(findings)}
	imp, err := c.ImportChangeFindings(ctx, cfg, 0, testTitle, runLabel, findings)
	exp := &domain.DefectDojoExport{
		ExportType: "change_findings",
		SourceID:   runID,
		Title:      fmt.Sprintf("%s (%s, %d findings)", testTitle, runLabel, len(findings)),
		ExportedBy: exportedBy,
		CreatedAt:  time.Now().UTC(),
	}
	now := time.Now().UTC()
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
	res.Import = imp
	exp.Status, exp.ExternalID, exp.ExternalURL = "success", imp.ExternalID, imp.ExternalURL

	refs, changed, terr := c.SyncTriage(ctx, cfg, imp.TestID, imp.ProductID, findings)
	res.TriageSynced = changed
	if terr != nil {
		res.TriageError = terr.Error()
		exp.ErrorMessage = "triage sync: " + terr.Error()
	}
	_ = store.AddDefectDojoExport(ctx, exp)

	st.LastStatus, st.LastError = "success", res.TriageError
	st.TestID, st.TestURL = imp.TestID, imp.ExternalURL
	if imp.ProductID > 0 {
		st.ProductID, st.ProductURL = imp.ProductID, fmt.Sprintf("%s/product/%d", baseURL(cfg.URL), imp.ProductID)
	}
	st.Findings, st.TriageSynced = len(findings), changed
	// Replace this test's links; other profiles' tests keep theirs.
	if st.FindingsByKey == nil {
		st.FindingsByKey = map[string][]domain.DefectDojoFindingRef{}
	}
	for k, list := range st.FindingsByKey {
		kept := list[:0:0]
		for _, r := range list {
			if r.TestID != imp.TestID {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(st.FindingsByKey, k)
		} else {
			st.FindingsByKey[k] = kept
		}
	}
	for _, r := range refs {
		key := "host:" + r.HostID
		if r.ServiceID != "" {
			key = "service:" + r.ServiceID
		}
		st.FindingsByKey[key] = append(st.FindingsByKey[key], r)
	}
	// Findings across every profile's test, not only the one just pushed.
	total := 0
	for _, list := range st.FindingsByKey {
		total += len(list)
	}
	st.Findings = total
	_ = db.SaveDefectDojoSync(ctx, store, st)
	return res, nil
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

// HostsInScope keeps the hosts inside the profile targets (IPs, CIDRs, ranges, names), so
// each profile's change test only covers what that profile scans. Unparseable scope keeps
// everything rather than closing every finding.
func HostsInScope(ctx context.Context, hosts []domain.Host, targets []string) []domain.Host {
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

// SyncAllProfiles pushes the change findings of every profile (its own test) - the admin
// "push now" action. Without profiles the whole inventory goes into one test.
func SyncAllProfiles(ctx context.Context, store db.Store, c *Client, cfg *domain.DefectDojoConfig, exportedBy string) ([]*ChangeSyncResult, error) {
	hosts, _, err := store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		return nil, err
	}
	profiles, _ := store.ListProfiles(ctx)
	label := "manual sync " + time.Now().UTC().Format("2006-01-02 15:04")
	var out []*ChangeSyncResult
	if len(profiles) == 0 {
		r, err := SyncChangeFindings(ctx, store, c, cfg, hosts, ChangesTestTitle(""), label, "", exportedBy)
		return append(out, r), err
	}
	var firstErr error
	covered := map[string]bool{}
	for _, p := range profiles {
		scoped := HostsInScope(ctx, hosts, p.Targets)
		for _, h := range scoped {
			covered[h.ID] = true
		}
		r, err := SyncChangeFindings(ctx, store, c, cfg, scoped, ChangesTestTitle(p.Name), label, "", exportedBy)
		out = append(out, r)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Hosts no profile covers (imports, manual entries) go to the plain "Dzięcioł changes" test.
	var rest []domain.Host
	for _, h := range hosts {
		if !covered[h.ID] {
			rest = append(rest, h)
		}
	}
	if len(rest) > 0 {
		r, err := SyncChangeFindings(ctx, store, c, cfg, rest, ChangesTestTitle(""), label, "", exportedBy)
		out = append(out, r)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return out, firstErr
}
