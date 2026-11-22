package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// DefectDojo finding states mirrored per finding.
const (
	DojoStateActive       = "active"
	DojoStateFalsePos     = "false_positive"
	DojoStateRiskAccepted = "risk_accepted"
	DojoStateMitigated    = "mitigated"
)

// FindingRef links one Dzięcioł change finding to its DefectDojo finding.
type FindingRef = domain.DefectDojoFindingRef

type dojoFinding struct {
	ID               int        `json:"id"`
	Test             int        `json:"test"`
	Title            string     `json:"title"`
	UniqueIDFromTool string     `json:"unique_id_from_tool"`
	Active           bool       `json:"active"`
	FalseP           bool       `json:"false_p"`
	RiskAccepted     bool       `json:"risk_accepted"`
	IsMitigated      bool       `json:"is_mitigated"`
	Verified         bool       `json:"verified"`
	Notes            []dojoNote `json:"notes"`
}

type dojoNote struct {
	ID     int    `json:"id"`
	Entry  string `json:"entry"`
	Date   string `json:"date"`
	Author struct {
		Username string `json:"username"`
	} `json:"author"`
}

// findingsPageSize keeps each findings page well under DefectDojo's response limits; a
// change test of a /18 holds several thousand findings.
// findingsPageSize keeps one page of full DefectDojo finding objects well under maxResponseBytes.
const findingsPageSize = 200

// listFindings returns every finding of a test matching the extra query (for example
// "&active=true"), following DefectDojo's limit/offset pagination.
func (c *Client) listFindings(ctx context.Context, cfg *domain.DefectDojoConfig, testID int, query string) ([]dojoFinding, error) {
	return listPaged[dojoFinding](ctx, c, cfg, fmt.Sprintf("/api/v2/findings/?test=%d%s", testID, query), findingsPageSize)
}

// listCurrentFindings returns the findings of a test that can belong to a current condition:
// the open ones and the false positives, which DefectDojo marks mitigated too (a reimport
// leaves them alone). The mitigated rest (fixed conditions, older wordings) only grows over
// time, so it is not read.
func (c *Client) listCurrentFindings(ctx context.Context, cfg *domain.DefectDojoConfig, testID int) ([]dojoFinding, error) {
	open, err := c.listFindings(ctx, cfg, testID, "&is_mitigated=false")
	if err != nil {
		return nil, err
	}
	fps, err := c.listFindings(ctx, cfg, testID, "&is_mitigated=true&false_p=true")
	if err != nil {
		return nil, err
	}
	return append(open, fps...), nil
}

// indexByUID maps unique_id_from_tool to the DefectDojo finding of each change finding. A
// unique id can have several: an older wording of the same condition (another owner in the
// title) leaves a mitigated finding behind. The current one is open, or false positive /
// risk accepted (DefectDojo also marks a false positive mitigated, and a reimport leaves it
// alone), then the one whose title matches the payload (DefectDojo title-cases titles),
// then the newest.
func indexByUID(findings []dojoFinding, payload []ChangeFinding) map[string]dojoFinding {
	titles := make(map[string]string, len(payload))
	for _, f := range payload {
		titles[f.UniqueIDFromTool] = strings.ToLower(f.Title)
	}
	score := func(f dojoFinding) int {
		s := 0
		switch {
		case !f.IsMitigated:
			s = 4
		case f.FalseP || f.RiskAccepted:
			s = 2
		}
		if strings.ToLower(f.Title) == titles[f.UniqueIDFromTool] {
			s++
		}
		return s
	}
	out := make(map[string]dojoFinding, len(findings))
	for _, f := range findings {
		if prev, ok := out[f.UniqueIDFromTool]; ok {
			if ps, fs := score(prev), score(f); ps > fs || (ps == fs && prev.ID > f.ID) {
				continue
			}
		}
		out[f.UniqueIDFromTool] = f
	}
	return out
}

func (f dojoFinding) state() string {
	switch {
	case f.FalseP:
		return DojoStateFalsePos
	case f.RiskAccepted:
		return DojoStateRiskAccepted
	case f.IsMitigated:
		return DojoStateMitigated
	}
	return DojoStateActive
}

func desiredState(t *domain.TriageInfo) string {
	if t == nil {
		return DojoStateActive
	}
	switch t.Status {
	case domain.TriageFalsePositive:
		return DojoStateFalsePos
	case domain.TriageAcceptedRisk:
		return DojoStateRiskAccepted
	}
	return DojoStateActive
}

// Notes SyncTriage leaves on a finding when it changes its state. The latest of them tells
// whether a false positive / risk accepted state is Dzięcioł's to revert.
const (
	triageNotePrefix    = "Dzięcioł triage: "
	withdrawnNotePrefix = "Dzięcioł: analyst decision withdrawn"
)

// decidedByDzieciol reports whether Dzięcioł set the finding's current false positive or
// risk accepted state: its latest Dzięcioł note is the triage note of that state. A state
// set in DefectDojo itself (no such note, or a later "withdrawn" one) is the decision of an
// analyst there.
func decidedByDzieciol(notes []dojoNote, state string) bool {
	var latest *dojoNote
	for i := range notes {
		n := &notes[i]
		e := strings.TrimSpace(n.Entry)
		if !strings.HasPrefix(e, triageNotePrefix) && !strings.HasPrefix(e, withdrawnNotePrefix) {
			continue
		}
		if latest == nil || n.ID > latest.ID || (n.ID == latest.ID && n.Date > latest.Date) {
			latest = n
		}
	}
	if latest == nil {
		return false
	}
	rest, ok := strings.CutPrefix(strings.TrimSpace(latest.Entry), triageNotePrefix)
	if !ok {
		return false
	}
	switch state {
	case DojoStateFalsePos:
		return strings.HasPrefix(rest, "False positive")
	case DojoStateRiskAccepted:
		return strings.HasPrefix(rest, "Accepted risk")
	}
	return false
}

// SyncTriage mirrors the analysts' decisions onto the findings of the change test just
// reimported: false positive -> false_p, accepted risk -> risk_accepted (simple risk
// acceptance; reason, author and expiry go into a note), withdrawn/expired -> active again.
// Only a state Dzięcioł set is reverted: a false positive or risk acceptance an analyst set
// in DefectDojo, on a finding Dzięcioł has no decision for, stays. Fixed items are mitigated
// by the reimport itself (close_old_findings). It returns one FindingRef per change finding
// (DefectDojo id, link and resulting state) and the number of findings whose state was
// changed.
func (c *Client) SyncTriage(ctx context.Context, cfg *domain.DefectDojoConfig, testID, productID int, findings []ChangeFinding) ([]FindingRef, int, error) {
	now := time.Now().UTC()
	refs := make([]FindingRef, 0, len(findings))
	if testID <= 0 {
		for _, f := range findings {
			refs = append(refs, FindingRef{ServiceID: f.ServiceID, HostID: f.HostID, Kind: f.Kind, Title: f.Title, Severity: f.Severity, State: desiredState(f.Triage), PushedAt: now})
		}
		return refs, 0, nil
	}
	// Open findings and false positives (which DefectDojo marks mitigated too).
	existing, err := c.listCurrentFindings(ctx, cfg, testID)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings of test %d: %w", testID, err)
	}
	return c.syncTriage(ctx, cfg, testID, productID, findings, existing)
}

// syncTriage is SyncTriage over an already listed test (existing: all its findings).
func (c *Client) syncTriage(ctx context.Context, cfg *domain.DefectDojoConfig, testID, productID int, findings []ChangeFinding, existing []dojoFinding) ([]FindingRef, int, error) {
	now := time.Now().UTC()
	refs := make([]FindingRef, 0, len(findings))
	byUID := indexByUID(existing, findings)
	base := baseURL(cfg.URL)
	changed := 0
	var firstErr error
	simpleRAEnabled := false
	for _, f := range findings {
		ref := FindingRef{ServiceID: f.ServiceID, HostID: f.HostID, Kind: f.Kind, Title: f.Title, Severity: f.Severity, TestID: testID, PushedAt: now}
		df, ok := byUID[f.UniqueIDFromTool]
		if !ok {
			ref.State = desiredState(f.Triage)
			ref.URL = fmt.Sprintf("%s/test/%d", base, testID)
			refs = append(refs, ref)
			continue
		}
		ref.FindingID, ref.URL = df.ID, fmt.Sprintf("%s/finding/%d", base, df.ID)
		want, have := desiredState(f.Triage), df.state()
		ref.State = have
		// Findings confirmed by a safe check (internal/verify) are marked verified: the reimport
		// itself sends verified=false (a multipart form cannot leave it unset).
		if f.Verified && !df.Verified && want == DojoStateActive && have == DojoStateActive {
			_ = c.patchJSON(ctx, cfg, fmt.Sprintf("/api/v2/findings/%d/", df.ID), map[string]any{"verified": true})
		}
		if want == DojoStateActive && (have == DojoStateFalsePos || have == DojoStateRiskAccepted) && !decidedByDzieciol(df.Notes, have) {
			refs = append(refs, ref) // decided in DefectDojo, not withdrawn in Dzięcioł
			continue
		}
		if want != have && !(want == DojoStateActive && have == DojoStateMitigated) {
			err := c.setFindingState(ctx, cfg, df.ID, productID, want, &simpleRAEnabled)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("finding %d -> %s: %w", df.ID, want, err)
				}
			} else {
				ref.State = want
				changed++
				if note := triageNote(f.Triage); note != "" {
					_ = c.postJSON(ctx, cfg, fmt.Sprintf("/api/v2/findings/%d/notes/", df.ID), map[string]any{"entry": note})
				}
			}
		}
		refs = append(refs, ref)
	}
	return refs, changed, firstErr
}

// setFindingState sets a DefectDojo finding to want (active, false positive, risk accepted).
// Simple risk acceptance is a per-product switch in DefectDojo: when it refuses the risk
// acceptance, the switch is turned on once (raEnabled) and the change retried.
func (c *Client) setFindingState(ctx context.Context, cfg *domain.DefectDojoConfig, findingID, productID int, want string, raEnabled *bool) error {
	var patch map[string]any
	switch want {
	case DojoStateFalsePos:
		patch = map[string]any{"false_p": true, "risk_accepted": false, "active": false, "verified": false}
	case DojoStateRiskAccepted:
		patch = map[string]any{"risk_accepted": true, "false_p": false, "active": false}
	default:
		patch = map[string]any{"false_p": false, "risk_accepted": false, "active": true}
	}
	path := fmt.Sprintf("/api/v2/findings/%d/", findingID)
	err := c.patchJSON(ctx, cfg, path, patch)
	if err != nil && want == DojoStateRiskAccepted && !*raEnabled && productID > 0 &&
		strings.Contains(strings.ToLower(err.Error()), "risk acceptance") {
		if perr := c.patchJSON(ctx, cfg, fmt.Sprintf("/api/v2/products/%d/", productID), map[string]any{"enable_simple_risk_acceptance": true}); perr == nil {
			*raEnabled = true
			err = c.patchJSON(ctx, cfg, path, patch)
		}
	}
	return err
}

func triageNote(t *domain.TriageInfo) string {
	if t == nil {
		return withdrawnNotePrefix + " or expired - finding is active again."
	}
	label := "Accepted risk"
	if t.Status == domain.TriageFalsePositive {
		label = "False positive"
	}
	note := fmt.Sprintf("%s%s by %s on %s. Reason: %s", triageNotePrefix, label, nonEmpty(t.By, "analyst"), t.At.UTC().Format("2006-01-02"), nonEmpty(t.Reason, "-"))
	if t.ExpiresAt != nil {
		note += fmt.Sprintf(". Expires %s (Dzięcioł re-activates the finding then).", t.ExpiresAt.UTC().Format("2006-01-02"))
	}
	return note
}

func (c *Client) patchJSON(ctx context.Context, cfg *domain.DefectDojoConfig, path string, body any) error {
	return c.sendJSON(ctx, cfg, http.MethodPatch, path, body)
}

func (c *Client) postJSON(ctx context.Context, cfg *domain.DefectDojoConfig, path string, body any) error {
	return c.sendJSON(ctx, cfg, http.MethodPost, path, body)
}

func (c *Client) sendJSON(ctx context.Context, cfg *domain.DefectDojoConfig, method, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURL(cfg.URL)+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	c.setHeaders(req, cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient(cfg.VerifyTLS).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 300))
	}
	return nil
}
