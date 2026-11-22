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

// cleartextOrUnauth are exposures that hand over credentials or data without any
// authentication; they are High in DefectDojo (the same band as the Dzięcioł score).
var cleartextOrUnauth = map[string]bool{
	"Telnet": true, "TELNET": true, "FTP": true, "VNC": true, "Docker API": true, "Redis": true,
	"MongoDB": true, "Elasticsearch": true, "Memcached": true, "CouchDB": true,
}

func exposureSeverity(label string) string {
	if cleartextOrUnauth[label] {
		return "High"
	}
	return "Medium"
}

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
	ID               int    `json:"id"`
	UniqueIDFromTool string `json:"unique_id_from_tool"`
	Active           bool   `json:"active"`
	FalseP           bool   `json:"false_p"`
	RiskAccepted     bool   `json:"risk_accepted"`
	IsMitigated      bool   `json:"is_mitigated"`
	Verified         bool   `json:"verified"`
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

// SyncTriage mirrors the analysts' decisions onto the findings of the change test just
// reimported: false positive -> false_p, accepted risk -> risk_accepted (simple risk
// acceptance; reason, author and expiry go into a note), withdrawn/expired -> active again.
// Fixed items are mitigated by the reimport itself (close_old_findings). It returns one
// FindingRef per change finding (DefectDojo id, link and resulting state) and the number of
// findings whose state was changed.
func (c *Client) SyncTriage(ctx context.Context, cfg *domain.DefectDojoConfig, testID, productID int, findings []ChangeFinding) ([]FindingRef, int, error) {
	now := time.Now().UTC()
	refs := make([]FindingRef, 0, len(findings))
	if testID <= 0 {
		for _, f := range findings {
			refs = append(refs, FindingRef{ServiceID: f.ServiceID, HostID: f.HostID, Kind: f.Kind, Title: f.Title, Severity: f.Severity, State: desiredState(f.Triage), PushedAt: now})
		}
		return refs, 0, nil
	}
	var page struct {
		Results []dojoFinding `json:"results"`
	}
	if err := c.getJSON(ctx, cfg, fmt.Sprintf("/api/v2/findings/?test=%d&limit=2000", testID), &page); err != nil {
		return nil, 0, fmt.Errorf("list findings of test %d: %w", testID, err)
	}
	byUID := make(map[string]dojoFinding, len(page.Results))
	for _, f := range page.Results {
		byUID[f.UniqueIDFromTool] = f
	}
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
		if want != have && !(want == DojoStateActive && have == DojoStateMitigated) {
			var patch map[string]any
			switch want {
			case DojoStateFalsePos:
				patch = map[string]any{"false_p": true, "risk_accepted": false, "active": false, "verified": false}
			case DojoStateRiskAccepted:
				patch = map[string]any{"risk_accepted": true, "false_p": false, "active": false}
			default:
				patch = map[string]any{"false_p": false, "risk_accepted": false, "active": true}
			}
			err := c.patchJSON(ctx, cfg, fmt.Sprintf("/api/v2/findings/%d/", df.ID), patch)
			if err != nil && want == DojoStateRiskAccepted && !simpleRAEnabled && productID > 0 &&
				strings.Contains(strings.ToLower(err.Error()), "risk acceptance") {
				// Simple risk acceptance is a per-product switch in DefectDojo.
				if perr := c.patchJSON(ctx, cfg, fmt.Sprintf("/api/v2/products/%d/", productID), map[string]any{"enable_simple_risk_acceptance": true}); perr == nil {
					simpleRAEnabled = true
					err = c.patchJSON(ctx, cfg, fmt.Sprintf("/api/v2/findings/%d/", df.ID), patch)
				}
			}
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

func triageNote(t *domain.TriageInfo) string {
	if t == nil {
		return "Dzięcioł: analyst decision withdrawn or expired - finding is active again."
	}
	label := "Accepted risk"
	if t.Status == domain.TriageFalsePositive {
		label = "False positive"
	}
	note := fmt.Sprintf("Dzięcioł triage: %s by %s on %s. Reason: %s", label, nonEmpty(t.By, "analyst"), t.At.UTC().Format("2006-01-02"), nonEmpty(t.Reason, "-"))
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
