package api

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/remediation"
)

// reflectFixInDefectDojo makes a scan-verified fix end up mitigated in DefectDojo.
//
// It uses the same mechanism as the triage sync: the "Dzięcioł changes" test is a snapshot
// of what is still actionable, reimported with close_old_findings. A verified fix means the
// condition is gone from the inventory (port closed, version upgraded, panel removed), so
// the finding is absent from the next reimport and DefectDojo mitigates it with the date.
// queueDojoSync runs that reimport (debounced) right away instead of waiting for the next
// automatic push, which also covers remote agent runs and imports. A verified fix that
// comes back is reactivated by the same reimport.
//
// DefectDojo only records "mitigated", which reads like a patch. The linked findings
// therefore get a note saying what the scan actually saw: an upgrade, or a service the
// scanner no longer reaches (which a firewall rule produces just as well).
func (s *Server) reflectFixInDefectDojo(ctx context.Context, t remediation.Ticket, scanID string) {
	cfg, err := db.LoadDefectDojoConfig(ctx, s.store)
	if err != nil || cfg == nil || strings.TrimSpace(cfg.URL) == "" || !cfg.HasAPIToken {
		return
	}
	note := mitigationNote(t, scanID, s.remediation.Prefs(ctx).Loc)
	details := map[string]any{
		"ticket_id": t.ID, "scan_run_id": scanID, "unique_id_from_tool": t.DefectDojoUniqueID,
		"fixed_reason": t.FixedReason, "outcome": t.FixOutcome(), "note": note,
	}
	// Name the linked DefectDojo finding(s) from the last sync, when there are any.
	var ids []int
	if t.ServiceID != "" {
		for _, ref := range db.LoadDefectDojoSync(ctx, s.store).FindingsByKey["service:"+t.ServiceID] {
			if ref.FindingID > 0 && (ref.Kind == t.Kind || (t.Kind == remediation.KindCleartextAdmin && ref.Kind == "risky-exposure")) {
				ids = append(ids, ref.FindingID)
			}
		}
		if len(ids) > 0 {
			details["finding_ids"] = ids
		}
	}
	mode := "queued change findings reimport (close_old_findings)"
	if !cfg.AutoPushFindings {
		mode = "automatic findings push is off; mitigated on the next manual sync"
	}
	details["mode"] = mode
	log.Printf("[INFO] remediation: ticket %s verified fixed by scan %s (%s); DefectDojo: %s", t.ID, scanID, t.FixOutcome(), mode)
	if len(ids) > 0 && s.dojo != nil {
		go func(ids []int) {
			nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			for _, id := range ids {
				if err := s.dojo.AddFindingNote(nctx, cfg, id, note); err != nil {
					log.Printf("[WARN] remediation: DefectDojo note on finding %d failed: %v", id, err)
				}
			}
		}(ids)
	}
	s.auditFromContext(ctx, &domain.AuditLog{
		Username: remediation.SystemUser, Action: "remediation.defectdojo_mitigate", Resource: "defectdojo",
		ResourceID: t.DefectDojoUniqueID, Status: "success", CreatedAt: time.Now().UTC(), Details: details,
	})
	s.queueDojoSync()
}

// mitigationNote is the DefectDojo note of a verified fix, e.g. "Dzięcioł verification:
// Closed: not reachable (scan 1a2b3c4d, 2026-11-22). Service no longer reachable from
// the scanner: port 23/tcp is closed (it may be firewalled rather than removed). This is
// not a confirmed patch."
func mitigationNote(t remediation.Ticket, scanID string, loc *time.Location) string {
	short := scanID
	if len(short) > 8 {
		short = short[:8]
	}
	day := ""
	if t.FixedAt != nil {
		day = ", " + locale.Date(*t.FixedAt, loc)
	}
	reason := strings.TrimSpace(t.LastCheckNote)
	if reason != "" {
		reason = " " + strings.ToUpper(reason[:1]) + reason[1:] + "."
	}
	note := fmt.Sprintf("%s%s (scan %s%s).%s", defectdojo.VerificationNotePrefix, t.FixOutcome(), short, day, reason)
	if t.FixedReason == remediation.FixedServiceRemoved {
		note += " This is not a confirmed patch: the service may only be blocked for the scanner."
	}
	return note
}
