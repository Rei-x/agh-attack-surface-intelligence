package api

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
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
func (s *Server) reflectFixInDefectDojo(ctx context.Context, t remediation.Ticket, scanID string) {
	cfg, err := db.LoadDefectDojoConfig(ctx, s.store)
	if err != nil || cfg == nil || strings.TrimSpace(cfg.URL) == "" || !cfg.HasAPIToken {
		return
	}
	details := map[string]any{"ticket_id": t.ID, "scan_run_id": scanID, "unique_id_from_tool": t.DefectDojoUniqueID}
	// Name the linked DefectDojo finding(s) from the last sync, when there are any.
	if t.ServiceID != "" {
		var ids []int
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
	log.Printf("[INFO] remediation: ticket %s verified fixed by scan %s; DefectDojo: %s", t.ID, scanID, mode)
	s.auditFromContext(ctx, &domain.AuditLog{
		Username: remediation.SystemUser, Action: "remediation.defectdojo_mitigate", Resource: "defectdojo",
		ResourceID: t.DefectDojoUniqueID, Status: "success", CreatedAt: time.Now().UTC(), Details: details,
	})
	s.queueDojoSync()
}
