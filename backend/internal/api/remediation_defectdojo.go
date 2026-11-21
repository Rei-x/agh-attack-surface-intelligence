package api

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/remediation"
)

// reflectFixInDefectDojo is the hook point between a scan-verified fix and DefectDojo.
//
// Today the DefectDojo side closes the item on its own: the auto-push reimport of the
// "Dzięcioł changes" test runs with close_old_findings, so a finding whose condition is
// gone (port closed, version upgraded, panel removed) is mitigated with the reimport date.
// The ticket carries the finding's unique_id_from_tool (DefectDojoUniqueID) so a direct
// triage sync can target it.
//
// TODO(defectdojo-sync): when the DefectDojo triage sync lands, look up the finding by
// t.DefectDojoUniqueID and mark it mitigated (is_mitigated=true, active=false,
// mitigated=now) with a note "Verified fixed by Dzięcioł scan <scanID>: <reason>".
func (s *Server) reflectFixInDefectDojo(ctx context.Context, t remediation.Ticket, scanID string) {
	cfg, err := s.store.GetDefectDojoConfig(ctx)
	if err != nil || cfg == nil || strings.TrimSpace(cfg.URL) == "" || t.DefectDojoUniqueID == "" {
		return
	}
	log.Printf("[INFO] remediation: ticket %s verified fixed by scan %s; DefectDojo finding %s is mitigated by the next changes reimport",
		t.ID, scanID, t.DefectDojoUniqueID)
	s.auditFromContext(ctx, &domain.AuditLog{
		Username: remediation.SystemUser, Action: "remediation.defectdojo_mitigate", Resource: "defectdojo",
		ResourceID: t.DefectDojoUniqueID, Status: "success", CreatedAt: time.Now().UTC(),
		Details: map[string]any{"ticket_id": t.ID, "scan_run_id": scanID, "mode": "reimport close_old_findings"},
	})
}
