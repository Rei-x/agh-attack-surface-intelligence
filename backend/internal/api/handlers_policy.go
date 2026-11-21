package api

import (
	"context"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/policy"
)

// Zone policies (internal/policy): zones with rules, the violation ledger, and the hooks
// that keep it current (every ingest through the pipeline, every policy edit, startup).

// initPolicy creates the engine, registers it for the asset query language and the ingest
// pipeline, and re-evaluates once in the background (picks up CLI imports and seeded zones).
func (s *Server) initPolicy() {
	s.policy = policy.NewEngine(s.store)
	db.SetPolicyMatcher(s.policy)
	s.pipeline.SetPostIngestHook(func(ctx context.Context, _ *domain.ScanRun) []domain.ChangeEvent {
		events, err := s.policy.Evaluate(ctx)
		if err != nil {
			log.Printf("[WARN] zone policy evaluation: %v", err)
		}
		return events
	})
	go s.reevaluatePolicies(context.Background())
}

func (s *Server) registerPolicyRoutes() {
	mw := s.authMW
	s.handle("GET /api/v1/policies", mw.RequirePerm(domain.PermAssetsRead, s.handleListPolicies))
	s.handle("PUT /api/v1/policies", mw.RequirePerm(domain.PermAssetsWrite, s.handleSavePolicies))
	s.handle("POST /api/v1/policies/evaluate", mw.RequirePerm(domain.PermAssetsWrite, s.handleEvaluatePolicies))
	s.handle("GET /api/v1/policies/violations", mw.RequirePerm(domain.PermAssetsRead, s.handleListViolations))
}

// reevaluatePolicies runs an evaluation outside an ingest, stores the resulting change
// events and sends them to the alert webhook.
func (s *Server) reevaluatePolicies(ctx context.Context) []domain.ChangeEvent {
	events, err := s.policy.Evaluate(ctx)
	if err != nil {
		log.Printf("[WARN] zone policy evaluation: %v", err)
		return nil
	}
	if len(events) == 0 {
		return nil
	}
	recorded := s.policy.RecordEvents(ctx, events, s.hub.Publish)
	if s.notifier != nil && len(recorded) > 0 {
		s.notifier.NotifyChanges(ctx, nil, recorded)
	}
	return recorded
}

func (s *Server) annotatePolicyHosts(hosts []domain.Host) {
	if s.policy != nil {
		s.policy.AnnotateHosts(hosts)
	}
}

func (s *Server) annotatePolicyServices(svcs []domain.Service) {
	if s.policy != nil {
		s.policy.AnnotateServices(svcs)
	}
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	zones, _ := policy.LoadZones(r.Context(), s.store)
	if zones == nil {
		zones = []domain.PolicyZone{}
	}
	st := s.policy.State(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"zones":        zones,
		"presets":      policy.Presets,
		"categories":   policy.Categories,
		"evaluated_at": st.EvaluatedAt,
		"open_count":   s.policy.OpenCount(),
	})
}

// handleSavePolicies replaces the full zone list and re-evaluates the inventory at once,
// so the response already reflects the new rules.
func (s *Server) handleSavePolicies(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.settingsStore(w); !ok {
		return
	}
	var body struct {
		Zones []domain.PolicyZone `json:"zones"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	zones, err := policy.SaveZones(r.Context(), s.store, body.Zones, currentUsername(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	events := s.reevaluatePolicies(r.Context())
	s.auditPolicy(r, "policies.save", map[string]any{"zones": len(zones), "changes": len(events)})
	writeJSON(w, http.StatusOK, map[string]any{
		"zones":      zones,
		"changes":    len(events),
		"open_count": s.policy.OpenCount(),
	})
}

func (s *Server) handleEvaluatePolicies(w http.ResponseWriter, r *http.Request) {
	events := s.reevaluatePolicies(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"changes": len(events), "open_count": s.policy.OpenCount()})
}

type violationGroup struct {
	Key      string         `json:"key"`
	Label    string         `json:"label"`
	Open     int            `json:"open"`
	Severity map[string]int `json:"severity"`
}

// handleListViolations returns the ledger (status=open default, resolved, all) with counts
// per zone, owner and severity.
func (s *Server) handleListViolations(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = domain.PolicyStatusOpen
	}
	st := s.policy.State(r.Context())
	out := make([]domain.PolicyViolation, 0, len(st.Violations))
	bySev := map[string]int{}
	zones := map[string]*violationGroup{}
	owners := map[string]*violationGroup{}
	resolved := 0
	for _, v := range st.Violations {
		if v.Status == domain.PolicyStatusResolved {
			resolved++
		}
		if status != "all" && v.Status != status {
			continue
		}
		out = append(out, v)
		if v.Status != domain.PolicyStatusOpen {
			continue
		}
		bySev[v.Severity]++
		bump(zones, v.ZoneID, v.ZoneName, v.Severity)
		owner := v.Owner
		if owner == "" {
			owner = "No owner"
		}
		bump(owners, owner, owner, v.Severity)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := sevOrder(out[i].Severity), sevOrder(out[j].Severity); a != b {
			return a > b
		}
		if out[i].ZoneName != out[j].ZoneName {
			return out[i].ZoneName < out[j].ZoneName
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"violations":     out,
		"total":          len(out),
		"resolved_count": resolved,
		"by_severity":    bySev,
		"by_zone":        sortedGroups(zones),
		"by_owner":       sortedGroups(owners),
		"evaluated_at":   st.EvaluatedAt,
	})
}

func bump(m map[string]*violationGroup, key, label, sev string) {
	g, ok := m[key]
	if !ok {
		g = &violationGroup{Key: key, Label: label, Severity: map[string]int{}}
		m[key] = g
	}
	g.Open++
	g.Severity[sev]++
}

func sortedGroups(m map[string]*violationGroup) []violationGroup {
	out := make([]violationGroup, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Open != out[j].Open {
			return out[i].Open > out[j].Open
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func sevOrder(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func (s *Server) auditPolicy(r *http.Request, action string, details map[string]any) {
	entry := &domain.AuditLog{
		Action:    action,
		Resource:  "policies",
		Status:    "success",
		Details:   details,
		IPAddress: agenthub.RemoteIP(r),
		CreatedAt: time.Now().UTC(),
	}
	if u := auth.UserFromContext(r.Context()); u != nil {
		entry.UserID, entry.Username, entry.RoleSlug = u.ID, u.Username, u.RoleSlug
	}
	_ = s.store.AddAuditLog(r.Context(), entry)
}
