package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, _, err := s.store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	runs, _ := s.store.ListScanRuns(ctx, 20)
	changes, _ := s.store.ListChangeEvents(ctx, db.ChangeFilter{Limit: 25})
	profiles, _ := s.store.ListProfiles(ctx)

	scopeIPs := 0
	for _, p := range profiles {
		if p.Enabled {
			for _, t := range p.Targets {
				scopeIPs += countTargetIPs(t)
			}
		}
	}
	if scopeIPs == 0 {
		scopeIPs = len(hosts)
	}

	breakdown := map[string]int{
		domain.HostStateNew:          0,
		domain.HostStateActive:       0,
		domain.HostStateIntermittent: 0,
		domain.HostStateMissing:      0,
		domain.HostStateInactive:     0,
		domain.HostStateReactivated:  0,
	}
	activeHosts := 0
	unstableHosts := 0
	totalServices := 0
	interestingCount := 0
	allServices := make([]domain.Service, 0)

	for _, h := range hosts {
		breakdown[h.LifecycleState]++
		if h.LifecycleState == domain.HostStateNew || h.LifecycleState == domain.HostStateActive || h.LifecycleState == domain.HostStateReactivated {
			activeHosts++
		}
		if h.LifecycleState == domain.HostStateIntermittent || h.LifecycleState == domain.HostStateMissing {
			unstableHosts++
		}
		totalServices += len(h.Services)
		for _, svc := range h.Services {
			if svc.Interestingness >= 50 {
				interestingCount++
			}
			allServices = append(allServices, svc)
		}
	}

	sort.Slice(allServices, func(i, j int) bool {
		return allServices[i].Interestingness > allServices[j].Interestingness
	})
	topFindings := allServices
	if len(topFindings) > 10 {
		topFindings = topFindings[:10]
	}

	var activeScan *domain.ScanRun
	changesLastScan := 0
	for i := range runs {
		if runs[i].Status == domain.ScanStatusRunning || runs[i].Status == domain.ScanStatusCalibrating || runs[i].Status == domain.ScanStatusPausedWindow || runs[i].Status == domain.ScanStatusPausedUser {
			cp := runs[i]
			activeScan = &cp
			break
		}
	}
	if len(runs) > 0 {
		changesLastScan = runs[0].ChangesDetected
	}

	// Timeline points oldest -> newest
	timeline := make([]map[string]any, 0, len(runs))
	for i := len(runs) - 1; i >= 0; i-- {
		run := runs[i]
		timeline = append(timeline, map[string]any{
			"scan_id":          run.ID,
			"name":             run.Name,
			"label":            run.StartedAt.Format("01-02 15:04"),
			"started_at":       run.StartedAt,
			"timestamp":        run.StartedAt,
			"active_hosts":     run.ActiveHosts,
			"services_found":   run.ServicesFound,
			"services":         run.ServicesFound,
			"changes_detected": run.ChangesDetected,
			"changes":          run.ChangesDetected,
		})
	}

	kpis := map[string]any{
		"total_ips":            scopeIPs,
		"scope_ips":            scopeIPs,
		"total_hosts":          len(hosts),
		"active_hosts":         activeHosts,
		"unstable_hosts":       unstableHosts,
		"total_services":       totalServices,
		"services_found":       totalServices,
		"recent_changes":       len(changes),
		"changes_last_scan":    changesLastScan,
		"interesting_findings": interestingCount,
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"kpis":                       kpis,
		"total_ips":                  scopeIPs,
		"scope_ips":                  scopeIPs,
		"total_hosts":                len(hosts),
		"active_hosts":               activeHosts,
		"unstable_hosts":             unstableHosts,
		"total_services":             totalServices,
		"services_found":             totalServices,
		"recent_changes_count":       len(changes),
		"changes_last_scan":          changesLastScan,
		"interesting_findings_count": interestingCount,
		"active_scan":                activeScan,
		"timeline":                   timeline,
		"top_findings":               topFindings,
		"top_interesting":            topFindings,
		"lifecycle_breakdown":        breakdown,
		"recent_changes":             changes,
	})
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, _, err := s.store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	targets, _ := s.store.ListTargets(ctx)
	filter := GraphFilter{
		State:       r.URL.Query().Get("state"),
		MinScore:    queryInt(r, "min_score", 0),
		AdminOnly:   queryBool(r, "admin_only") || queryBool(r, "has_admin"),
		StagingOnly: queryBool(r, "staging_only"),
	}
	writeJSON(w, http.StatusOK, BuildGraph(hosts, targets, filter))
}

func (s *Server) handleClusters(w http.ResponseWriter, r *http.Request) {
	hosts, _, err := s.store.ListHosts(r.Context(), db.HostFilter{})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	clusters := s.pipeline.Analyzer().ComputeClusters(hosts)
	groupBy := strings.TrimSpace(r.URL.Query().Get("group_by"))
	if groupBy != "" {
		filtered := make([]domain.ServiceCluster, 0, len(clusters))
		for _, c := range clusters {
			if strings.EqualFold(c.GroupBy, groupBy) {
				filtered = append(filtered, c)
			}
		}
		clusters = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"clusters": clusters})
}
