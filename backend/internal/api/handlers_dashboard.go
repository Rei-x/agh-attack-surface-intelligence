package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
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
	// Triage: accepted-risk / false-positive findings are left out of "most important
	// findings"; expired acceptances are listed so they get re-reviewed.
	now := time.Now()
	acceptedCount := 0
	expiredAcceptances := make([]map[string]any, 0)
	noteExpired := func(h *domain.Host, svc *domain.Service, t *domain.TriageInfo) {
		item := map[string]any{"host_id": h.ID, "host_ip": h.IP, "triage": t}
		if svc != nil {
			item["service_id"], item["port"], item["service_name"] = svc.ID, svc.Port, svc.ServiceName
		}
		expiredAcceptances = append(expiredAcceptances, item)
	}

	for _, h := range hosts {
		breakdown[h.LifecycleState]++
		if h.LifecycleState == domain.HostStateNew || h.LifecycleState == domain.HostStateActive || h.LifecycleState == domain.HostStateReactivated {
			activeHosts++
		}
		if h.LifecycleState == domain.HostStateIntermittent || h.LifecycleState == domain.HostStateMissing {
			unstableHosts++
		}
		totalServices += len(h.Services)
		hostSuppressed := h.Triage.IsSuppressing(now)
		if hostSuppressed {
			acceptedCount++
		} else if h.Triage != nil && h.Triage.Expired {
			noteExpired(&h, nil, h.Triage)
		}
		for _, svc := range h.Services {
			if svc.Triage.IsSuppressing(now) {
				acceptedCount++
				continue
			}
			if svc.Triage != nil && svc.Triage.Expired {
				noteExpired(&h, &svc, svc.Triage)
			}
			if hostSuppressed {
				continue
			}
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
	eol.AnnotateServices(topFindings, now)

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
		"accepted_risk_count":        acceptedCount,
		"expired_acceptances":        expiredAcceptances,
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
	q := r.URL.Query()
	filter := GraphFilter{
		State:          q.Get("state"),
		MinScore:       queryInt(r, "min_score", 0),
		AdminOnly:      queryBool(r, "admin_only") || queryBool(r, "has_admin"),
		StagingOnly:    queryBool(r, "staging_only"),
		AdminOrStaging: queryBool(r, "admin_or_staging"),
		Subnet:         q.Get("subnet"),
		Block:          q.Get("block"),
		Query:          q.Get("q"),
		Mode:           q.Get("mode"),
		Limit:          queryInt(r, "limit", 50),
	}
	writeJSON(w, http.StatusOK, BuildGraph(hosts, targets, filter))
}

func (s *Server) handleClusters(w http.ResponseWriter, r *http.Request) {
	hosts, _, err := s.store.ListHosts(r.Context(), db.HostFilter{})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	groupBy, ok := normalizeClusterGroupBy(r.URL.Query().Get("group_by"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid group_by: use one of favicon, http_title, tech_stack (alias: tech), service_product (alias: product)")
		return
	}
	clusters := s.pipeline.Analyzer().ComputeClusters(hosts)
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

// normalizeClusterGroupBy maps a group_by query value (with short aliases) to a cluster
// GroupBy key. An unknown value is rejected instead of silently returning no clusters.
func normalizeClusterGroupBy(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return "", true
	case "favicon", "favicon_mmh3":
		return "favicon", true
	case "http_title", "title":
		return "http_title", true
	case "tech_stack", "tech", "technology", "technologies":
		return "tech_stack", true
	case "service_product", "product", "service":
		return "service_product", true
	}
	return "", false
}
