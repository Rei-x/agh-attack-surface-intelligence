package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/intelligence"
)

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := queryInt(r, "limit", 50)
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	page := queryInt(r, "page", 1)
	if page < 1 {
		page = 1
	}
	if _, err := db.ParseAssetQuery(q.Get("q")); err != nil {
		writeErr(w, http.StatusBadRequest, "query: "+err.Error())
		return
	}
	filter := db.HostFilter{
		Query:    q.Get("q"),
		State:    q.Get("state"),
		Tag:      q.Get("tag"),
		MinScore: queryInt(r, "min_score", 0),
		Env:      q.Get("env"),
		HasAdmin: queryBool(r, "has_admin") || queryBool(r, "admin_only"),
		Page:     page,
		Limit:    limit,
	}
	hosts, total, err := s.store.ListHosts(r.Context(), filter)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	eol.AnnotateHosts(hosts, time.Now().UTC())
	s.annotatePolicyHosts(hosts)
	totalPages := (total + limit - 1) / limit
	if totalPages < 1 {
		totalPages = 1
	}
	var body any = hosts
	if q.Get("fields") == "summary" {
		body = summarizeHosts(hosts)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts":       body,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	})
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host, err := s.store.GetHost(ctx, r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if len(host.TimeOfDayStats) > 0 {
		// Bayesian liveness is derived from persisted slot posteriors; evaluate at read time.
		l := intelligence.EstimateLiveness(*host, time.Now().UTC(), intelligence.LifecycleConfig{})
		host.Liveness = &l
	}
	eol.AnnotateServices(host.Services, time.Now().UTC())
	s.annotatePolicyServices(host.Services)
	allChanges, _ := s.store.ListChangeEvents(ctx, db.ChangeFilter{HostID: host.ID, Limit: 20})
	hostChanges := make([]domain.ChangeEvent, 0)
	for _, ev := range allChanges {
		if ev.HostID == host.ID {
			hostChanges = append(hostChanges, ev)
			if len(hostChanges) >= 20 {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, struct {
		*domain.Host
		RecentChanges []domain.ChangeEvent `json:"recent_changes"`
	}{
		Host:          host,
		RecentChanges: hostChanges,
	})
}

func (s *Server) handlePatchHostOverrides(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if _, err := s.store.GetHost(ctx, id); err != nil {
		writeStoreErr(w, err)
		return
	}

	var body map[string]any
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	var unlock []string
	if rawUnlock, ok := body["unlock_fields"].([]any); ok {
		for _, u := range rawUnlock {
			if s, ok := u.(string); ok {
				unlock = append(unlock, s)
			}
		}
	}
	patch := make(map[string]any)
	for k, v := range body {
		if db.AllowedHostOverrideFields[k] {
			patch[k] = v
		}
	}
	if err := applyTriagePatch(body, patch, &unlock, currentUsername(r), false, time.Now()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.PatchOverrides(ctx, "host", id, patch, unlock, currentUsername(r)); err != nil {
		writeStoreErr(w, err)
		return
	}
	// Triage decisions are mirrored to DefectDojo shortly after (debounced).
	s.queueDojoSync()
	updated, err := s.store.GetHost(ctx, id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteHost(r.Context(), r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if _, err := db.ParseAssetQuery(q.Get("q")); err != nil {
		writeErr(w, http.StatusBadRequest, "query: "+err.Error())
		return
	}
	filter := db.ServiceFilter{
		HostID:   q.Get("host_id"),
		Query:    q.Get("q"),
		Port:     queryInt(r, "port", 0),
		Tag:      q.Get("tag"),
		MinScore: queryInt(r, "min_score", 0),
		HasAdmin: queryBool(r, "has_admin") || queryBool(r, "admin_only"),
		State:    q.Get("state"),
	}
	svcs, err := s.store.ListServices(r.Context(), filter)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	triage := strings.TrimSpace(q.Get("triage_status"))
	if triage != "" {
		filtered := make([]domain.Service, 0, len(svcs))
		for _, svc := range svcs {
			if strings.EqualFold(svc.TriageStatus, triage) {
				filtered = append(filtered, svc)
			}
		}
		svcs = filtered
	}
	eol.AnnotateServices(svcs, time.Now().UTC())
	s.annotatePolicyServices(svcs)
	writeJSON(w, http.StatusOK, map[string]any{"services": svcs, "total": len(svcs)})
}

func (s *Server) handlePatchServiceOverrides(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if _, err := s.store.GetService(ctx, id); err != nil {
		writeStoreErr(w, err)
		return
	}

	var body map[string]any
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	var unlock []string
	if rawUnlock, ok := body["unlock_fields"].([]any); ok {
		for _, u := range rawUnlock {
			if s, ok := u.(string); ok {
				unlock = append(unlock, s)
			}
		}
	}
	patch := make(map[string]any)
	for k, v := range body {
		if db.AllowedServiceOverrideFields[k] {
			patch[k] = v
		}
	}
	if err := applyTriagePatch(body, patch, &unlock, currentUsername(r), true, time.Now()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.PatchOverrides(ctx, "service", id, patch, unlock, currentUsername(r)); err != nil {
		writeStoreErr(w, err)
		return
	}
	// Triage decisions are mirrored to DefectDojo shortly after (debounced).
	s.queueDojoSync()
	updated, err := s.store.GetService(ctx, id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleServiceObservations(w http.ResponseWriter, r *http.Request) {
	obs, err := s.store.ListServiceObservations(r.Context(), r.PathValue("id"), queryInt(r, "limit", 50))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"observations": obs})
}

func (s *Server) handleListChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	events, err := s.store.ListChangeEvents(r.Context(), db.ChangeFilter{
		ScanRunID:   q.Get("scan_id"),
		Severity:    q.Get("severity"),
		EventType:   q.Get("type"),
		AnomalyOnly: queryBool(r, "anomaly_only"),
		Limit:       queryInt(r, "limit", 200),
	})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	s.withOwners(r.Context(), events)
	writeJSON(w, http.StatusOK, map[string]any{"changes": events})
}

func (s *Server) handleAcknowledgeChange(w http.ResponseWriter, r *http.Request) {
	ev, err := s.store.AcknowledgeChange(r.Context(), r.PathValue("id"), currentUsername(r))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}
