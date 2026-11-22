package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// --- Targets & Exclusions ---

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListTargets(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": items})
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var t domain.Target
	if err := decodeJSON(r, &t); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	t.Value = strings.TrimSpace(t.Value)
	if t.Value == "" {
		writeErr(w, http.StatusBadRequest, "target value is required")
		return
	}
	kind, err := scanner.ValidateTargetEntry(t.Value, scanner.DefaultMaxExpandedIPs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	t.Value = strings.TrimSpace(t.Value)
	if t.Kind == "" {
		t.Kind = kind
		if kind == "ipv6" { // UI knows ip / cidr / range / domain
			t.Kind = "ip"
			if strings.Contains(t.Value, "/") {
				t.Kind = "cidr"
			}
		}
	}
	if len(t.Label) > maxNameLen {
		writeErr(w, http.StatusBadRequest, "label too long")
		return
	}
	t.Enabled = true
	t.CreatedBy = currentUsername(r)
	if err := s.store.CreateTarget(r.Context(), &t); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteTarget(r.Context(), r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEstimateTargets(w http.ResponseWriter, r *http.Request) {
	var raw struct {
		EstimateRequest
		AllowedPorts string `json:"allowed_ports"`
	}
	if err := decodeJSON(r, &raw); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req := raw.EstimateRequest
	if req.Ports == "" && raw.AllowedPorts != "" {
		req.Ports = raw.AllowedPorts
	}
	// Merge stored exclusions if caller didn't supply explicit exclusions
	if len(req.Exclusions) == 0 {
		if exList, err := s.store.ListExclusions(r.Context()); err == nil {
			for _, ex := range exList {
				req.Exclusions = append(req.Exclusions, ex.Value)
			}
		}
	}
	est, err := s.runner.EstimateTargets(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, est)
}

func (s *Server) handleListExclusions(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListExclusions(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exclusions": items})
}

func (s *Server) handleCreateExclusion(w http.ResponseWriter, r *http.Request) {
	var ex domain.TargetExclusion
	if err := decodeJSON(r, &ex); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ex.Value = strings.TrimSpace(ex.Value)
	if ex.Value == "" {
		writeErr(w, http.StatusBadRequest, "exclusion value is required")
		return
	}
	// No size cap for exclusions (excluding a whole /8 is legitimate), but a typo must not be
	// silently ignored: an unparsable exclusion would leave hosts in scope.
	if _, err := scanner.ValidateTargetEntry(ex.Value, 0); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(ex.Reason) > maxNotesLen {
		writeErr(w, http.StatusBadRequest, "reason too long")
		return
	}
	ex.CreatedBy = currentUsername(r)
	if err := s.store.CreateExclusion(r.Context(), &ex); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, ex)
}

func (s *Server) handleDeleteExclusion(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteExclusion(r.Context(), r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Profiles ---

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListProfiles(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": s.withSchedules(r, items)})
}

func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var p domain.ScanProfile
	if err := decodeJSON(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(p.Name) == "" {
		writeErr(w, http.StatusBadRequest, "profile name is required")
		return
	}
	if err := validateScanParams(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	applyProfileDefaults(&p)
	if err := validateProfileSchedule(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := s.validateProfileAgent(r.Context(), &p); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.store.CreateProfile(r.Context(), &p); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.withSchedules(r, []domain.ScanProfile{p})[0])
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	var p domain.ScanProfile
	if err := decodeJSON(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p.ID = r.PathValue("id")
	if err := validateScanParams(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	applyProfileDefaults(&p)
	if err := validateProfileSchedule(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := s.validateProfileAgent(r.Context(), &p); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.store.UpdateProfile(r.Context(), &p); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.withSchedules(r, []domain.ScanProfile{p})[0])
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteProfile(r.Context(), r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Scan Runs ---

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListScanRuns(r.Context(), queryInt(r, "limit", 100))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	for i := range items {
		if i >= 100 {
			break
		}
		items[i].Telemetry = loadRunTelemetry(r.Context(), s.store, items[i].ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": items})
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetScanRun(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	run.Telemetry = loadRunTelemetry(r.Context(), s.store, run.ID)
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProfileID        string   `json:"profile_id"`
		Name             string   `json:"name"`
		Notes            string   `json:"notes"`
		Targets          []string `json:"targets"`
		AllowedPorts     string   `json:"allowed_ports"`
		MaxRatePPS       int      `json:"max_rate_pps"`
		HTTPRPS          int      `json:"http_rps"`
		Concurrency      int      `json:"concurrency"`
		ChunkTargetSec   int      `json:"chunk_target_sec"`
		WindowEnabled    bool     `json:"window_enabled"`
		WindowStart      string   `json:"window_start"`
		WindowEnd        string   `json:"window_end"`
		Timezone         string   `json:"timezone"`
		MissingThreshold int      `json:"missing_threshold"`
		GracePeriodHours int      `json:"grace_period_hours"`
		SaveProfile      bool     `json:"save_profile"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	if req.ProfileID != "" {
		// Saved profiles always start through the scheduler so a profile can never run
		// twice concurrently, whichever endpoint the client uses (same as /profiles/{id}/run).
		r.SetPathValue("id", req.ProfileID)
		s.handleRunProfileNow(w, r)
		return
	}
	profile := &domain.ScanProfile{
		Name:                  nonEmptyStr(req.Name, "Quick scan "+time.Now().UTC().Format("15:04")),
		Targets:               req.Targets,
		AllowedPorts:          req.AllowedPorts,
		MaxRatePPS:            req.MaxRatePPS,
		HTTPRPS:               req.HTTPRPS,
		Concurrency:           req.Concurrency,
		ChunkTargetSec:        req.ChunkTargetSec,
		WindowEnabled:         req.WindowEnabled,
		WindowStart:           req.WindowStart,
		WindowEnd:             req.WindowEnd,
		Timezone:              req.Timezone,
		MissingThreshold:      req.MissingThreshold,
		GracePeriodHours:      req.GracePeriodHours,
		EnableHTTPFingerprint: true,
		Enabled:               true,
	}
	if err := validateScanParams(profile); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Notes) > maxNotesLen {
		writeErr(w, http.StatusBadRequest, "notes too long")
		return
	}
	exclusions, _ := s.store.ListExclusions(r.Context())
	if res, err := scanner.ParseAndNormalizeTargets(r.Context(), profile.Targets, exclusions, nil); err == nil {
		if len(res.IPs) == 0 && res.ExcludedCount > 0 {
			writeErr(w, http.StatusBadRequest, "every target is covered by an exclusion (Scans, Scope tab); remove the exclusion to scan it")
			return
		}
		// Auto ports on a tiny scope scan all 65535 ports: raise the default rate so a
		// single-host scan finishes in seconds (only when the caller did not set a rate).
		if req.MaxRatePPS <= 0 && scanner.IsAutoPorts(profile.AllowedPorts) && len(res.IPs) <= scanner.AutoFullRangeMaxIPs {
			profile.MaxRatePPS = scanner.AutoFullRangeRatePPS
		}
	}
	applyProfileDefaults(profile)
	if req.WindowEnabled {
		if err := validateProfileSchedule(profile); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// Persist ad-hoc profile when windowing or save_profile is enabled so Pause/Resume works seamlessly.
	if req.SaveProfile || req.WindowEnabled {
		_ = s.store.CreateProfile(r.Context(), profile)
	}
	if len(profile.Targets) == 0 {
		writeErr(w, http.StatusBadRequest, "no targets specified in profile or request")
		return
	}

	run := &domain.ScanRun{
		ID:          db.NewID(),
		ProfileID:   profile.ID,
		Name:        nonEmptyStr(req.Name, profile.Name+" "+time.Now().UTC().Format("2006-01-02 15:04")),
		RunType:     domain.ScanTypeActive,
		Status:      domain.ScanStatusQueued,
		Notes:       req.Notes,
		TriggeredBy: currentUsername(r),
		StartedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateScanRun(r.Context(), run); err != nil {
		writeStoreErr(w, err)
		return
	}

	bgCtx := context.Background()
	// The runner mutates the run it is given while this handler encodes the response: give the
	// background goroutine its own copy (was a data race).
	bgRun := *run
	go func() {
		if err := s.runner.StartScan(bgCtx, &bgRun, profile, exclusions); err != nil {
			now := time.Now().UTC()
			bgRun.Status = domain.ScanStatusFailed
			bgRun.FinishedAt = &now
			_ = s.store.UpdateScanRun(bgCtx, &bgRun)
		}
	}()

	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) handleUpdateScanMeta(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Notes string `json:"notes"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	updated, err := s.store.UpdateScanRunMeta(r.Context(), r.PathValue("id"), req.Name, req.Notes)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handlePauseScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.runner.PauseScan(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	run, err := s.store.GetScanRun(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleResumeScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.runner.ResumeScan(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	run, err := s.store.GetScanRun(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleStopScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.runner.StopScan(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	run, err := s.store.GetScanRun(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	// Stop a still-running scan first so its worker does not keep scanning (and writing) a
	// deleted run. Errors (already finished, not found) are irrelevant here.
	_ = s.runner.StopScan(r.Context(), r.PathValue("id"))
	if err := s.store.DeleteScanRun(r.Context(), r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleScanDiff(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fromID := strings.TrimSpace(r.URL.Query().Get("from"))
	toID := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromID == "" || toID == "" {
		writeErr(w, http.StatusBadRequest, "from and to scan IDs are required")
		return
	}
	fromHosts, err := s.store.GetScanSnapshot(ctx, fromID)
	if err != nil {
		fromHosts = []domain.Host{}
	}
	toHosts, err := s.store.GetScanSnapshot(ctx, toID)
	if err != nil {
		toHosts, _, _ = s.store.ListHosts(ctx, db.HostFilter{})
	}
	toChanges, _ := s.store.ListChangeEvents(ctx, db.ChangeFilter{ScanRunID: toID, Limit: 500})
	diff := ComputeScanDiff(fromID, toID, fromHosts, toHosts, toChanges)
	writeJSON(w, http.StatusOK, diff)
}

func applyProfileDefaults(p *domain.ScanProfile) {
	if scanner.IsAutoPorts(p.AllowedPorts) {
		p.AllowedPorts = scanner.AutoPortsKeyword
	}
	if p.MaxRatePPS <= 0 {
		p.MaxRatePPS = 500
	}
	if p.HTTPRPS <= 0 {
		p.HTTPRPS = 25
	}
	if p.Concurrency <= 0 {
		p.Concurrency = 32
	}
	if p.ChunkTargetSec <= 0 {
		p.ChunkTargetSec = 60
	}
	if p.Timezone == "" {
		p.Timezone = "Europe/Warsaw"
	}
	if p.MissingThreshold <= 0 {
		p.MissingThreshold = 2
	}
	if p.GracePeriodHours <= 0 {
		p.GracePeriodHours = 24
	}
	if p.UserAgent == "" {
		p.UserAgent = "Dzieciol-CBI-AGH/1.0"
	}
}

func nonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return b
}
