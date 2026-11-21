package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/verify"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb"
)

// Vulnerability intelligence (internal/vulndb) and safe verification (internal/verify).
//
//	GET  /api/v1/vulndb                     snapshot info (date, sources, counts)
//	GET  /api/v1/verify/checks              the check catalog with YAML source
//	GET  /api/v1/verify/profiles            per-profile opt-in + last run
//	PUT  /api/v1/verify/profiles/{id}       {enabled, default_creds}
//	GET  /api/v1/verify/hosts/{id}          profiles that may verify this host
//	POST /api/v1/verify/run                 {profile_id, host_id}: host = synchronous, profile = background

func (s *Server) verifier() *verify.Service { return s.verify }

func (s *Server) initVerify() {
	v, err := verify.NewService(s.store)
	if err != nil {
		log.Printf("[WARN] verification checks failed to load: %v", err)
		return
	}
	v.Audit = s.auditFromContext
	v.Publish = s.hub.Publish
	v.OnRecorded = s.queueDojoSync // verified evidence reaches the DefectDojo change findings
	verify.Activate(v)
	s.verify = v
	go s.watchScansForVerify(v)
}

// watchScansForVerify runs Verify after every completed scan of an opted-in profile.
func (s *Server) watchScansForVerify(v *verify.Service) {
	events := s.hub.Subscribe()
	work := make(chan string, 32)
	go func() {
		for id := range work {
			s.verifyAfterScan(v, id)
		}
	}()
	for ev := range events {
		if ev.Type != "scan.completed" || ev.ScanRunID == "" {
			continue
		}
		select {
		case work <- ev.ScanRunID:
		default:
			log.Printf("[WARN] verify: queue full, skipped scan %s", ev.ScanRunID)
		}
	}
}

func (s *Server) verifyAfterScan(v *verify.Service, runID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		run, err := s.store.GetScanRun(ctx, runID)
		if err == nil && run != nil {
			switch run.Status {
			case domain.ScanStatusCompleted:
				if !v.Results.Profile(run.ProfileID).Enabled {
					return
				}
				v.AfterScan(ctx, run)
				return
			case domain.ScanStatusFailed, domain.ScanStatusStopped:
				return
			}
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Second)
	}
}

func (s *Server) registerVerifyRoutes() {
	mw := s.authMW
	s.handle("GET /api/v1/vulndb", mw.RequirePerm(domain.PermAssetsRead, s.handleVulnDBInfo))
	s.handle("GET /api/v1/verify/checks", mw.RequirePerm(domain.PermScansRead, s.handleVerifyChecks))
	s.handle("GET /api/v1/verify/profiles", mw.RequirePerm(domain.PermScansRead, s.handleVerifyProfiles))
	s.handle("PUT /api/v1/verify/profiles/{id}", mw.RequirePerm(domain.PermScansWrite, s.handleSaveVerifyProfile))
	s.handle("GET /api/v1/verify/hosts/{id}", mw.RequirePerm(domain.PermAssetsRead, s.handleVerifyHostScope))
	s.handle("POST /api/v1/verify/run", mw.RequirePerm(domain.PermScansRun, s.handleVerifyRun))
}

func (s *Server) handleVulnDBInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, vulndb.Current().Info())
}

type checkView struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Severity    string         `json:"severity"`
	Kind        string         `json:"kind"`
	Requires    string         `json:"requires,omitempty"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	References  []string       `json:"references,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Match       verify.Applies `json:"match"`
	Source      string         `json:"source"`
	YAML        string         `json:"yaml"`
}

func (s *Server) handleVerifyChecks(w http.ResponseWriter, r *http.Request) {
	v := s.verifier()
	if v == nil {
		writeErr(w, http.StatusServiceUnavailable, "verification is unavailable")
		return
	}
	out := make([]checkView, 0, len(v.Checks))
	for _, c := range v.Checks {
		src, _ := verify.ReadCheckSource(c.Source)
		out = append(out, checkView{
			ID: c.ID, Name: c.Info.Name, Severity: c.Info.Severity, Kind: c.Kind(), Requires: c.Requires,
			Description: c.Info.Description, Remediation: c.Info.Remediation, References: c.Info.Reference, Tags: c.Info.Tags,
			Match: c.Match, Source: c.Source, YAML: src,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type verifyProfileView struct {
	ProfileID   string               `json:"profile_id"`
	ProfileName string               `json:"profile_name"`
	Config      verify.ProfileConfig `json:"config"`
	LastRun     *verify.RunSummary   `json:"last_run,omitempty"`
	RemoteAgent bool                 `json:"remote_agent,omitempty"`
}

func (s *Server) verifyProfileViews(ctx context.Context, v *verify.Service) ([]verifyProfileView, error) {
	profiles, err := s.store.ListProfiles(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]verifyProfileView, 0, len(profiles))
	for _, p := range profiles {
		pv := verifyProfileView{ProfileID: p.ID, ProfileName: p.Name, Config: v.Results.Profile(p.ID), RemoteAgent: p.AgentID != ""}
		if last, ok := v.Results.LastRun(p.ID); ok {
			pv.LastRun = &last
		}
		out = append(out, pv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileName < out[j].ProfileName })
	return out, nil
}

func (s *Server) handleVerifyProfiles(w http.ResponseWriter, r *http.Request) {
	v := s.verifier()
	if v == nil {
		writeErr(w, http.StatusServiceUnavailable, "verification is unavailable")
		return
	}
	out, err := s.verifyProfileViews(r.Context(), v)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSaveVerifyProfile(w http.ResponseWriter, r *http.Request) {
	v := s.verifier()
	if v == nil {
		writeErr(w, http.StatusServiceUnavailable, "verification is unavailable")
		return
	}
	id := r.PathValue("id")
	p, err := s.store.GetProfile(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var body struct {
		Enabled      bool `json:"enabled"`
		DefaultCreds bool `json:"default_creds"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	prev := v.Results.Profile(id)
	cfg := verify.ProfileConfig{Enabled: body.Enabled, DefaultCreds: body.Enabled && body.DefaultCreds, UpdatedBy: currentUsername(r), UpdatedAt: time.Now().UTC()}
	if err := v.Results.SetProfile(r.Context(), id, cfg); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.auditFromContext(r.Context(), &domain.AuditLog{
		Action: "verify.config", Resource: "scan_profile", ResourceID: id, Status: "success",
		Details: map[string]any{"profile": p.Name, "enabled": cfg.Enabled, "default_creds": cfg.DefaultCreds, "was_enabled": prev.Enabled, "was_default_creds": prev.DefaultCreds},
	})
	writeJSON(w, http.StatusOK, verifyProfileView{ProfileID: id, ProfileName: p.Name, Config: cfg})
}

// handleVerifyHostScope lists the profiles whose targets cover the host, with their opt-in.
func (s *Server) handleVerifyHostScope(w http.ResponseWriter, r *http.Request) {
	v := s.verifier()
	if v == nil {
		writeErr(w, http.StatusServiceUnavailable, "verification is unavailable")
		return
	}
	h, err := s.store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	views, err := s.verifyProfileViews(r.Context(), v)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	out := []verifyProfileView{}
	for _, pv := range views {
		p, err := s.store.GetProfile(r.Context(), pv.ProfileID)
		if err != nil {
			continue
		}
		in, err := v.Scope(r.Context(), p)
		if err == nil && in(h.IP) {
			out = append(out, pv)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"host_id": h.ID, "ip": h.IP, "profiles": out, "checks": len(v.Checks)})
}

func (s *Server) handleVerifyRun(w http.ResponseWriter, r *http.Request) {
	v := s.verifier()
	if v == nil {
		writeErr(w, http.StatusServiceUnavailable, "verification is unavailable")
		return
	}
	var body struct {
		ProfileID string `json:"profile_id"`
		HostID    string `json:"host_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	body.ProfileID, body.HostID = strings.TrimSpace(body.ProfileID), strings.TrimSpace(body.HostID)
	if body.ProfileID == "" && body.HostID != "" {
		// Pick the first opted-in profile that covers the host.
		h, err := s.store.GetHost(r.Context(), body.HostID)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		profiles, _ := s.store.ListProfiles(r.Context())
		for i := range profiles {
			if !v.Results.Profile(profiles[i].ID).Enabled {
				continue
			}
			if in, err := v.Scope(r.Context(), &profiles[i]); err == nil && in(h.IP) {
				body.ProfileID = profiles[i].ID
				break
			}
		}
		if body.ProfileID == "" {
			writeErr(w, http.StatusConflict, "no profile with Verify enabled covers this host")
			return
		}
	}
	if body.ProfileID == "" {
		writeErr(w, http.StatusBadRequest, "profile_id or host_id is required")
		return
	}
	if !v.Results.Profile(body.ProfileID).Enabled {
		writeErr(w, http.StatusConflict, verify.ErrDisabled.Error())
		return
	}
	user := currentUsername(r)
	if body.HostID != "" {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Minute)
		defer cancel()
		sum, err := v.RunProfile(ctx, body.ProfileID, body.HostID, "", "manual:"+user)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, verify.ErrDisabled) || errors.Is(err, verify.ErrRunning) {
				status = http.StatusConflict
			}
			writeErr(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, sum)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Minute)
		defer cancel()
		if _, err := v.RunProfile(ctx, body.ProfileID, "", "", "manual:"+user); err != nil {
			log.Printf("[WARN] verify run for profile %s: %v", body.ProfileID, err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "started", "profile_id": body.ProfileID})
}
