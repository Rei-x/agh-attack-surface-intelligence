package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/selfdist"
)

// Quick scan: the one-step flows behind the "Quick scan" button.
//
//	GET  /api/v1/quickscan        what the dialog can offer: the lab option, the server URL
//	                              for agent commands, the platforms this server hands out
//	POST /api/v1/quickscan/lab    start a fast scan of the lab network, or join the one running
//	POST /api/v1/quickscan/agent  scan one network of an agent's host with conservative settings
//
// Both scans use small chunks, so hosts reach the live view block by block instead of all at
// the end. Rates, ports, windows and the agent's own allowlist stay as configured.

const (
	// quickLabMaxIPs caps the lab quick scan: a wider lab profile scans its first /22.
	quickLabMaxIPs = 1024
	// quickChunkTargetSec asks the chunk planner for the smallest chunks (32 to 64 IPs), so
	// the first ones finish within a minute.
	quickChunkTargetSec = 2
	// quickAgentMaxIPs caps a quick scan through an agent (a /20).
	quickAgentMaxIPs = 4096
	// Conservative defaults for an agent on a network nobody here knows (a home or office
	// LAN): about two minutes for a /24 on the compact port list.
	quickAgentRatePPS     = 150
	quickAgentHTTPRPS     = 5
	quickAgentConcurrency = 8
)

// quickState remembers the lab quick scan, so a second click joins it.
type quickState struct {
	startMu  sync.Mutex // serializes lab starts: two clicks at once start one scan
	mu       sync.Mutex
	labRunID string
}

func (s *Server) registerQuickScanRoutes() {
	mw := s.authMW
	s.handle("GET /install.sh", s.handleInstallScript)
	s.handle("GET /download/{file}", s.handleDownload)
	s.handle("GET /api/v1/quickscan", mw.RequirePerm(domain.PermScansRead, s.handleQuickScanInfo))
	s.handle("POST /api/v1/quickscan/lab", mw.RequirePerm(domain.PermScansRun, s.handleQuickScanLab))
	s.handle("POST /api/v1/quickscan/agent", mw.RequirePerm(domain.PermScansRun, s.handleQuickScanAgent))
}

// handleInstallScript serves install.sh with this server's /download URL filled in.
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(selfdist.Script(strings.TrimRight(publicBaseURL(r), "/") + "/download"))
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	s.dist.ServeFile(w, r, r.PathValue("file"))
}

// quickLab is the lab option of the dialog.
type quickLab struct {
	Available   bool     `json:"available"`
	Reason      string   `json:"reason,omitempty"` // why it is not available
	ProfileID   string   `json:"profile_id,omitempty"`
	ProfileName string   `json:"profile_name,omitempty"`
	Targets     []string `json:"targets,omitempty"`
	TotalIPs    int      `json:"total_ips,omitempty"`
	PortCount   int      `json:"port_count,omitempty"`
	AgentID     string   `json:"agent_id,omitempty"`
	AgentName   string   `json:"agent_name,omitempty"`
	AgentOnline bool     `json:"agent_online,omitempty"`
	// ActiveRunID is the scan a click joins instead of starting another one: the lab quick
	// scan already running, or the job the lab agent is busy with.
	ActiveRunID string `json:"active_run_id,omitempty"`

	profile *domain.ScanProfile
}

// labProfile picks the profile behind "Our lab network": DZIECIOL_QUICKSCAN_PROFILE (id or
// name) when set, otherwise the smallest enabled profile with "lab" in its name, preferring
// one whose agent is online.
func (s *Server) labProfile(ctx context.Context) (*domain.ScanProfile, string) {
	profiles, err := s.store.ListProfiles(ctx)
	if err != nil {
		return nil, "cannot read the scan profiles"
	}
	if want := strings.TrimSpace(os.Getenv("DZIECIOL_QUICKSCAN_PROFILE")); want != "" {
		for i := range profiles {
			if profiles[i].ID == want || strings.EqualFold(profiles[i].Name, want) {
				return &profiles[i], ""
			}
		}
		return nil, fmt.Sprintf("DZIECIOL_QUICKSCAN_PROFILE names no scan profile (%q)", want)
	}
	agents := map[string]domain.Agent{}
	for _, a := range s.agents.ListAgents(ctx) {
		agents[a.ID] = a
	}
	type cand struct {
		p      *domain.ScanProfile
		online bool
		ips    int
	}
	var cands []cand
	for i := range profiles {
		p := &profiles[i]
		if !p.Enabled || len(p.Targets) == 0 || !strings.Contains(strings.ToLower(p.Name), "lab") {
			continue
		}
		online := true
		if p.AgentID != "" {
			a, ok := agents[p.AgentID]
			if !ok || a.Disabled {
				continue
			}
			online = a.Status == domain.AgentStatusOnline
		}
		ips := 0
		if res, err := scanner.ParseAndNormalizeTargets(ctx, quickLabTargets(p.Targets), nil, nil); err == nil {
			ips = len(res.IPs)
		}
		if ips == 0 {
			continue
		}
		cands = append(cands, cand{p, online, ips})
	}
	if len(cands) == 0 {
		return nil, "no scan profile with \"lab\" in its name"
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].online != cands[j].online {
			return cands[i].online
		}
		return cands[i].ips < cands[j].ips
	})
	return cands[0].p, ""
}

// quickLabTargets keeps the lab quick scan short: a single CIDR wider than /22 scans its
// first /22 (10.66.0.0/18 becomes 10.66.0.0/22); anything else is kept.
func quickLabTargets(targets []string) []string {
	if len(targets) == 1 {
		if p, err := netip.ParsePrefix(strings.TrimSpace(targets[0])); err == nil && p.Addr().Is4() && p.Bits() < 22 {
			return []string{netip.PrefixFrom(p.Masked().Addr(), 22).String()}
		}
	}
	return targets
}

func (s *Server) quickLab(ctx context.Context) quickLab {
	p, reason := s.labProfile(ctx)
	if p == nil {
		return quickLab{Reason: reason}
	}
	lab := quickLab{ProfileID: p.ID, ProfileName: p.Name, Targets: quickLabTargets(p.Targets), profile: p}
	if res, err := scanner.ParseAndNormalizeTargets(ctx, lab.Targets, nil, nil); err == nil {
		lab.TotalIPs = len(res.IPs)
		if ports, err := scanner.ParsePorts(scanner.EffectivePorts(p.AllowedPorts, len(res.IPs))); err == nil {
			lab.PortCount = len(ports)
		}
	}
	lab.Available = true
	if p.AgentID != "" {
		a, err := s.agents.GetAgent(ctx, p.AgentID)
		switch {
		case err != nil:
			lab.Available, lab.Reason = false, "the lab profile points at an agent that no longer exists"
		default:
			lab.AgentID, lab.AgentName = a.ID, a.Name
			lab.AgentOnline = a.Status == domain.AgentStatusOnline
			if !lab.AgentOnline {
				lab.Available, lab.Reason = false, fmt.Sprintf("the lab agent %s is %s", a.Name, a.Status)
			}
		}
	}
	if wg, err := scanner.NewWindowGuard(p.WindowEnabled, p.WindowStart, p.WindowEnd, p.Timezone); err == nil && !wg.IsOpen(time.Now()) {
		lab.Available, lab.Reason = false, fmt.Sprintf("the lab profile only scans between %s and %s", p.WindowStart, p.WindowEnd)
	}
	if run := s.activeLabRun(ctx, lab.AgentID); run != nil {
		lab.ActiveRunID = run.ID
	}
	return lab
}

func isActiveRun(status string) bool {
	switch status {
	case domain.ScanStatusQueued, domain.ScanStatusCalibrating, domain.ScanStatusRunning,
		domain.ScanStatusPausedWindow, domain.ScanStatusPausedUser:
		return true
	}
	return false
}

// activeLabRun is the run a lab click joins: the lab quick scan while it is active, else the
// job the lab agent is executing or has queued (the agent runs one job at a time, so a new
// scan would only wait behind it).
func (s *Server) activeLabRun(ctx context.Context, agentID string) *domain.ScanRun {
	s.quick.mu.Lock()
	id := s.quick.labRunID
	s.quick.mu.Unlock()
	if id != "" {
		if run, err := s.store.GetScanRun(ctx, id); err == nil && isActiveRun(run.Status) {
			return run
		}
	}
	if agentID == "" {
		return nil
	}
	runs, err := s.store.ListScanRuns(ctx, 50)
	if err != nil {
		return nil
	}
	var pick *domain.ScanRun
	for i := range runs {
		run := &runs[i]
		if !isActiveRun(run.Status) || s.agents.JobAgent(run.ID) != agentID {
			continue
		}
		// Prefer the run the agent is executing over one waiting in its queue.
		if pick == nil || (pick.Status == domain.ScanStatusQueued && run.Status != domain.ScanStatusQueued) {
			pick = run
		}
	}
	return pick
}

// settingsAdmins lists (up to five) active users who may create agent enrollment tokens, so
// the dialog can say whom to ask.
func (s *Server) settingsAdmins(ctx context.Context) []string {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil
	}
	roles, err := s.store.ListRoles(ctx)
	if err != nil {
		return nil
	}
	perms := map[string][]string{}
	for _, r := range roles {
		perms[r.ID] = r.Permissions
	}
	var out []string
	for _, u := range users {
		if u.Active && auth.HasPermission(perms[u.RoleID], domain.PermAdminSettings) && len(out) < 5 {
			out = append(out, u.Username)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleQuickScanInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lab := s.quickLab(ctx)
	resp := map[string]any{
		"lab":        lab,
		"server_url": publicBaseURL(r),
		"platforms":  s.dist.Available(),
	}
	if u := auth.UserFromContext(ctx); u == nil || !auth.HasPermission(u.Permissions, domain.PermAdminSettings) {
		resp["token_admins"] = s.settingsAdmins(ctx)
	}
	writeJSON(w, http.StatusOK, resp)
}

// startQuickRun creates a run for an ad-hoc profile and hands it to the runner (local engine
// or agent queue) in the background, like POST /api/v1/scans.
func (s *Server) startQuickRun(r *http.Request, profile *domain.ScanProfile, notes string) (*domain.ScanRun, error) {
	ctx := r.Context()
	exclusions, _ := s.store.ListExclusions(ctx)
	if res, err := scanner.ParseAndNormalizeTargets(ctx, profile.Targets, exclusions, nil); err == nil && len(res.IPs) == 0 && res.ExcludedCount > 0 {
		return nil, errors.New("every target is covered by an exclusion (Scans, Scope tab)")
	}
	run := &domain.ScanRun{
		ID:          db.NewID(),
		Name:        profile.Name,
		RunType:     domain.ScanTypeActive,
		Status:      domain.ScanStatusQueued,
		Notes:       notes,
		TriggeredBy: currentUsername(r),
		StartedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateScanRun(ctx, run); err != nil {
		return nil, err
	}
	bgRun := *run
	go func() {
		bg := context.Background()
		if err := s.runner.StartScan(bg, &bgRun, profile, exclusions); err != nil {
			now := time.Now().UTC()
			bgRun.Status = domain.ScanStatusFailed
			bgRun.FinishedAt = &now
			bgRun.Notes = strings.TrimSpace(bgRun.Notes + "\nCould not start: " + err.Error())
			_ = s.store.UpdateScanRun(bg, &bgRun)
		}
	}()
	return run, nil
}

// handleQuickScanLab starts a fast scan of the lab network, or answers with the scan already
// running there (joined: true), so many people clicking at once share one scan.
func (s *Server) handleQuickScanLab(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s.quick.startMu.Lock()
	defer s.quick.startMu.Unlock()
	lab := s.quickLab(ctx)
	if lab.profile == nil || !lab.Available {
		writeErr(w, http.StatusConflict, "the lab scan is not available: "+lab.Reason)
		return
	}
	if lab.ActiveRunID != "" {
		if run, err := s.store.GetScanRun(ctx, lab.ActiveRunID); err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"run": run, "joined": true})
			return
		}
	}
	p := *lab.profile
	p.ID = ""
	p.Name = "Quick scan: " + lab.ProfileName
	p.Targets = lab.Targets
	p.ChunkTargetSec = quickChunkTargetSec
	p.ScheduleCron = ""
	applyProfileDefaults(&p)
	run, err := s.startQuickRun(r, &p, "Started from Quick scan (lab network).")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.quick.mu.Lock()
	s.quick.labRunID = run.ID
	s.quick.mu.Unlock()
	writeJSON(w, http.StatusAccepted, map[string]any{"run": run, "joined": false})
}

// agentMayScan reports whether target lies inside the networks the agent says it may scan:
// its allowlist, or (an agent too old to report one) its local subnets.
func agentMayScan(caps domain.AgentCapabilities, target netip.Prefix) bool {
	nets := caps.AllowCIDRs
	if len(nets) == 0 && !caps.AllowFromInterfaces {
		for _, s := range caps.LocalSubnets {
			nets = append(nets, s.CIDR)
		}
	}
	for _, n := range nets {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			continue
		}
		if p.Addr().Is4() == target.Addr().Is4() && p.Bits() <= target.Bits() && p.Contains(target.Addr()) {
			return true
		}
	}
	return false
}

// handleQuickScanAgent scans one network of an agent's host (typically one of the subnets it
// reported) with conservative settings for a network nobody here knows.
func (s *Server) handleQuickScanAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID string `json:"agent_id"`
		Target  string `json:"target"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ctx := r.Context()
	a, err := s.agents.GetAgent(ctx, strings.TrimSpace(req.AgentID))
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown agent")
		return
	}
	if a.Status != domain.AgentStatusOnline {
		writeErr(w, http.StatusConflict, fmt.Sprintf("agent %s is %s", a.Name, a.Status))
		return
	}
	target := strings.TrimSpace(req.Target)
	prefix, err := netip.ParsePrefix(target)
	if err != nil {
		addr, aerr := netip.ParseAddr(target)
		if aerr != nil {
			writeErr(w, http.StatusBadRequest, "target must be a network (CIDR) or one IP address")
			return
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() && prefix.Bits() < 116 {
		writeErr(w, http.StatusBadRequest, "IPv6 networks are too large to sweep; enter a /116 or smaller")
		return
	}
	if prefix.Addr().Is4() && 1<<(32-prefix.Bits()) > quickAgentMaxIPs {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("%s is too large for a quick scan (at most %d addresses, a /20); pick a /24 or create a scan profile", prefix, quickAgentMaxIPs))
		return
	}
	if !agentMayScan(a.Capabilities, prefix) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("%s is outside the networks agent %s may scan (%s)", prefix, a.Name,
			strings.Join(a.Capabilities.AllowCIDRs, ", ")))
		return
	}
	p := &domain.ScanProfile{
		Name:                  fmt.Sprintf("Quick scan: %s via %s", prefix, a.Name),
		Targets:               []string{prefix.String()},
		AllowedPorts:          scanner.AutoWidePorts,
		MaxRatePPS:            quickAgentRatePPS,
		HTTPRPS:               quickAgentHTTPRPS,
		Concurrency:           quickAgentConcurrency,
		ChunkTargetSec:        1,
		EnableHTTPFingerprint: true,
		Enabled:               true,
		AgentID:               a.ID,
	}
	applyProfileDefaults(p)
	run, err := s.startQuickRun(r, p, fmt.Sprintf("Started from Quick scan through agent %s at %d packets/s.", a.Name, quickAgentRatePPS))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"run": run})
}
