package verify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// Service runs verification for scan profiles and keeps the results.
type Service struct {
	DB      db.Store
	Results *Store
	Checks  []*Check
	Audit   Auditor
	Publish func(domain.LiveEvent)
	// OnRecorded runs after results were stored (the API queues a DefectDojo resync).
	OnRecorded func()
	// NewLimiter builds the per-run governor (default: scanner.Governor at the profile's
	// HTTP rate). Tests replace it.
	NewLimiter func(p *domain.ScanProfile) Limiter
	Timeout    time.Duration

	mu      sync.Mutex
	running map[string]bool
}

// ErrDisabled is returned when the profile has not opted in.
var ErrDisabled = errors.New("verification is off for this profile (enable Verify in the profile first)")

// ErrRunning is returned when a run for the profile is already in progress.
var ErrRunning = errors.New("verification is already running for this profile")

// NewService loads the embedded checks.
func NewService(store db.Store) (*Service, error) {
	checks, err := LoadBuiltinChecks()
	if err != nil {
		return nil, err
	}
	settings, _ := store.(db.SettingsStore)
	return &Service{DB: store, Results: NewStore(settings), Checks: checks, running: map[string]bool{}}, nil
}

func (s *Service) limiter(p *domain.ScanProfile) Limiter {
	if s.NewLimiter != nil {
		return s.NewLimiter(p)
	}
	rps := float64(p.HTTPRPS)
	if rps <= 0 {
		rps = 5
	}
	if rps > 20 {
		rps = 20 // verification stays gentle even on fast profiles
	}
	return scanner.NewGovernor(scanner.GovernorConfig{GlobalRatePerSec: rps, PerHostRatePerSec: rps / 2, PerHostBurst: 1, GlobalBurst: 2})
}

// Scope resolves the profile's targets minus exclusions to a membership test.
func (s *Service) Scope(ctx context.Context, p *domain.ScanProfile) (func(ip string) bool, error) {
	excl, err := s.DB.ListExclusions(ctx)
	if err != nil {
		return nil, err
	}
	res, err := scanner.ParseAndNormalizeTargets(ctx, p.Targets, excl, nil)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(res.IPs))
	for _, ip := range res.IPs {
		set[ip] = true
	}
	return func(ip string) bool { return set[strings.TrimSpace(ip)] }, nil
}

// RunProfile verifies the services of the profile's in-scope hosts (only hostID when set).
// It refuses when the profile has not opted in.
func (s *Service) RunProfile(ctx context.Context, profileID, hostID, scanRunID, trigger string) (*RunSummary, error) {
	cfg := s.Results.Profile(profileID)
	if !cfg.Enabled {
		return nil, ErrDisabled
	}
	p, err := s.DB.GetProfile(ctx, profileID)
	if err != nil || p == nil {
		return nil, fmt.Errorf("profile %s: %w", profileID, err)
	}
	s.mu.Lock()
	if s.running[profileID] {
		s.mu.Unlock()
		return nil, ErrRunning
	}
	s.running[profileID] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, profileID)
		s.mu.Unlock()
	}()

	sum := RunSummary{ProfileID: p.ID, ProfileName: p.Name, ScanRunID: scanRunID, Trigger: trigger, StartedAt: time.Now().UTC()}
	inScope, err := s.Scope(ctx, p)
	if err != nil {
		return nil, err
	}
	hosts, _, err := s.DB.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		return nil, err
	}
	var targets []Target
	var checked []string
	for _, h := range hosts {
		if (hostID != "" && h.ID != hostID) || !inScope(h.IP) {
			continue
		}
		if h.LifecycleState == domain.HostStateMissing || h.LifecycleState == domain.HostStateInactive {
			continue
		}
		svcs, err := s.DB.ListServicesByHost(ctx, h.ID)
		if err != nil {
			continue
		}
		for _, svc := range svcs {
			if svc.State != "" && svc.State != "open" {
				continue
			}
			targets = append(targets, Target{Service: svc, HostIP: h.IP})
			checked = append(checked, svc.ID)
		}
	}
	eng := &Engine{Checks: s.Checks, Limiter: s.limiter(p), Audit: s.Audit, Timeout: s.Timeout}
	s.publish("verify.started", scanRunID, map[string]any{"profile_id": p.ID, "targets": len(targets)})
	findings, st := eng.Run(ctx, targets, Options{DefaultCreds: cfg.DefaultCreds, UserAgent: p.UserAgent, ScanRunID: scanRunID, ProfileID: p.ID, InScope: inScope})
	sum.FinishedAt = time.Now().UTC()
	sum.Stats = st
	sum.BySeverity, sum.Checks = summarize(findings)
	if ctx.Err() != nil {
		sum.Error = "interrupted: " + ctx.Err().Error()
		checked = nil // partial run: keep the previous results
		for _, f := range findings {
			checked = appendUniq(checked, f.ServiceID)
		}
	}
	if err := s.Results.Record(context.WithoutCancel(ctx), checked, findings, sum, st.Inconclusive); err != nil {
		sum.Error = strings.TrimSpace(sum.Error + " saving results: " + err.Error())
	}
	if s.Audit != nil {
		s.Audit(ctx, &domain.AuditLog{
			Username: "system", Action: "verify.run", Resource: "scan_profile", ResourceID: p.ID, Status: "success", CreatedAt: time.Now().UTC(),
			Details: map[string]any{
				"trigger": trigger, "scan_run_id": scanRunID, "host_id": hostID, "default_creds": cfg.DefaultCreds,
				"targets": st.Targets, "checks_run": st.ChecksRun, "findings": st.Findings, "out_of_scope": st.OutOfScope,
				"default_creds_tried": st.DefaultCredsTried,
			},
		})
	}
	s.publish("verify.completed", scanRunID, map[string]any{"profile_id": p.ID, "findings": st.Findings, "by_severity": sum.BySeverity})
	if s.OnRecorded != nil {
		s.OnRecorded()
	}
	return &sum, nil
}

func (s *Service) publish(typ, runID string, payload map[string]any) {
	if s.Publish != nil {
		s.Publish(domain.LiveEvent{Type: typ, ScanRunID: runID, Timestamp: time.Now().UTC(), Payload: payload})
	}
}

// AfterScan runs verification for a completed scan when its profile opted in (and the scan
// ran from this server: agent-routed profiles are verified only on demand, from here).
func (s *Service) AfterScan(ctx context.Context, run *domain.ScanRun) {
	if run == nil || run.ProfileID == "" || !s.Results.Profile(run.ProfileID).Enabled {
		return
	}
	if _, err := s.RunProfile(ctx, run.ProfileID, "", run.ID, "scan"); err != nil && !errors.Is(err, ErrDisabled) {
		s.publish("verify.failed", run.ID, map[string]any{"profile_id": run.ProfileID, "error": err.Error()})
	}
}

// ---- process-wide activation -----------------------------------------------------------

var (
	activeMu     sync.RWMutex
	active       *Service
	registerOnce sync.Once
)

// Activate makes s the service whose results annotate every service read (eol.Annotate).
// Safe to call more than once (tests build several API servers); the last one wins.
func Activate(s *Service) {
	activeMu.Lock()
	active = s
	activeMu.Unlock()
	registerOnce.Do(func() { eol.RegisterAnnotator(annotateActive, FactorVerified) })
}

func annotateActive(svc *domain.Service, now time.Time) []domain.InterestingnessFactor {
	activeMu.RLock()
	s := active
	activeMu.RUnlock()
	if s == nil {
		svc.Verified = nil
		return nil
	}
	return s.Annotator(svc, now)
}

// ---- read-time annotation --------------------------------------------------------------

// Points of a verified finding in the service interestingness, by severity.
var verifiedPoints = map[string]int{"critical": 40, "high": 30, "medium": 15, "low": 5}

// FactorVerified prefixes the interestingness factor of verified findings.
const FactorVerified = "Verified exposure: "

// Annotator fills Service.Verified from the store and returns its score factor (for
// eol.RegisterAnnotator).
func (s *Service) Annotator(svc *domain.Service, _ time.Time) []domain.InterestingnessFactor {
	svc.Verified = s.Results.ForService(svc.ID)
	if len(svc.Verified) == 0 {
		return nil
	}
	best, names := 0, make([]string, 0, len(svc.Verified))
	for _, f := range svc.Verified {
		if p := verifiedPoints[f.Severity]; p > best {
			best = p
		}
		names = append(names, f.Name)
	}
	if best == 0 {
		return nil
	}
	return []domain.InterestingnessFactor{{Reason: FactorVerified + strings.Join(names, "; "), Points: best}}
}
