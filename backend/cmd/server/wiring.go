package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/intelligence"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

// IntelligenceAnalyzer bridges scanner-engine's signatures + intelligence packages
// into backend-core's unified ingest.Analyzer interface.
type IntelligenceAnalyzer struct{}

func NewIntelligenceAnalyzer() *IntelligenceAnalyzer {
	return &IntelligenceAnalyzer{}
}

func (a *IntelligenceAnalyzer) BuiltinSignatures() []domain.Signature {
	return signatures.BuiltinSignatures()
}

func (a *IntelligenceAnalyzer) ValidateSignature(sig domain.Signature) error {
	vr := signatures.ValidateSignature(sig)
	if !vr.Valid {
		return errors.New(strings.Join(vr.Errors, "; "))
	}
	return nil
}

func (a *IntelligenceAnalyzer) AnalyzeService(obs *domain.ObservedService, customSigs []domain.Signature) ingest.ServiceAnalysis {
	if obs == nil {
		return ingest.ServiceAnalysis{}
	}
	sigEngine := signatures.NewEngine(customSigs)
	svc := &domain.Service{
		Port:        obs.Port,
		Protocol:    obs.Protocol,
		State:       obs.State,
		ServiceName: obs.ServiceName,
		Product:     obs.Product,
		Version:     obs.Version,
		CPE:         obs.CPE,
		Banner:      obs.Banner,
		HTTP:        obs.HTTP,
		Tags:        append([]string(nil), obs.Tags...),
	}
	matches := intelligence.EnrichService(svc, *obs, sigEngine, 1)

	tagSet := make(map[string]struct{}, len(obs.Tags)+8)
	tags := make([]string, 0, len(obs.Tags)+8)
	addTag := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" {
			return
		}
		if _, ok := tagSet[t]; !ok {
			tagSet[t] = struct{}{}
			tags = append(tags, t)
		}
	}
	for _, t := range obs.Tags {
		addTag(t)
	}
	for _, m := range matches {
		for _, t := range m.Signature.Tags {
			addTag(t)
		}
	}
	if svc.IsAdminPanel {
		addTag("admin_panel")
	}
	if svc.IsStagingEnv {
		addTag("staging")
	}
	if svc.IsIoT {
		addTag("iot")
	}

	return ingest.ServiceAnalysis{
		Technologies:       svc.Technologies,
		MatchedSignatures:  svc.MatchedSignatures,
		IsAdminPanel:       svc.IsAdminPanel,
		IsStagingEnv:       svc.IsStagingEnv,
		IsIoT:              svc.IsIoT,
		ClusterKey:         svc.ClusterKey,
		Interestingness:    svc.Interestingness,
		InterestingFactors: svc.InterestingFactors,
		Tags:               tags,
	}
}

func (a *IntelligenceAnalyzer) EvaluateLifecycle(prev *domain.Host, seen bool, now time.Time, missingThreshold int, graceHours int) ingest.LifecycleTransition {
	var working domain.Host
	if prev != nil {
		working = *prev
		working.TimeOfDayStats = append([]domain.TimeSlotStat(nil), prev.TimeOfDayStats...)
	}
	tr := intelligence.EvaluateHostLifecycle(&working, seen, now, intelligence.LifecycleConfig{
		MissingThreshold: missingThreshold,
		GracePeriodHours: graceHours,
	})
	return ingest.LifecycleTransition{
		NewState:           tr.NewState,
		Changed:            tr.Transitioned,
		TotalScansSeen:     working.TotalScansSeen,
		TotalScansChecked:  working.TotalScansChecked,
		ConsecutiveMisses:  working.ConsecutiveMisses,
		StateTransitions:   working.StateTransitions,
		StabilityScore:     tr.StabilityScore,
		TimeOfDayStats:     working.TimeOfDayStats,
		IsExpectedSchedule: tr.IsExpectedSchedule,
		IsTimeAnomaly:      tr.IsTimeAnomaly,
		Summary:            tr.Reason,
	}
}

func (a *IntelligenceAnalyzer) ScoreHost(host *domain.Host, services []domain.Service) (int, []domain.InterestingnessFactor) {
	return intelligence.ScoreHost(host, services, nil)
}

func (a *IntelligenceAnalyzer) ComputeClusters(hosts []domain.Host) []domain.ServiceCluster {
	var allServices []domain.Service
	for _, h := range hosts {
		for _, s := range h.Services {
			if s.HostIP == "" {
				s.HostIP = h.IP
			}
			allServices = append(allServices, s)
		}
	}
	return intelligence.ComputeClustersWithMinSize(allServices, 1)
}

func (a *IntelligenceAnalyzer) RetroactiveTest(sig domain.Signature, services []domain.Service) []ingest.SignatureTestHit {
	matches, vr := signatures.RetroactiveTest(sig, services)
	if !vr.Valid {
		return []ingest.SignatureTestHit{}
	}
	svcMap := make(map[string]domain.Service, len(services))
	for _, s := range services {
		svcMap[s.ID] = s
	}
	hits := make([]ingest.SignatureTestHit, 0, len(matches))
	for _, m := range matches {
		texts := make([]string, 0, len(m.Evidence))
		for _, ev := range m.Evidence {
			texts = append(texts, ev.Detail)
		}
		proto := "tcp"
		title := ""
		if orig, ok := svcMap[m.ServiceID]; ok {
			if orig.Protocol != "" {
				proto = orig.Protocol
			}
			if orig.HTTP != nil {
				title = orig.HTTP.Title
			}
		}
		hits = append(hits, ingest.SignatureTestHit{
			ServiceID:   m.ServiceID,
			HostID:      m.HostID,
			HostIP:      m.HostIP,
			Port:        m.Port,
			Protocol:    proto,
			Title:       title,
			Version:     m.Version,
			Confidence:  intelligence.FuseConfidence(m.Evidence, 1, false),
			MatchedText: texts,
		})
	}
	return hits
}

// LiveScanRunner bridges scanner.Engine into api.ScanRunner with async execution,
// checkpoint persistence, Pause/Resume across time windows, and unified pipeline ingestion.
type LiveScanRunner struct {
	store    db.Store
	pipeline *ingest.Pipeline
	hub      *api.SSEHub

	mu     sync.Mutex
	active map[string]*activeScanHandle
}

type activeScanHandle struct {
	cancel     context.CancelFunc
	profile    domain.ScanProfile
	exclusions []domain.TargetExclusion
	resolution *scanner.TargetResolution
	pauseReq   bool
}

func NewLiveScanRunner(store db.Store, pipeline *ingest.Pipeline, hub *api.SSEHub) *LiveScanRunner {
	return &LiveScanRunner{
		store:    store,
		pipeline: pipeline,
		hub:      hub,
		active:   make(map[string]*activeScanHandle),
	}
}

func (r *LiveScanRunner) NmapAvailable() bool {
	return scanner.NmapAvailable()
}

func (r *LiveScanRunner) EstimateTargets(ctx context.Context, req api.EstimateRequest) (domain.TargetEstimate, error) {
	excls := make([]domain.TargetExclusion, 0, len(req.Exclusions))
	for _, ex := range req.Exclusions {
		excls = append(excls, domain.TargetExclusion{Value: ex})
	}
	wg, err := scanner.NewWindowGuard(req.WindowEnabled, req.WindowStart, req.WindowEnd, req.Timezone)
	if err != nil {
		return domain.TargetEstimate{}, err
	}
	est, _, err := scanner.EstimateTargets(ctx, scanner.EstimateRequest{
		Targets:               req.Targets,
		Exclusions:            excls,
		Ports:                 req.Ports,
		MaxRatePPS:            req.MaxRatePPS,
		Concurrency:           req.Concurrency,
		ChunkTargetSec:        req.ChunkTargetSec,
		Window:                wg,
		Now:                   time.Now().UTC(),
		EnableHTTPFingerprint: true,
	})
	if err != nil {
		return domain.TargetEstimate{}, err
	}
	return *est, nil
}

func (r *LiveScanRunner) StartScan(ctx context.Context, run *domain.ScanRun, profile *domain.ScanProfile, exclusions []domain.TargetExclusion) error {
	if run == nil || profile == nil {
		return errors.New("scan run and profile are required")
	}

	// Collect previously active hosts for Stage 4 unstable re-probing.
	unstableHosts := r.collectTrackedHostIPs(ctx)

	engine := scanner.NewEngine(scanner.EngineConfig{
		UseNmap:       scanner.NmapAvailable(),
		UnstableHosts: unstableHosts,
	})

	prepared, resolution, err := engine.PrepareRun(ctx, run.ID, *profile, exclusions)
	if err != nil {
		run.Status = domain.ScanStatusFailed
		_ = r.store.UpdateScanRun(ctx, run)
		return fmt.Errorf("prepare scan run: %w", err)
	}

	run.TotalIPs = prepared.TotalIPs
	run.TotalChunks = prepared.TotalChunks
	run.ETASeconds = prepared.ETASeconds
	run.Status = domain.ScanStatusRunning
	run.Chunks = prepared.Chunks
	if err := r.store.UpdateScanRun(ctx, run); err != nil {
		return err
	}
	if err := r.store.SaveScanChunks(ctx, run.ID, prepared.Chunks); err != nil {
		return err
	}

	r.launchAsync(run, *profile, exclusions, resolution, unstableHosts)
	return nil
}

func (r *LiveScanRunner) launchAsync(
	run *domain.ScanRun,
	profile domain.ScanProfile,
	exclusions []domain.TargetExclusion,
	resolution *scanner.TargetResolution,
	unstableHosts []string,
) {
	runCtx, cancel := context.WithCancel(context.Background())
	handle := &activeScanHandle{
		cancel:     cancel,
		profile:    profile,
		exclusions: exclusions,
		resolution: resolution,
	}

	r.mu.Lock()
	r.active[run.ID] = handle
	r.mu.Unlock()

	runCopy := *run
	runCopy.Chunks = append([]domain.ScanChunk(nil), run.Chunks...)

	go func() {
		defer func() {
			cancel()
			r.mu.Lock()
			if cur, ok := r.active[runCopy.ID]; ok && cur == handle {
				delete(r.active, runCopy.ID)
			}
			r.mu.Unlock()
		}()

		engine := scanner.NewEngine(scanner.EngineConfig{
			UseNmap:       scanner.NmapAvailable(),
			UnstableHosts: unstableHosts,
		})

		res, err := engine.Execute(runCtx, &runCopy, profile, resolution, scanner.RunCallbacks{
			OnEvent: func(ev domain.LiveEvent) {
				if r.hub != nil {
					r.hub.Publish(ev)
				}
			},
			OnChunkUpdate: func(ch domain.ScanChunk) {
				bgCtx, bgCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer bgCancel()
				for idx := range runCopy.Chunks {
					if runCopy.Chunks[idx].ID == ch.ID {
						runCopy.Chunks[idx] = ch
						break
					}
				}
				_ = r.store.SaveScanChunks(bgCtx, runCopy.ID, runCopy.Chunks)
			},
			OnCheckpoint: func(cp *domain.ScanRun) {
				bgCtx, bgCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer bgCancel()
				_ = r.store.UpdateScanRun(bgCtx, cp)
				_ = r.store.SaveScanChunks(bgCtx, cp.ID, cp.Chunks)
			},
		})

		bgCtx, bgCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer bgCancel()

		// Check if user requested pause vs stop.
		r.mu.Lock()
		wasPause := handle.pauseReq
		r.mu.Unlock()

		if err != nil {
			if wasPause {
				runCopy.Status = domain.ScanStatusPausedUser
				for idx := range runCopy.Chunks {
					if runCopy.Chunks[idx].Status == domain.ChunkStatusRunning {
						runCopy.Chunks[idx].Status = domain.ChunkStatusPaused
					}
				}
				_ = r.store.SaveScanChunks(bgCtx, runCopy.ID, runCopy.Chunks)
				_ = r.store.UpdateScanRun(bgCtx, &runCopy)
				if r.hub != nil {
					r.hub.Publish(domain.LiveEvent{
						Type:      "scan.paused",
						ScanRunID: runCopy.ID,
						Timestamp: time.Now().UTC(),
						Payload:   map[string]any{"status": runCopy.Status},
					})
				}
				return
			}
			if errors.Is(err, context.Canceled) {
				now := time.Now().UTC()
				runCopy.Status = domain.ScanStatusStopped
				runCopy.FinishedAt = &now
				_ = r.store.UpdateScanRun(bgCtx, &runCopy)
				return
			}
			log.Printf("[ERROR] scan %s failed: %v", runCopy.ID, err)
			now := time.Now().UTC()
			runCopy.Status = domain.ScanStatusFailed
			runCopy.FinishedAt = &now
			_ = r.store.UpdateScanRun(bgCtx, &runCopy)
			return
		}

		if res == nil {
			return
		}

		// Persist observations through the unified ingestion pipeline (diff, lifecycle, overrides, encryption!).
		var scopeIPs []string
		if resolution != nil {
			scopeIPs = resolution.IPs
		}
		if len(res.ObservedHosts) > 0 || res.RawNmapXML != "" {
			if _, perr := r.pipeline.ProcessObservations(bgCtx, ingest.IngestRequest{
				ScanRunID:        runCopy.ID,
				ProfileID:        profile.ID,
				RunType:          domain.ScanTypeActive,
				ScanName:         runCopy.Name,
				Notes:            runCopy.Notes,
				TriggeredBy:      runCopy.TriggeredBy,
				RawNmapXML:       res.RawNmapXML,
				Observations:     res.ObservedHosts,
				ScopeIPs:         scopeIPs,
				MarkMissingHosts: !res.PausedByWindow,
				MissingThreshold: profile.MissingThreshold,
				GracePeriodHours: profile.GracePeriodHours,
			}); perr != nil {
				log.Printf("[ERROR] scan %s ingest failed: %v", runCopy.ID, perr)
			}
		}

		// Preserve PAUSED_WINDOW status if halted by time window.
		if res.PausedByWindow {
			saved, gerr := r.store.GetScanRun(bgCtx, runCopy.ID)
			if gerr == nil {
				saved.Status = domain.ScanStatusPausedWindow
				saved.FinishedAt = nil
				saved.WindowPausedCount = runCopy.WindowPausedCount
				_ = r.store.UpdateScanRun(bgCtx, saved)
			}
		}
	}()
}

func (r *LiveScanRunner) PauseScan(ctx context.Context, scanRunID string) error {
	r.mu.Lock()
	if h, ok := r.active[scanRunID]; ok {
		h.pauseReq = true
		h.cancel()
	}
	r.mu.Unlock()

	run, err := r.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		return err
	}
	run.Status = domain.ScanStatusPausedUser
	return r.store.UpdateScanRun(ctx, run)
}

func (r *LiveScanRunner) ResumeScan(ctx context.Context, scanRunID string) error {
	run, err := r.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		return err
	}
	if run.ProfileID == "" {
		return errors.New("scan has no associated profile to resume")
	}
	profile, err := r.store.GetProfile(ctx, run.ProfileID)
	if err != nil {
		return err
	}
	exclusions, _ := r.store.ListExclusions(ctx)
	chunks, _ := r.store.GetScanChunks(ctx, scanRunID)
	for i := range chunks {
		if chunks[i].Status == domain.ChunkStatusPaused || chunks[i].Status == domain.ChunkStatusRunning {
			chunks[i].Status = domain.ChunkStatusPending
		}
	}
	run.Chunks = chunks
	run.Status = domain.ScanStatusRunning
	run.FinishedAt = nil
	if err := r.store.SaveScanChunks(ctx, scanRunID, chunks); err != nil {
		return err
	}
	if err := r.store.UpdateScanRun(ctx, run); err != nil {
		return err
	}

	_, resolution, _ := scanner.EstimateTargets(ctx, scanner.EstimateRequest{
		Targets:    profile.Targets,
		Exclusions: exclusions,
		Ports:      profile.AllowedPorts,
	})
	r.launchAsync(run, *profile, exclusions, resolution, r.collectTrackedHostIPs(ctx))
	return nil
}

func (r *LiveScanRunner) StopScan(ctx context.Context, scanRunID string) error {
	r.mu.Lock()
	if h, ok := r.active[scanRunID]; ok {
		h.pauseReq = false
		h.cancel()
	}
	r.mu.Unlock()

	run, err := r.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	run.Status = domain.ScanStatusStopped
	run.FinishedAt = &now
	return r.store.UpdateScanRun(ctx, run)
}

func (r *LiveScanRunner) collectTrackedHostIPs(ctx context.Context) []string {
	hosts, _, err := r.store.ListHosts(ctx, db.HostFilter{Limit: 10000})
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h.LifecycleState == domain.HostStateActive ||
			h.LifecycleState == domain.HostStateNew ||
			h.LifecycleState == domain.HostStateIntermittent ||
			h.LifecycleState == domain.HostStateMissing ||
			h.LifecycleState == domain.HostStateReactivated {
			out = append(out, h.IP)
		}
	}
	return out
}

// StartWindowWatcher periodically checks for PAUSED_WINDOW scans and auto-resumes them
// the moment their configured time window reopens.
func (r *LiveScanRunner) StartWindowWatcher(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.checkPausedWindowScans(ctx)
			}
		}
	}()
}

func (r *LiveScanRunner) checkPausedWindowScans(ctx context.Context) {
	runs, err := r.store.ListScanRuns(ctx, 50)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, run := range runs {
		if run.Status != domain.ScanStatusPausedWindow || run.ProfileID == "" {
			continue
		}
		r.mu.Lock()
		_, alreadyRunning := r.active[run.ID]
		r.mu.Unlock()
		if alreadyRunning {
			continue
		}
		prof, err := r.store.GetProfile(ctx, run.ProfileID)
		if err != nil {
			continue
		}
		wg, err := scanner.NewWindowGuard(prof.WindowEnabled, prof.WindowStart, prof.WindowEnd, prof.Timezone)
		if err != nil {
			continue
		}
		if wg.IsOpen(now) {
			log.Printf("[INFO] Time window reopened for scan %s (%s); auto-resuming from checkpoint", run.ID, run.Name)
			if err := r.ResumeScan(ctx, run.ID); err != nil {
				log.Printf("[WARN] Auto-resume failed for scan %s: %v", run.ID, err)
			}
		}
	}
}
