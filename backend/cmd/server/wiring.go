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
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
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

	id := intelligence.IdentifyProduct(*obs)
	return ingest.ServiceAnalysis{
		Product:            id.Product,
		Version:            id.Version,
		ProductSource:      id.Source,
		VersionSource:      id.VersionSource,
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
		Liveness:           working.Liveness,
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
	// dojo pushes completed runs' Nmap XML to DefectDojo when auto_push_nmap is on.
	dojo *defectdojo.Client

	mu     sync.Mutex
	active map[string]*activeScanHandle
	// adhoc keeps the profile of running/paused quick scans that have no saved profile, so a
	// user pause can be resumed (in this process).
	adhoc map[string]domain.ScanProfile
	// resumeMu serializes ResumeScan (user clicks, window watcher) so one run never gets two
	// concurrent workers.
	resumeMu sync.Mutex

	// isRemoteRun reports runs executed by a remote agent (agenthub): boot recovery and the
	// window watcher must leave those alone, the agent coordinator owns them.
	isRemoteRun func(runID string) bool

	// Test seams (nil in production): clock for window checks and engine config override.
	nowFn        func() time.Time
	engineConfig func(scanner.EngineConfig) scanner.EngineConfig
}

func (r *LiveScanRunner) now() time.Time {
	if r.nowFn != nil {
		return r.nowFn()
	}
	return time.Now().UTC()
}

func (r *LiveScanRunner) newEngine(unstableHosts []string) *scanner.Engine {
	cfg := scanner.EngineConfig{
		UseNmap:       scanner.NmapAvailable(),
		UnstableHosts: unstableHosts,
	}
	if r.nowFn != nil {
		cfg.Now = r.nowFn
	}
	if r.engineConfig != nil {
		cfg = r.engineConfig(cfg)
	}
	return scanner.NewEngine(cfg)
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
		dojo:     defectdojo.NewClient(),
		active:   make(map[string]*activeScanHandle),
		adhoc:    make(map[string]domain.ScanProfile),
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

	engine := r.newEngine(unstableHosts)

	prepared, resolution, err := engine.PrepareRun(ctx, run.ID, *profile, exclusions)
	if err != nil {
		run.Status = domain.ScanStatusFailed
		_ = r.store.UpdateScanRun(ctx, run)
		return fmt.Errorf("prepare scan run: %w", err)
	}
	if prepared.TotalIPs == 0 {
		// Nothing left to scan (all excluded or invalid): fail loudly instead of reporting an
		// empty COMPLETED run that looks like "the scanner found nothing".
		reason := "no addresses to scan"
		if resolution != nil {
			reason = fmt.Sprintf("no addresses to scan: %d excluded by the exclusion list, %d invalid entries",
				resolution.ExcludedCount, len(resolution.InvalidEntries))
		}
		now := time.Now().UTC()
		run.Status = domain.ScanStatusFailed
		run.FinishedAt = &now
		run.Notes = strings.TrimSpace(run.Notes + "\n" + reason)
		_ = r.store.UpdateScanRun(ctx, run)
		return errors.New(reason)
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
	if r.hub != nil {
		r.hub.Publish(domain.LiveEvent{
			Type:      "scan.started",
			ScanRunID: run.ID,
			Timestamp: time.Now().UTC(),
			Payload: map[string]any{
				"name":         run.Name,
				"total_ips":    run.TotalIPs,
				"total_chunks": run.TotalChunks,
				"eta_seconds":  run.ETASeconds,
			},
		})
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
	if profile.ID == "" {
		r.adhoc[run.ID] = profile
	}
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
			if runCopy.Status != domain.ScanStatusPausedUser && runCopy.Status != domain.ScanStatusPausedWindow {
				delete(r.adhoc, runCopy.ID)
			}
			r.mu.Unlock()
		}()

		engine := r.newEngine(unstableHosts)

		res, err := engine.Execute(runCtx, &runCopy, profile, resolution, scanner.RunCallbacks{
			OnEvent: func(ev domain.LiveEvent) {
				if r.hub != nil {
					r.hub.Publish(ev)
				}
			},
			OnHostObserved: func(obs domain.ObservedHost) {
				if r.hub == nil || !obs.IsAlive {
					return
				}
				ports := make([]int, 0, len(obs.Services))
				titles := make([]string, 0, len(obs.Services))
				for _, s := range obs.Services {
					ports = append(ports, s.Port)
					if s.HTTP != nil && s.HTTP.Title != "" {
						titles = append(titles, s.HTTP.Title)
					}
				}
				r.hub.Publish(domain.LiveEvent{
					Type:      "scan.host_discovered",
					ScanRunID: runCopy.ID,
					Timestamp: time.Now().UTC(),
					Payload: map[string]any{
						"ip":       obs.IP,
						"hostname": obs.Hostname,
						"ports":    ports,
						"services": len(obs.Services),
						"titles":   titles,
					},
				})
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

		// Check if user requested pause vs stop.
		r.mu.Lock()
		wasPause := handle.pauseReq
		r.mu.Unlock()

		// Persist observations of the chunks finished in THIS segment through the unified
		// ingestion pipeline - also when the segment ended by window/user pause or stop,
		// because DONE chunks are skipped on resume and would otherwise never be ingested.
		// Ingest gets its own generous deadline: it scales with the number of live hosts, and a
		// short shared deadline (60 s) silently cut large scans off mid-way while the run still
		// reported COMPLETED (seen on the /18 lab: 42% of hosts persisted).
		ingestCtx, ingestCancel := context.WithTimeout(context.Background(), 2*time.Hour)
		ingestErr := r.ingestSegment(ingestCtx, &runCopy, profile, res)
		ingestCancel()

		bgCtx, bgCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer bgCancel()
		if ingestErr != nil && err == nil {
			now := time.Now().UTC()
			runCopy.Status = domain.ScanStatusFailed
			runCopy.FinishedAt = &now
			runCopy.Notes = strings.TrimSpace(runCopy.Notes + "\nsaving results failed: " + ingestErr.Error())
			_ = r.store.SaveScanChunks(bgCtx, runCopy.ID, runCopy.Chunks)
			_ = r.store.UpdateScanRun(bgCtx, &runCopy)
			return
		}

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

		// Final status write: COMPLETED, or PAUSED_WINDOW (resumed by the window watcher
		// from the chunk checkpoint when the next window opens).
		if res.PausedByWindow {
			runCopy.Status = domain.ScanStatusPausedWindow
			runCopy.FinishedAt = nil
		}
		_ = r.store.SaveScanChunks(bgCtx, runCopy.ID, runCopy.Chunks)
		_ = r.store.UpdateScanRun(bgCtx, &runCopy)
		if !res.PausedByWindow {
			r.autoPushDefectDojo(context.Background(), runCopy.ID)
		}
	}()
}

// autoPushDefectDojo reimports a completed run's merged Nmap XML into DefectDojo when the
// operator enabled auto_push_nmap. One DefectDojo test per profile, so DefectDojo closes
// services that disappeared since the profile's previous run. Failures are recorded in the
// export log and never affect the scan itself.
func (r *LiveScanRunner) autoPushDefectDojo(ctx context.Context, runID string) {
	if r.dojo == nil {
		return
	}
	cfg, err := r.store.GetDefectDojoConfig(ctx)
	if err != nil || cfg == nil || !cfg.AutoPushNmap || strings.TrimSpace(cfg.URL) == "" {
		return
	}
	run, err := r.store.GetScanRun(ctx, runID)
	if err != nil || run.Status != domain.ScanStatusCompleted {
		return
	}
	profileName := run.Name
	var profile *domain.ScanProfile
	if run.ProfileID != "" {
		if p, perr := r.store.GetProfile(ctx, run.ProfileID); perr == nil && p != nil && p.Name != "" {
			profileName, profile = p.Name, p
		}
	}
	pushCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	// Actionable change findings (risky exposures, admin/staging, EOL, new, gone) with owners.
	defer r.pushChangeFindings(pushCtx, cfg, run, profile, profileName)
	if strings.TrimSpace(run.RawNmapXML) == "" {
		return
	}
	imp, err := r.dojo.ImportNmapXML(pushCtx, cfg, 0, defectdojo.NmapTestTitle(profileName), run.Name, run.RawNmapXML)
	exp := &domain.DefectDojoExport{
		ExportType: "nmap_xml",
		SourceID:   run.ID,
		Title:      "Nmap Scan (auto): " + run.Name,
		ExportedBy: "auto-push",
		CreatedAt:  time.Now().UTC(),
	}
	payload := map[string]any{"scan_run_id": run.ID}
	if err != nil {
		exp.Status, exp.ErrorMessage = "failed", err.Error()
		payload["error"] = err.Error()
		log.Printf("[WARN] DefectDojo auto-push for scan %s failed: %v", run.ID, err)
	} else {
		exp.Status, exp.ExternalID, exp.ExternalURL = "success", imp.ExternalID, imp.ExternalURL
		payload["external_url"] = imp.ExternalURL
		log.Printf("[INFO] DefectDojo auto-push for scan %s: %s", run.ID, imp.ExternalURL)
	}
	_ = r.store.AddDefectDojoExport(ctx, exp)
	r.PublishEvent(domain.LiveEvent{Type: "defectdojo_push", ScanRunID: run.ID, Timestamp: time.Now().UTC(), Payload: payload})
}

// ingestSegment pushes one window segment's observations through the pipeline. Missing-host
// detection is scoped to the IPs actually scanned in this segment (res.ScannedIPs): using the
// whole scope here would flag every host scanned in an earlier window as missing.
func (r *LiveScanRunner) ingestSegment(ctx context.Context, run *domain.ScanRun, profile domain.ScanProfile, res *scanner.RunResult) error {
	if res == nil || r.pipeline == nil || (len(res.ObservedHosts) == 0 && res.RawNmapXML == "") {
		return nil
	}
	ingestStart := time.Now()
	defer func() {
		log.Printf("[INFO] scan %s ingest: %d observations in %s", run.ID, len(res.ObservedHosts), time.Since(ingestStart).Round(time.Millisecond))
	}()
	if _, perr := r.pipeline.ProcessObservations(ctx, ingest.IngestRequest{
		ScanRunID:        run.ID,
		ProfileID:        profile.ID,
		RunType:          domain.ScanTypeActive,
		ScanName:         run.Name,
		Notes:            run.Notes,
		TriggeredBy:      run.TriggeredBy,
		RawNmapXML:       res.RawNmapXML,
		Observations:     res.ObservedHosts,
		ScopeIPs:         res.ScannedIPs,
		MarkMissingHosts: len(res.ScannedIPs) > 0,
		MissingThreshold: profile.MissingThreshold,
		GracePeriodHours: profile.GracePeriodHours,
	}); perr != nil {
		log.Printf("[ERROR] scan %s ingest failed: %v", run.ID, perr)
		return perr
	}
	// The pipeline overwrites per-segment counters on the stored run; keep the engine's
	// cumulative ActiveHosts/ServicesFound and adopt the pipeline's ChangesDetected.
	if saved, err := r.store.GetScanRun(ctx, run.ID); err == nil {
		run.ChangesDetected = saved.ChangesDetected
	}
	return nil
}

// scanStateErr reports an invalid pause/resume/stop transition (HTTP 409 with this message).
func scanStateErr(format string, a ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), db.ErrConflict)
}

func (r *LiveScanRunner) PauseScan(ctx context.Context, scanRunID string) error {
	run, err := r.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		return err
	}
	switch run.Status {
	case domain.ScanStatusQueued, domain.ScanStatusCalibrating, domain.ScanStatusRunning, domain.ScanStatusPausedWindow:
	default:
		return scanStateErr("cannot pause a scan that is %s", run.Status)
	}
	r.mu.Lock()
	if h, ok := r.active[scanRunID]; ok {
		h.pauseReq = true
		h.cancel()
	}
	r.mu.Unlock()

	run.Status = domain.ScanStatusPausedUser
	return r.store.UpdateScanRun(ctx, run)
}

func (r *LiveScanRunner) ResumeScan(ctx context.Context, scanRunID string) error {
	r.resumeMu.Lock()
	defer r.resumeMu.Unlock()

	run, err := r.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		return err
	}
	if run.Status != domain.ScanStatusPausedUser && run.Status != domain.ScanStatusPausedWindow {
		return scanStateErr("only a paused scan can be resumed (status: %s)", run.Status)
	}
	// A pause cancels the worker, which then writes its final checkpoint: wait for it, or the
	// old segment and the resumed one would run (and write) concurrently.
	for deadline := time.Now().Add(15 * time.Second); r.IsScanActive(scanRunID); {
		if time.Now().After(deadline) {
			return scanStateErr("scan is still pausing - retry in a moment")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if run, err = r.store.GetScanRun(ctx, scanRunID); err != nil {
		return err
	}
	if run.Status != domain.ScanStatusPausedUser && run.Status != domain.ScanStatusPausedWindow {
		return scanStateErr("only a paused scan can be resumed (status: %s)", run.Status)
	}
	var profile *domain.ScanProfile
	if run.ProfileID != "" {
		if profile, err = r.store.GetProfile(ctx, run.ProfileID); err != nil {
			return err
		}
	} else {
		r.mu.Lock()
		p, ok := r.adhoc[scanRunID]
		r.mu.Unlock()
		if !ok {
			return scanStateErr("a quick scan without a saved profile cannot be resumed after a server restart - start it again")
		}
		profile = &p
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
	run, err := r.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		return err
	}
	switch run.Status {
	case domain.ScanStatusCompleted, domain.ScanStatusFailed, domain.ScanStatusStopped:
		return scanStateErr("scan already finished (%s)", run.Status)
	}
	r.mu.Lock()
	if h, ok := r.active[scanRunID]; ok {
		h.pauseReq = false
		h.cancel()
	}
	delete(r.adhoc, scanRunID)
	r.mu.Unlock()

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

// PublishEvent forwards scheduler events (schedule.fired / schedule.skipped) to the SSE hub.
func (r *LiveScanRunner) PublishEvent(ev domain.LiveEvent) {
	if r.hub != nil {
		r.hub.Publish(ev)
	}
}

// IsScanActive reports whether a scan run is executing in this process right now.
func (r *LiveScanRunner) IsScanActive(scanRunID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.active[scanRunID]
	return ok
}

// RecoverInterrupted runs once at boot: scan runs left QUEUED/CALIBRATING/RUNNING by a
// previous process (crash, deploy, restart) have no live goroutine any more. Runs that already
// have a chunk ledger are parked as PAUSED_WINDOW (chunks RUNNING/PAUSED -> PENDING) so the
// window watcher resumes them from the checkpoint as soon as their window is open; runs that
// never got a ledger are marked FAILED. Without this, the scheduler would treat the orphan as
// "still running" forever and skip every future slot of that profile.
func (r *LiveScanRunner) RecoverInterrupted(ctx context.Context) (int, error) {
	runs, err := r.store.ListScanRuns(ctx, 500)
	if err != nil {
		return 0, err
	}
	recovered := 0
	for i := range runs {
		run := runs[i]
		switch run.Status {
		case domain.ScanStatusQueued, domain.ScanStatusCalibrating, domain.ScanStatusRunning:
		default:
			continue
		}
		if run.RunType != "" && run.RunType != domain.ScanTypeActive {
			continue
		}
		if r.IsScanActive(run.ID) || (r.isRemoteRun != nil && r.isRemoteRun(run.ID)) {
			continue
		}
		chunks, _ := r.store.GetScanChunks(ctx, run.ID)
		if len(chunks) == 0 || run.ProfileID == "" {
			now := time.Now().UTC()
			run.Status = domain.ScanStatusFailed
			run.FinishedAt = &now
			// Tell the user why in the UI, not only in the server log. Results ingested before
			// the restart are kept.
			run.Notes = strings.TrimSpace(run.Notes + "\nInterrupted by a server restart/crash - run the scan again (results collected so far were saved).")
			_ = r.store.UpdateScanRun(ctx, &run)
			log.Printf("[WARN] scan %s (%s) was interrupted before its chunk ledger existed; marked FAILED", run.ID, run.Name)
			recovered++
			continue
		}
		for c := range chunks {
			if chunks[c].Status == domain.ChunkStatusRunning || chunks[c].Status == domain.ChunkStatusPaused {
				chunks[c].Status = domain.ChunkStatusPending
				chunks[c].StartedAt = nil
			}
		}
		_ = r.store.SaveScanChunks(ctx, run.ID, chunks)
		run.Status = domain.ScanStatusPausedWindow
		run.FinishedAt = nil
		_ = r.store.UpdateScanRun(ctx, &run)
		log.Printf("[INFO] scan %s (%s) was interrupted by a restart; parked as PAUSED_WINDOW for checkpoint resume", run.ID, run.Name)
		recovered++
	}
	return recovered, nil
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
	now := r.now()
	for _, run := range runs {
		if run.Status != domain.ScanStatusPausedWindow || run.ProfileID == "" {
			continue
		}
		if r.isRemoteRun != nil && r.isRemoteRun(run.ID) {
			continue // resumed by its agent (agenthub), never locally
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
