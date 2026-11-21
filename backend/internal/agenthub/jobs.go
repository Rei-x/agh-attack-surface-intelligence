package agenthub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// stateErr reports an invalid pause/resume/stop transition (HTTP 409, same as local runs).
func stateErr(format string, a ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), db.ErrConflict)
}

// IsAgentRun reports whether the run was queued for a remote agent.
func (c *Coordinator) IsAgentRun(runID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLoadedLocked(context.Background())
	_, ok := c.jobs[runID]
	return ok
}

// JobAgent returns the agent id of an agent run ("" for local runs).
func (c *Coordinator) JobAgent(runID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLoadedLocked(context.Background())
	if j, ok := c.jobs[runID]; ok {
		return j.AgentID
	}
	return ""
}

// Enqueue queues a run of an agent-bound profile. The run stays QUEUED until the agent
// claims it; the no-concurrent-run-per-profile rule keeps working because QUEUED is active.
func (c *Coordinator) Enqueue(ctx context.Context, run *domain.ScanRun, profile *domain.ScanProfile) error {
	if run == nil || profile == nil {
		return errors.New("scan run and profile are required")
	}
	now := c.now()
	c.mu.Lock()
	c.ensureLoadedLocked(ctx)
	a, ok := c.agents[profile.AgentID]
	if !ok {
		c.mu.Unlock()
		run.Notes = appendNote(run.Notes, "Profil wskazuje agenta, który nie istnieje (usunięty?) - wybierz agenta w profilu. / Profile points at an unknown agent.")
		return ErrUnknownAgent
	}
	if a.Disabled {
		c.mu.Unlock()
		run.Notes = appendNote(run.Notes, fmt.Sprintf("Agent %q jest wyłączony - skan nie został zlecony. / Agent disabled.", a.Name))
		return ErrAgentOff
	}
	name, site, online := a.Name, a.Site, c.statusLocked(a, now) == domain.AgentStatusOnline
	c.jobs[run.ID] = &Job{RunID: run.ID, AgentID: a.ID, Profile: *profile, QueuedAt: now, UpdatedAt: now}
	c.saveJobsLocked(ctx)
	c.mu.Unlock()

	note := fmt.Sprintf("Zlecono agentowi %q", name)
	if site != "" {
		note += " (" + site + ")"
	}
	if !online {
		note += " - agent jest teraz offline, skan ruszy po jego połączeniu"
	}
	run.Notes = appendNote(run.Notes, note+". / Queued for remote agent.")
	run.Status = domain.ScanStatusQueued
	if err := c.store.UpdateScanRun(ctx, run); err != nil {
		return err
	}
	c.publish(domain.LiveEvent{Type: "scan.queued", ScanRunID: run.ID, Timestamp: now,
		Payload: map[string]any{"agent_id": a.ID, "agent_name": name, "agent_online": online}})
	c.wakeAgent(a.ID)
	return nil
}

func windowOpen(p domain.ScanProfile, now time.Time) bool {
	wg, err := scanner.NewWindowGuard(p.WindowEnabled, p.WindowStart, p.WindowEnd, p.Timezone)
	if err != nil {
		return true
	}
	return wg.IsOpen(now)
}

func terminalChunk(status string) bool {
	return status == domain.ChunkStatusDone || status == domain.ChunkStatusFailed
}

// recomputeCounters derives the run's progress counters from the server ledger, where a
// DONE/FAILED chunk means "results received and ingested".
func recomputeCounters(run *domain.ScanRun, chunks []domain.ScanChunk) {
	if len(chunks) == 0 {
		return
	}
	total, scanned, done, active, services := 0, 0, 0, 0, 0
	for _, ch := range chunks {
		total += ch.IPCount
		if terminalChunk(ch.Status) {
			done++
			scanned += ch.IPCount
			active += ch.ActiveHosts
			services += ch.Services
		}
	}
	run.TotalChunks = len(chunks)
	if total > 0 {
		run.TotalIPs = total
	}
	run.CompletedChunks = done
	run.ScannedIPs = scanned
	run.ActiveHosts = active
	run.ServicesFound = services
}

func applyTiming(run *domain.ScanRun, t Timing) {
	if t.DurationMs > run.DurationMs {
		run.DurationMs = t.DurationMs
	}
	if t.HostsPerSec >= 0 {
		run.HostsPerSec = t.HostsPerSec
	}
	if t.ETASeconds >= 0 {
		run.ETASeconds = t.ETASeconds
	}
	if t.WindowPausedCount > run.WindowPausedCount {
		run.WindowPausedCount = t.WindowPausedCount
	}
}

// mergeLedger adopts the agent's ledger (it may have re-chunked the untouched tail) while the
// server stays authoritative for chunks it already ingested. A chunk the agent reports as
// finished but whose results have not arrived yet is shown as RUNNING.
func mergeLedger(runID string, server, agent []domain.ScanChunk) []domain.ScanChunk {
	srv := make(map[string]domain.ScanChunk, len(server))
	for _, ch := range server {
		srv[ch.ID] = ch
	}
	out := make([]domain.ScanChunk, 0, len(agent))
	seen := make(map[string]bool, len(agent))
	for _, a := range agent {
		if a.ID == "" || seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		if s, ok := srv[a.ID]; ok && terminalChunk(s.Status) {
			out = append(out, s)
			continue
		}
		if terminalChunk(a.Status) {
			a.Status = domain.ChunkStatusRunning
		}
		a.ScanRunID = runID
		out = append(out, a)
	}
	for _, s := range server {
		if terminalChunk(s.Status) && !seen[s.ID] {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ChunkIndex < out[j].ChunkIndex })
	return out
}

func (c *Coordinator) jobFor(runID, agentID string) (*Job, error) {
	j, ok := c.jobs[runID]
	if !ok || j.AgentID != agentID {
		return nil, ErrNotYourRun
	}
	return j, nil
}

// busyLocked reports whether the agent holds a live lease on a run other than exceptRun.
func (c *Coordinator) busyLocked(agentID, exceptRun string, now time.Time) bool {
	for _, j := range c.jobs {
		if j.AgentID == agentID && !j.Done && j.RunID != exceptRun && j.Instance != "" && now.Before(c.leaseUntil[j.RunID]) {
			return true
		}
	}
	return false
}

// holdLeaseLocked checks that instance may act on the run and renews its lease.
func (c *Coordinator) holdLeaseLocked(j *Job, instance string, now time.Time) error {
	if j.Instance != "" && j.Instance != instance && now.Before(c.leaseUntil[j.RunID]) {
		return ErrLeased
	}
	j.Instance = instance
	c.leaseUntil[j.RunID] = now.Add(c.opts.LeaseTTL)
	return nil
}

// ---------------------------------------------------------------------------------------
// Job queue

// NextJob hands the agent its next job, waiting up to wait for one to appear (long-poll).
// Priority: a run this agent was already executing (resume after restart or network loss),
// then a window-paused run whose window is open again, then the oldest queued run. An agent
// executes at most one run at a time, and a run is leased to one agent instance.
func (c *Coordinator) NextJob(ctx context.Context, agentID, instance string, wait time.Duration) (*JobSpec, error) {
	if wait > c.opts.MaxLongPoll {
		wait = c.opts.MaxLongPoll
	}
	deadline := time.Now().Add(wait)
	for {
		spec, err := c.tryClaim(ctx, agentID, instance)
		if err != nil || spec != nil {
			return spec, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil
		}
		c.mu.Lock()
		ch := c.wakeChanLocked(agentID)
		c.mu.Unlock()
		t := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, nil
		case <-ch:
			t.Stop()
		case <-t.C:
			return c.tryClaim(ctx, agentID, instance)
		}
	}
}

func (c *Coordinator) tryClaim(ctx context.Context, agentID, instance string) (*JobSpec, error) {
	c.mu.Lock()
	c.ensureLoadedLocked(ctx)
	a, ok := c.agents[agentID]
	if !ok {
		c.mu.Unlock()
		return nil, ErrUnknownAgent
	}
	if a.Disabled {
		c.mu.Unlock()
		return nil, ErrAgentOff
	}
	var cands []Job
	for _, j := range c.jobs {
		if j.AgentID == agentID && !j.Done {
			cands = append(cands, *j)
		}
	}
	c.mu.Unlock()
	sort.Slice(cands, func(i, k int) bool { return cands[i].QueuedAt.Before(cands[k].QueuedAt) })

	now := c.now()
	var running, windowed, queued []string
	var finished []string
	for _, j := range cands {
		run, err := c.store.GetScanRun(ctx, j.RunID)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				finished = append(finished, j.RunID)
			}
			continue
		}
		switch run.Status {
		case domain.ScanStatusRunning, domain.ScanStatusCalibrating:
			running = append(running, j.RunID)
		case domain.ScanStatusPausedWindow:
			if windowOpen(j.Profile, now) {
				windowed = append(windowed, j.RunID)
			}
		case domain.ScanStatusQueued:
			queued = append(queued, j.RunID)
		case domain.ScanStatusPausedUser:
		default:
			finished = append(finished, j.RunID)
		}
	}
	if len(finished) > 0 {
		c.mu.Lock()
		for _, id := range finished {
			if j, ok := c.jobs[id]; ok {
				j.Done = true
			}
		}
		c.saveJobsLocked(ctx)
		c.mu.Unlock()
	}
	// A run this instance already holds comes first (restart / retry of a claim).
	order := append(append(running, windowed...), queued...)
	c.mu.Lock()
	sort.SliceStable(order, func(i, k int) bool {
		hi := c.jobs[order[i]] != nil && c.jobs[order[i]].Instance == instance
		hk := c.jobs[order[k]] != nil && c.jobs[order[k]].Instance == instance
		return hi && !hk
	})
	c.mu.Unlock()
	for _, id := range order {
		spec, err := c.claim(ctx, id, agentID, instance)
		if err != nil || spec != nil {
			return spec, err
		}
	}
	return nil, nil
}

func (c *Coordinator) claim(ctx context.Context, runID, agentID, instance string) (*JobSpec, error) {
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	run, err := c.store.GetScanRun(ctx, runID)
	if err != nil {
		return nil, nil
	}
	now := c.now()
	c.mu.Lock()
	j, err := c.jobFor(runID, agentID)
	if err != nil || j.Done {
		c.mu.Unlock()
		return nil, nil
	}
	switch run.Status {
	case domain.ScanStatusQueued, domain.ScanStatusRunning, domain.ScanStatusCalibrating:
	case domain.ScanStatusPausedWindow:
		if !windowOpen(j.Profile, now) {
			c.mu.Unlock()
			return nil, nil
		}
	default:
		c.mu.Unlock()
		return nil, nil
	}
	// One run per agent at a time: another live lease of this agent blocks the claim.
	if c.busyLocked(agentID, runID, now) {
		c.mu.Unlock()
		return nil, nil
	}
	if err := c.holdLeaseLocked(j, instance, now); err != nil {
		c.mu.Unlock()
		return nil, nil
	}
	resumed := j.Offline || run.Status == domain.ScanStatusPausedWindow
	j.Offline = false
	j.Control = ""
	j.UpdatedAt = now
	profile := j.Profile
	agentName := ""
	if a := c.agents[agentID]; a != nil {
		agentName = a.Name
	}
	c.saveJobsLocked(ctx)
	c.mu.Unlock()

	// Use the current saved profile (edits since queueing apply) while it still targets this agent.
	if profile.ID != "" {
		if p, perr := c.store.GetProfile(ctx, profile.ID); perr == nil && p.AgentID == agentID {
			profile = *p
		}
	}
	exclusions, _ := c.store.ListExclusions(ctx)
	chunks, _ := c.store.GetScanChunks(ctx, runID)
	for i := range chunks {
		if !terminalChunk(chunks[i].Status) {
			chunks[i].Status = domain.ChunkStatusPending
			chunks[i].StartedAt = nil
		}
	}
	if len(chunks) > 0 {
		_ = c.store.SaveScanChunks(ctx, runID, chunks)
		recomputeCounters(run, chunks)
		run.Status = domain.ScanStatusRunning
	} else {
		run.Status = domain.ScanStatusQueued
	}
	run.FinishedAt = nil
	if resumed {
		run.Notes = appendNote(run.Notes, fmt.Sprintf("%s: agent %q wznowił skan od punktu kontrolnego (%d/%d fragmentów gotowych). / Resumed by agent from checkpoint.",
			now.Format("2006-01-02 15:04"), agentName, run.CompletedChunks, run.TotalChunks))
	}
	run.RawNmapXML = ""
	if err := c.store.UpdateScanRun(ctx, run); err != nil {
		return nil, err
	}
	c.publish(domain.LiveEvent{Type: "scan.assigned", ScanRunID: runID, Timestamp: now,
		Payload: map[string]any{"agent_id": agentID, "agent_name": agentName, "resumed": resumed}})

	return &JobSpec{
		RunID:      runID,
		RunName:    run.Name,
		Profile:    profile,
		Exclusions: exclusions,
		Chunks:     chunks,
		Run: RunCounters{
			TotalIPs: run.TotalIPs, TotalChunks: run.TotalChunks, ScannedIPs: run.ScannedIPs,
			CompletedChunks: run.CompletedChunks, ActiveHosts: run.ActiveHosts, ServicesFound: run.ServicesFound,
			DurationMs: run.DurationMs, WindowPausedCount: run.WindowPausedCount, StartedAt: run.StartedAt,
		},
		UnstableHosts: c.unstableFor(ctx, profile, exclusions),
	}, nil
}

type noResolver struct{}

func (noResolver) LookupHost(context.Context, string) ([]string, error) {
	return nil, errors.New("no DNS on the server side")
}

// unstableFor returns tracked hosts inside the job's IP scope, so the agent's Stage 4 re-probe
// works like a local scan without handing the agent the whole inventory.
func (c *Coordinator) unstableFor(ctx context.Context, p domain.ScanProfile, excl []domain.TargetExclusion) []string {
	if c.opts.TrackedHosts == nil {
		return nil
	}
	tracked := c.opts.TrackedHosts(ctx)
	if len(tracked) == 0 {
		return nil
	}
	res, err := scanner.ParseAndNormalizeTargets(ctx, p.Targets, excl, noResolver{})
	if err != nil || res == nil {
		return nil
	}
	scope := make(map[string]struct{}, len(res.IPs))
	for _, ip := range res.IPs {
		scope[ip] = struct{}{}
	}
	var out []string
	for _, ip := range tracked {
		if _, ok := scope[ip]; ok {
			out = append(out, ip)
		}
	}
	return out
}

// Start records the coverage ledger the agent planned for a fresh run.
func (c *Coordinator) Start(ctx context.Context, agentID, instance, runID string, req StartRequest) (*ControlResponse, error) {
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	run, err := c.store.GetScanRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	now := c.now()
	c.mu.Lock()
	j, err := c.jobFor(runID, agentID)
	if err == nil {
		err = c.holdLeaseLocked(j, instance, now)
	}
	control := ""
	if j != nil {
		control = j.Control
	}
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !isActive(run.Status) {
		return &ControlResponse{OK: true, Control: ControlStop}, nil
	}
	if existing, _ := c.store.GetScanChunks(ctx, runID); len(existing) > 0 {
		return &ControlResponse{OK: true, Duplicate: true, Control: control}, nil
	}
	if len(req.Chunks) == 0 {
		return nil, errors.New("chunks are required")
	}
	chunks := make([]domain.ScanChunk, 0, len(req.Chunks))
	for _, ch := range req.Chunks {
		if ch.ID == "" {
			return nil, errors.New("chunk id is required")
		}
		ch.ScanRunID = runID
		if terminalChunk(ch.Status) {
			ch.Status = domain.ChunkStatusPending
		}
		chunks = append(chunks, ch)
	}
	if err := c.store.SaveScanChunks(ctx, runID, chunks); err != nil {
		return nil, err
	}
	recomputeCounters(run, chunks)
	if req.TotalIPs > 0 {
		run.TotalIPs = req.TotalIPs
	}
	run.ETASeconds = req.ETASeconds
	if run.Status == domain.ScanStatusQueued {
		run.Status = domain.ScanStatusRunning
	}
	run.RawNmapXML = ""
	if err := c.store.UpdateScanRun(ctx, run); err != nil {
		return nil, err
	}
	c.publish(domain.LiveEvent{Type: "scan.started", ScanRunID: runID, Timestamp: now, Payload: map[string]any{
		"name": run.Name, "total_ips": run.TotalIPs, "total_chunks": run.TotalChunks, "eta_seconds": run.ETASeconds, "agent_id": agentID,
	}})
	return &ControlResponse{OK: true, Control: control}, nil
}

// relayedEvents are the engine events an agent may forward to the SSE hub.
var relayedEvents = map[string]bool{
	"scan.workers": true, "scan.chunk": true, "scan.progress": true, "scan.rechunk": true,
	"governor.throttle": true, "scan.host_discovered": true, "scan.paused_window": true, "scan.completed": true,
}

func (c *Coordinator) relay(runID string, events []domain.LiveEvent) {
	if len(events) > 500 {
		events = events[len(events)-500:]
	}
	for _, ev := range events {
		if !relayedEvents[ev.Type] {
			continue
		}
		ev.ScanRunID = runID
		if ev.Timestamp.IsZero() {
			ev.Timestamp = c.now()
		}
		c.publish(ev)
	}
}

// Progress stores the agent's ledger and counters and relays its live events.
func (c *Coordinator) Progress(ctx context.Context, agentID, instance, runID string, req ProgressRequest) (*ControlResponse, error) {
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	run, err := c.store.GetScanRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	now := c.now()
	c.mu.Lock()
	j, err := c.jobFor(runID, agentID)
	if err == nil {
		err = c.holdLeaseLocked(j, instance, now)
	}
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	control, wasOffline := j.Control, j.Offline
	if wasOffline {
		j.Offline = false
		c.saveJobsLocked(ctx)
	}
	c.mu.Unlock()

	chunks, _ := c.store.GetScanChunks(ctx, runID)
	if len(req.Chunks) > 0 {
		chunks = mergeLedger(runID, chunks, req.Chunks)
		if err := c.store.SaveScanChunks(ctx, runID, chunks); err != nil {
			return nil, err
		}
	}
	recomputeCounters(run, chunks)
	applyTiming(run, req.Timing)
	switch {
	case run.Status == domain.ScanStatusQueued && len(chunks) > 0:
		run.Status = domain.ScanStatusRunning
	case run.Status == domain.ScanStatusPausedWindow && wasOffline:
		run.Status = domain.ScanStatusRunning
		run.Notes = appendNote(run.Notes, now.Format("2006-01-02 15:04")+": agent znów odpowiada - skan kontynuowany. / Agent back, scan continues.")
	}
	if !isActive(run.Status) && control == "" {
		control = ControlStop
	}
	run.RawNmapXML = ""
	if err := c.store.UpdateScanRun(ctx, run); err != nil {
		return nil, err
	}
	c.relay(runID, req.Events)
	return &ControlResponse{OK: true, Control: control}, nil
}

// UploadChunk ingests one finished chunk through the unified pipeline, exactly like the local
// runner ingests a segment: missing-host detection is scoped to the chunk's IPs (only for a
// DONE chunk), counters come from the ledger, an ingest error fails the run. Idempotent by
// chunk id.
func (c *Coordinator) UploadChunk(ctx context.Context, agentID, instance, runID string, up ChunkUpload) (*ControlResponse, error) {
	ch := up.Chunk
	if ch.ID == "" || !terminalChunk(ch.Status) {
		return nil, errors.New("chunk with id and status DONE or FAILED is required")
	}
	if len(ch.Targets) > 1<<20 {
		return nil, errors.New("chunk too large")
	}
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	run, err := c.store.GetScanRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	now := c.now()
	c.mu.Lock()
	j, err := c.jobFor(runID, agentID)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if j.Instance == instance {
		c.leaseUntil[runID] = now.Add(c.opts.LeaseTTL)
	}
	control, profile := j.Control, j.Profile
	c.mu.Unlock()

	chunks, _ := c.store.GetScanChunks(ctx, runID)
	for _, s := range chunks {
		if s.ID == ch.ID && terminalChunk(s.Status) {
			return &ControlResponse{OK: true, Duplicate: true, Control: control}, nil
		}
	}

	// Accept only observations of IPs this chunk actually covered.
	inChunk := make(map[string]struct{}, len(ch.Targets))
	for _, ip := range ch.Targets {
		inChunk[ip] = struct{}{}
	}
	obs := make([]domain.ObservedHost, 0, len(up.Observations))
	dropped := 0
	for _, o := range up.Observations {
		if _, ok := inChunk[o.IP]; ok {
			obs = append(obs, o)
		} else {
			dropped++
		}
	}
	if dropped > 0 {
		log.Printf("[WARN] agent %s run %s chunk %s: dropped %d observations outside the chunk", agentID, runID, ch.ID, dropped)
	}

	done := ch.Status == domain.ChunkStatusDone
	var scope []string
	if done {
		scope = ch.Targets
	}
	if c.pipeline != nil && (len(obs) > 0 || (done && len(scope) > 0)) {
		if _, perr := c.pipeline.ProcessObservations(ctx, ingest.IngestRequest{
			ScanRunID:        runID,
			ProfileID:        run.ProfileID,
			RunType:          domain.ScanTypeActive,
			ScanName:         run.Name,
			Notes:            run.Notes,
			TriggeredBy:      run.TriggeredBy,
			Observations:     obs,
			ScopeIPs:         scope,
			MarkMissingHosts: done && len(scope) > 0,
			MissingThreshold: profile.MissingThreshold,
			GracePeriodHours: profile.GracePeriodHours,
		}); perr != nil {
			log.Printf("[ERROR] agent run %s ingest failed: %v", runID, perr)
			if cur, gerr := c.store.GetScanRun(ctx, runID); gerr == nil {
				run = cur
			}
			run.Status = domain.ScanStatusFailed
			run.FinishedAt = &now
			run.Notes = appendNote(run.Notes, "zapis wyników nie powiódł się: "+perr.Error())
			run.RawNmapXML = ""
			_ = c.store.UpdateScanRun(ctx, run)
			c.mu.Lock()
			j.Control, j.Done = ControlStop, true
			c.saveJobsLocked(ctx)
			c.mu.Unlock()
			return &ControlResponse{OK: false, Control: ControlStop, Error: perr.Error()}, nil
		}
		// The pipeline updated ChangesDetected on the stored run.
		if cur, gerr := c.store.GetScanRun(ctx, runID); gerr == nil {
			run = cur
		}
	}

	ch.ScanRunID = runID
	replaced := false
	for i := range chunks {
		if chunks[i].ID == ch.ID {
			chunks[i] = ch
			replaced = true
			break
		}
	}
	if !replaced {
		chunks = append(chunks, ch)
		sort.SliceStable(chunks, func(a, b int) bool { return chunks[a].ChunkIndex < chunks[b].ChunkIndex })
	}
	if err := c.store.SaveScanChunks(ctx, runID, chunks); err != nil {
		return nil, err
	}
	recomputeCounters(run, chunks)
	if !isActive(run.Status) && control == "" {
		control = ControlStop
	}
	run.RawNmapXML = ""
	if err := c.store.UpdateScanRun(ctx, run); err != nil {
		return nil, err
	}
	return &ControlResponse{OK: true, Control: control, Dropped: dropped}, nil
}

// Finish closes one execution segment: merges the segment's raw nmap XML into the run and
// applies the outcome. Idempotent by segment id.
func (c *Coordinator) Finish(ctx context.Context, agentID, instance, runID string, req FinishRequest) (*ControlResponse, error) {
	switch req.Outcome {
	case OutcomeCompleted, OutcomePausedWindow, OutcomePausedUser, OutcomeStopped, OutcomeInterrupted, OutcomeFailed, OutcomeRefused:
	default:
		return nil, fmt.Errorf("unknown outcome %q", req.Outcome)
	}
	if req.SegmentID == "" {
		return nil, errors.New("segment_id is required")
	}
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	run, err := c.store.GetScanRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	now := c.now()
	c.mu.Lock()
	j, err := c.jobFor(runID, agentID)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	for _, s := range j.Segments {
		if s == req.SegmentID {
			c.mu.Unlock()
			return &ControlResponse{OK: true, Duplicate: true}, nil
		}
	}
	agentName := ""
	if a := c.agents[agentID]; a != nil {
		agentName = a.Name
	}
	c.mu.Unlock()

	chunks, _ := c.store.GetScanChunks(ctx, runID)
	if len(req.Chunks) > 0 {
		chunks = mergeLedger(runID, chunks, req.Chunks)
		_ = c.store.SaveScanChunks(ctx, runID, chunks)
	}
	recomputeCounters(run, chunks)
	applyTiming(run, req.Timing)
	if req.RawNmapXML != "" {
		run.RawNmapXML = scanner.MergeNmapXML([]string{run.RawNmapXML, req.RawNmapXML})
		run.HasRawNmapXML = run.RawNmapXML != ""
	} else {
		run.RawNmapXML = "" // keep the stored document
	}
	allDone := len(chunks) > 0
	for _, ch := range chunks {
		if !terminalChunk(ch.Status) {
			allDone = false
		}
	}
	running := run.Status == domain.ScanStatusRunning || run.Status == domain.ScanStatusQueued || run.Status == domain.ScanStatusCalibrating
	completed, terminal := false, false
	switch req.Outcome {
	case OutcomeCompleted:
		switch {
		case allDone && (running || run.Status == domain.ScanStatusPausedUser || run.Status == domain.ScanStatusPausedWindow):
			run.Status = domain.ScanStatusCompleted
			run.FinishedAt = &now
			run.ETASeconds = 0
			completed, terminal = true, true
		case !allDone && running:
			// Results of some chunks never arrived: let the agent pick the run up again.
			run.Status = domain.ScanStatusQueued
		}
	case OutcomePausedWindow:
		if running {
			run.Status = domain.ScanStatusPausedWindow
			run.FinishedAt = nil
		}
	case OutcomePausedUser:
		if running && run.Status == domain.ScanStatusRunning {
			run.Status = domain.ScanStatusPausedUser
		}
	case OutcomeStopped:
		if running && run.Status == domain.ScanStatusRunning {
			run.Status = domain.ScanStatusStopped
			run.FinishedAt = &now
			terminal = true
		}
	case OutcomeInterrupted:
		// Agent shut down; the run stays RUNNING and is resumed when the agent reconnects
		// (or parked by the offline sweep if it does not).
	case OutcomeFailed, OutcomeRefused:
		if isActive(run.Status) {
			var msg string
			if req.Outcome == OutcomeRefused {
				msg = fmt.Sprintf("agent %q odmówił wykonania (lokalna polityka bezpieczeństwa): %s / refused by agent safety policy", agentName, req.Error)
			} else {
				msg = fmt.Sprintf("agent %q: skan nie powiódł się: %s", agentName, req.Error)
			}
			run.Status = domain.ScanStatusFailed
			run.FinishedAt = &now
			run.Notes = appendNote(run.Notes, clip(msg, 2000))
			terminal = true
		}
	}
	if !isActive(run.Status) {
		terminal = true
	}
	if err := c.store.UpdateScanRun(ctx, run); err != nil {
		return nil, err
	}

	c.mu.Lock()
	j.Segments = append(j.Segments, req.SegmentID)
	if len(j.Segments) > 50 {
		j.Segments = j.Segments[len(j.Segments)-50:]
	}
	c.leaseUntil[runID] = now // released: the next claim may take it at once
	if req.Outcome != OutcomeInterrupted {
		j.Instance = ""
	}
	j.Control = ""
	j.Done = terminal
	j.UpdatedAt = now
	c.saveJobsLocked(ctx)
	c.mu.Unlock()

	c.relay(runID, req.Events)
	if req.Outcome == OutcomePausedUser || req.Outcome == OutcomeStopped {
		c.publish(domain.LiveEvent{Type: "scan.paused", ScanRunID: runID, Timestamp: now, Payload: map[string]any{"status": run.Status}})
	}
	if completed && c.opts.OnRunCompleted != nil {
		go c.opts.OnRunCompleted(runID)
	}
	c.wakeAgent(agentID)
	return &ControlResponse{OK: true}, nil
}

// Heartbeat records liveness/capabilities and returns pending pause/stop commands.
func (c *Coordinator) Heartbeat(ctx context.Context, agentID, instance string, req HeartbeatRequest) (*HeartbeatResponse, error) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.agents[agentID]
	if !ok {
		return nil, ErrUnknownAgent
	}
	caps := sanitizeCaps(req.Capabilities)
	ver := clip(req.Version, 64)
	if ver != a.Version || fmt.Sprint(caps) != fmt.Sprint(a.Capabilities) {
		a.Version, a.Capabilities = ver, caps
		c.saveAgentsLocked(ctx)
	}
	control := map[string]string{}
	for _, j := range c.jobs {
		if j.AgentID != agentID || j.Done {
			continue
		}
		if j.Control != "" {
			control[j.RunID] = j.Control
		}
		if j.Instance == instance && j.RunID == req.CurrentRunID {
			c.leaseUntil[j.RunID] = now.Add(c.opts.LeaseTTL)
		}
	}
	if id := req.CurrentRunID; id != "" {
		if j, ok := c.jobs[id]; !ok || j.AgentID != agentID || (j.Done && control[id] == "") {
			control[id] = ControlStop
		}
	}
	return &HeartbeatResponse{ServerTime: now, HeartbeatSec: int(c.opts.HeartbeatInterval / time.Second), Control: control}, nil
}

// ---------------------------------------------------------------------------------------
// User actions on agent runs (called by the dispatching scan runner)

// Pause marks an agent run paused; a connected agent receives the pause control on its next heartbeat.
func (c *Coordinator) Pause(ctx context.Context, runID string) error {
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	run, err := c.store.GetScanRun(ctx, runID)
	if err != nil {
		return err
	}
	switch run.Status {
	case domain.ScanStatusQueued, domain.ScanStatusCalibrating, domain.ScanStatusRunning, domain.ScanStatusPausedWindow:
	default:
		return stateErr("nie można wstrzymać skanu w stanie %s / cannot pause a scan that is %s", run.Status, run.Status)
	}
	c.mu.Lock()
	if j, ok := c.jobs[runID]; ok {
		if j.Instance != "" {
			j.Control = ControlPause
		}
		j.Offline = false
		c.saveJobsLocked(ctx)
	}
	c.mu.Unlock()
	run.Status = domain.ScanStatusPausedUser
	run.RawNmapXML = ""
	if err := c.store.UpdateScanRun(ctx, run); err != nil {
		return err
	}
	c.publish(domain.LiveEvent{Type: "scan.paused", ScanRunID: runID, Timestamp: c.now(), Payload: map[string]any{"status": run.Status}})
	return nil
}

// Resume re-queues a paused agent run (unfinished chunks back to pending) and wakes its agent.
func (c *Coordinator) Resume(ctx context.Context, runID string) error {
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	run, err := c.store.GetScanRun(ctx, runID)
	if err != nil {
		return err
	}
	if run.Status != domain.ScanStatusPausedUser && run.Status != domain.ScanStatusPausedWindow {
		return stateErr("można wznowić tylko wstrzymany skan (stan: %s) / only a paused scan can be resumed", run.Status)
	}
	agentID := ""
	c.mu.Lock()
	if j, ok := c.jobs[runID]; ok {
		j.Control, j.Offline, j.Done = "", false, false
		agentID = j.AgentID
		c.saveJobsLocked(ctx)
	}
	c.mu.Unlock()
	chunks, _ := c.store.GetScanChunks(ctx, runID)
	for i := range chunks {
		if !terminalChunk(chunks[i].Status) {
			chunks[i].Status = domain.ChunkStatusPending
		}
	}
	if len(chunks) > 0 {
		_ = c.store.SaveScanChunks(ctx, runID, chunks)
	}
	run.Status = domain.ScanStatusQueued
	run.FinishedAt = nil
	run.RawNmapXML = ""
	if err := c.store.UpdateScanRun(ctx, run); err != nil {
		return err
	}
	c.publish(domain.LiveEvent{Type: "scan.queued", ScanRunID: runID, Timestamp: c.now(), Payload: map[string]any{"agent_id": agentID}})
	c.wakeAgent(agentID)
	return nil
}

// Stop marks an agent run stopped; a connected agent receives the stop control.
func (c *Coordinator) Stop(ctx context.Context, runID string) error {
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	run, err := c.store.GetScanRun(ctx, runID)
	if err != nil {
		return err
	}
	if !isActive(run.Status) {
		return stateErr("skan jest już zakończony (%s) / scan already finished", run.Status)
	}
	c.mu.Lock()
	if j, ok := c.jobs[runID]; ok {
		j.Control = ControlStop
		if j.Instance == "" {
			j.Done = true
		}
		c.saveJobsLocked(ctx)
	}
	c.mu.Unlock()
	now := c.now()
	run.Status = domain.ScanStatusStopped
	run.FinishedAt = &now
	run.RawNmapXML = ""
	return c.store.UpdateScanRun(ctx, run)
}

// ---------------------------------------------------------------------------------------
// Offline detection

// StartSweeper marks silent agents offline and parks their running runs.
func (c *Coordinator) StartSweeper(ctx context.Context) {
	every := c.opts.OfflineAfter / 6
	if every < time.Second {
		every = time.Second
	}
	if every > 15*time.Second {
		every = 15 * time.Second
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.Sweep(ctx)
			}
		}
	}()
}

// Sweep runs one offline check: an agent silent for longer than OfflineAfter is marked
// offline, and a run it was executing (lease expired) becomes PAUSED_WINDOW with a note. The
// run resumes from its chunk checkpoint as soon as the agent asks for work again.
func (c *Coordinator) Sweep(ctx context.Context) {
	now := c.now()
	type parked struct{ runID, agent string }
	var toPark []parked
	c.mu.Lock()
	c.ensureLoadedLocked(ctx)
	changed := false
	for _, a := range c.agents {
		if c.statusLocked(a, now) == domain.AgentStatusOffline && a.Status != domain.AgentStatusOffline {
			a.Status = domain.AgentStatusOffline
			changed = true
			c.publish(domain.LiveEvent{Type: "agent.offline", Timestamp: now, Payload: map[string]any{"agent_id": a.ID, "name": a.Name}})
			log.Printf("[WARN] agent %s (%s) is offline (silent for more than %s)", a.Name, a.ID, c.opts.OfflineAfter)
		}
	}
	if changed {
		c.saveAgentsLocked(ctx)
	}
	for _, j := range c.jobs {
		if j.Done || j.Instance == "" {
			continue
		}
		a := c.agents[j.AgentID]
		if a == nil || c.statusLocked(a, now) == domain.AgentStatusOnline || now.Before(c.leaseUntil[j.RunID]) {
			continue
		}
		toPark = append(toPark, parked{j.RunID, a.Name})
	}
	c.mu.Unlock()
	for _, p := range toPark {
		c.parkOffline(ctx, p.runID, p.agent, now)
	}
}

func (c *Coordinator) parkOffline(ctx context.Context, runID, agentName string, now time.Time) {
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	run, err := c.store.GetScanRun(ctx, runID)
	if err != nil {
		return
	}
	c.mu.Lock()
	j, ok := c.jobs[runID]
	if !ok {
		c.mu.Unlock()
		return
	}
	j.Instance = ""
	parkIt := run.Status == domain.ScanStatusRunning || run.Status == domain.ScanStatusCalibrating
	if parkIt {
		j.Offline = true
	}
	c.saveJobsLocked(ctx)
	c.mu.Unlock()
	if !parkIt {
		return
	}
	chunks, _ := c.store.GetScanChunks(ctx, runID)
	for i := range chunks {
		if !terminalChunk(chunks[i].Status) {
			chunks[i].Status = domain.ChunkStatusPending
			chunks[i].StartedAt = nil
		}
	}
	_ = c.store.SaveScanChunks(ctx, runID, chunks)
	recomputeCounters(run, chunks)
	run.Status = domain.ScanStatusPausedWindow
	run.FinishedAt = nil
	run.Notes = appendNote(run.Notes, fmt.Sprintf(
		"%s: agent %q przestał odpowiadać (offline) - skan wstrzymany po %d/%d fragmentach; zostanie wznowiony od punktu kontrolnego, gdy agent wróci. / Agent offline: scan paused, resumes from checkpoint when the agent returns.",
		now.Format("2006-01-02 15:04"), agentName, run.CompletedChunks, run.TotalChunks))
	run.RawNmapXML = ""
	_ = c.store.UpdateScanRun(ctx, run)
	c.publish(domain.LiveEvent{Type: "scan.paused", ScanRunID: runID, Timestamp: now,
		Payload: map[string]any{"status": run.Status, "reason": "agent_offline", "agent_name": agentName}})
	log.Printf("[WARN] agent run %s parked: agent %s offline", runID, agentName)
}
