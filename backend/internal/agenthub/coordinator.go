package agenthub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

// Settings documents (encrypted at rest by the store, persisted in the file snapshot and in
// PostgreSQL app_settings) holding all agent state. No extra tables or snapshot fields.
const (
	settingAgents = "agents"
	settingTokens = "agent_enroll_tokens"
	settingJobs   = "agent_jobs"
)

var (
	ErrUnauthorized = errors.New("invalid agent credential")
	ErrTokenInvalid = errors.New("enrollment token is invalid, expired or already used")
	ErrNotYourRun   = errors.New("run is not assigned to this agent")
	ErrLeased       = errors.New("run is being executed by another instance of this agent")
	ErrUnknownAgent = errors.New("unknown agent")
	ErrAgentOff     = errors.New("agent is disabled")
)

// Job binds one scan run to the agent executing it.
type Job struct {
	RunID     string             `json:"run_id"`
	AgentID   string             `json:"agent_id"`
	Profile   domain.ScanProfile `json:"profile"`
	QueuedAt  time.Time          `json:"queued_at"`
	Instance  string             `json:"instance,omitempty"` // lease holder
	Control   string             `json:"control,omitempty"`  // pending pause/stop
	Offline   bool               `json:"offline,omitempty"`  // paused because the agent went silent
	Segments  []string           `json:"segments,omitempty"` // applied finish segment ids
	Done      bool               `json:"done,omitempty"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// Options tune the coordinator; zero values get sensible defaults.
type Options struct {
	HeartbeatInterval time.Duration // told to agents (default 15s)
	OfflineAfter      time.Duration // silence before an agent counts as offline (default 90s)
	LeaseTTL          time.Duration // a run's lease survives this long without agent calls (default 60s)
	MaxLongPoll       time.Duration // cap for jobs/next?wait= (default 25s)
	Now               func() time.Time
	// OnRunCompleted runs after an agent run reached COMPLETED (DefectDojo auto-push).
	OnRunCompleted func(runID string)
	// TrackedHosts returns IPs worth an unstable-host re-probe (same list the local runner
	// gives its engine); filtered to the job's scope before being sent to the agent.
	TrackedHosts func(ctx context.Context) []string
}

// Coordinator owns the agent registry, enrollment tokens and the agent job queue.
type Coordinator struct {
	store    db.Store
	settings db.SettingsStore // nil: state lives only in memory (stores without settings)
	pipeline *ingest.Pipeline
	emit     func(domain.LiveEvent)
	opts     Options
	bootAt   time.Time

	mu            sync.Mutex
	loaded        bool
	agents        map[string]*domain.Agent
	tokens        []domain.AgentEnrollToken
	jobs          map[string]*Job
	persistedSeen map[string]time.Time
	leaseUntil    map[string]time.Time // run id -> lease expiry (memory only)
	wake          map[string]chan struct{}

	runLocksMu sync.Mutex
	runLocks   map[string]*sync.Mutex
}

// New creates a coordinator. emit publishes live events (the SSE hub); may be nil.
func New(store db.Store, pipeline *ingest.Pipeline, emit func(domain.LiveEvent), opts Options) *Coordinator {
	if opts.HeartbeatInterval <= 0 {
		opts.HeartbeatInterval = 15 * time.Second
	}
	if opts.OfflineAfter <= 0 {
		opts.OfflineAfter = 90 * time.Second
	}
	if opts.LeaseTTL <= 0 {
		opts.LeaseTTL = 60 * time.Second
	}
	if opts.MaxLongPoll <= 0 {
		opts.MaxLongPoll = 25 * time.Second
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	c := &Coordinator{
		store:         store,
		pipeline:      pipeline,
		emit:          emit,
		opts:          opts,
		agents:        map[string]*domain.Agent{},
		jobs:          map[string]*Job{},
		persistedSeen: map[string]time.Time{},
		leaseUntil:    map[string]time.Time{},
		wake:          map[string]chan struct{}{},
		runLocks:      map[string]*sync.Mutex{},
	}
	c.bootAt = opts.Now()
	if ss, ok := store.(db.SettingsStore); ok {
		c.settings = ss
	}
	return c
}

// Options returns the effective options.
func (c *Coordinator) Options() Options { return c.opts }

func (c *Coordinator) now() time.Time { return c.opts.Now() }

func (c *Coordinator) publish(ev domain.LiveEvent) {
	if c.emit != nil {
		c.emit(ev)
	}
}

func (c *Coordinator) ensureLoadedLocked(ctx context.Context) {
	if c.loaded {
		return
	}
	c.loaded = true
	if c.settings == nil {
		return
	}
	var agents []domain.Agent
	if _, err := c.settings.GetSetting(ctx, settingAgents, &agents); err != nil {
		log.Printf("[WARN] agents: load registry: %v", err)
	}
	for i := range agents {
		a := agents[i]
		c.agents[a.ID] = &a
		if a.LastSeenAt != nil {
			c.persistedSeen[a.ID] = *a.LastSeenAt
		}
	}
	if _, err := c.settings.GetSetting(ctx, settingTokens, &c.tokens); err != nil {
		log.Printf("[WARN] agents: load enrollment tokens: %v", err)
	}
	var jobs []Job
	if _, err := c.settings.GetSetting(ctx, settingJobs, &jobs); err != nil {
		log.Printf("[WARN] agents: load jobs: %v", err)
	}
	for i := range jobs {
		j := jobs[i]
		c.jobs[j.RunID] = &j
	}
}

func (c *Coordinator) saveAgentsLocked(ctx context.Context) {
	if c.settings == nil {
		return
	}
	out := make([]domain.Agent, 0, len(c.agents))
	for _, a := range c.agents {
		out = append(out, *a)
		if a.LastSeenAt != nil {
			c.persistedSeen[a.ID] = *a.LastSeenAt
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnrolledAt.Before(out[j].EnrolledAt) })
	if err := c.settings.SaveSetting(ctx, settingAgents, out); err != nil {
		log.Printf("[ERROR] agents: save registry: %v", err)
	}
}

func (c *Coordinator) saveTokensLocked(ctx context.Context) {
	if c.settings == nil {
		return
	}
	if err := c.settings.SaveSetting(ctx, settingTokens, c.tokens); err != nil {
		log.Printf("[ERROR] agents: save enrollment tokens: %v", err)
	}
}

// saveJobsLocked persists the job table, keeping at most 200 finished jobs.
func (c *Coordinator) saveJobsLocked(ctx context.Context) {
	all := make([]Job, 0, len(c.jobs))
	for _, j := range c.jobs {
		all = append(all, *j)
	}
	sort.Slice(all, func(i, k int) bool { return all[i].QueuedAt.After(all[k].QueuedAt) })
	kept, done := all[:0], 0
	for _, j := range all {
		if j.Done {
			done++
			if done > 200 {
				delete(c.jobs, j.RunID)
				continue
			}
		}
		kept = append(kept, j)
	}
	if c.settings == nil {
		return
	}
	if err := c.settings.SaveSetting(ctx, settingJobs, kept); err != nil {
		log.Printf("[ERROR] agents: save jobs: %v", err)
	}
}

// runLock serializes everything that writes one agent run (chunk ingest, progress, finish,
// pause/stop, offline sweep) so concurrent writers never overwrite each other's run state.
// Lock order: runLock before c.mu, never the reverse.
func (c *Coordinator) runLock(runID string) *sync.Mutex {
	c.runLocksMu.Lock()
	defer c.runLocksMu.Unlock()
	l, ok := c.runLocks[runID]
	if !ok {
		l = &sync.Mutex{}
		c.runLocks[runID] = l
	}
	return l
}

func randomSecret(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hashEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// CreateEnrollToken creates a one-time token valid for ttl. The token is returned once; only
// its SHA-256 is stored.
func (c *Coordinator) CreateEnrollToken(ctx context.Context, name, site string, ttl time.Duration, createdBy string) (string, domain.AgentEnrollToken, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if ttl > 30*24*time.Hour {
		return "", domain.AgentEnrollToken{}, errors.New("token validity is limited to 30 days")
	}
	token := "aet_" + randomSecret(32)
	now := c.now()
	rec := domain.AgentEnrollToken{
		ID:        db.NewID(),
		Name:      strings.TrimSpace(name),
		Site:      strings.TrimSpace(site),
		TokenHash: hashSecret(token),
		Prefix:    token[:10],
		CreatedBy: createdBy,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLoadedLocked(ctx)
	c.pruneTokensLocked(now)
	c.tokens = append(c.tokens, rec)
	c.saveTokensLocked(ctx)
	return token, publicToken(rec), nil
}

// pruneTokensLocked drops tokens that expired or were used more than 7 days ago.
func (c *Coordinator) pruneTokensLocked(now time.Time) {
	kept := c.tokens[:0]
	for _, t := range c.tokens {
		if now.Sub(t.ExpiresAt) > 7*24*time.Hour {
			continue
		}
		if t.UsedAt != nil && now.Sub(*t.UsedAt) > 7*24*time.Hour {
			continue
		}
		kept = append(kept, t)
	}
	c.tokens = kept
}

func publicToken(t domain.AgentEnrollToken) domain.AgentEnrollToken {
	t.TokenHash = ""
	return t
}

// ListEnrollTokens returns enrollment tokens newest first, without their hashes.
func (c *Coordinator) ListEnrollTokens(ctx context.Context) []domain.AgentEnrollToken {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLoadedLocked(ctx)
	out := make([]domain.AgentEnrollToken, 0, len(c.tokens))
	for i := len(c.tokens) - 1; i >= 0; i-- {
		out = append(out, publicToken(c.tokens[i]))
	}
	return out
}

// RevokeEnrollToken deletes an enrollment token.
func (c *Coordinator) RevokeEnrollToken(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLoadedLocked(ctx)
	for i, t := range c.tokens {
		if t.ID == id {
			c.tokens = append(c.tokens[:i], c.tokens[i+1:]...)
			c.saveTokensLocked(ctx)
			return nil
		}
	}
	return db.ErrNotFound
}

// Enroll exchanges a one-time token for a new agent identity and its long-lived credential.
func (c *Coordinator) Enroll(ctx context.Context, req EnrollRequest, remoteIP string) (*EnrollResponse, error) {
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil, ErrTokenInvalid
	}
	h := hashSecret(token)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLoadedLocked(ctx)
	idx := -1
	for i := range c.tokens {
		if hashEqual(c.tokens[i].TokenHash, h) {
			idx = i
		}
	}
	if idx < 0 || c.tokens[idx].UsedAt != nil || !now.Before(c.tokens[idx].ExpiresAt) {
		return nil, ErrTokenInvalid
	}
	tok := &c.tokens[idx]
	secret := randomSecret(32)
	name := strings.TrimSpace(tok.Name)
	if name == "" {
		name = strings.TrimSpace(req.Name)
	}
	if name == "" {
		name = strings.TrimSpace(req.Capabilities.Hostname)
	}
	if name == "" {
		name = "agent"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	a := &domain.Agent{
		ID:             db.NewID(),
		Name:           name,
		Site:           tok.Site,
		Version:        clip(req.Version, 64),
		Status:         domain.AgentStatusOnline,
		RemoteIP:       remoteIP,
		Capabilities:   sanitizeCaps(req.Capabilities),
		EnrolledAt:     now,
		EnrolledBy:     tok.CreatedBy,
		CredentialHash: hashSecret(secret),
	}
	seen := now
	a.LastSeenAt = &seen
	tok.UsedAt = &seen
	tok.AgentID = a.ID
	c.agents[a.ID] = a
	c.saveTokensLocked(ctx)
	c.saveAgentsLocked(ctx)
	c.publish(domain.LiveEvent{Type: "agent.enrolled", Timestamp: now, Payload: map[string]any{"agent_id": a.ID, "name": a.Name, "site": a.Site}})
	return &EnrollResponse{
		AgentID:      a.ID,
		Name:         a.Name,
		Site:         a.Site,
		Credential:   CredentialPrefix + a.ID + "." + secret,
		HeartbeatSec: int(c.opts.HeartbeatInterval / time.Second),
	}, nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func sanitizeCaps(caps domain.AgentCapabilities) domain.AgentCapabilities {
	caps.NmapVersion = clip(caps.NmapVersion, 64)
	caps.OS = clip(caps.OS, 32)
	caps.Arch = clip(caps.Arch, 32)
	caps.Hostname = clip(caps.Hostname, 255)
	if len(caps.AllowCIDRs) > 256 {
		caps.AllowCIDRs = caps.AllowCIDRs[:256]
	}
	for i := range caps.AllowCIDRs {
		caps.AllowCIDRs[i] = clip(caps.AllowCIDRs[i], 64)
	}
	// Local subnets become one-click targets in the UI: keep only well-formed prefixes.
	subnets := make([]domain.LocalSubnet, 0, len(caps.LocalSubnets))
	for _, s := range caps.LocalSubnets {
		p, err := netip.ParsePrefix(strings.TrimSpace(s.CIDR))
		if err != nil || len(subnets) >= 64 {
			continue
		}
		s.CIDR = p.Masked().String()
		if a, err := netip.ParseAddr(strings.TrimSpace(s.Address)); err == nil && p.Contains(a) {
			s.Address = a.String()
		} else {
			s.Address = ""
		}
		s.Interface = clip(s.Interface, 32)
		subnets = append(subnets, s)
	}
	caps.LocalSubnets = subnets
	if len(subnets) == 0 {
		caps.LocalSubnets = nil
	}
	return caps
}

// Authenticate verifies an agent credential and records the contact (last seen, IP).
func (c *Coordinator) Authenticate(ctx context.Context, credential, remoteIP string) (*domain.Agent, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(credential), CredentialPrefix)
	if !ok {
		return nil, ErrUnauthorized
	}
	id, secret, ok := strings.Cut(rest, ".")
	if !ok || id == "" || secret == "" {
		return nil, ErrUnauthorized
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLoadedLocked(ctx)
	a, found := c.agents[id]
	if !found || !hashEqual(a.CredentialHash, hashSecret(secret)) {
		return nil, ErrUnauthorized
	}
	if a.Disabled {
		return nil, ErrAgentOff
	}
	now := c.now()
	wasOnline := c.statusLocked(a, now) == domain.AgentStatusOnline && a.Status == domain.AgentStatusOnline
	a.LastSeenAt = &now
	if remoteIP != "" {
		a.RemoteIP = remoteIP
	}
	if !wasOnline {
		a.Status = domain.AgentStatusOnline
		c.saveAgentsLocked(ctx)
		c.publish(domain.LiveEvent{Type: "agent.online", Timestamp: now, Payload: map[string]any{"agent_id": a.ID, "name": a.Name}})
	} else if now.Sub(c.persistedSeen[a.ID]) > 5*time.Minute {
		c.saveAgentsLocked(ctx)
	}
	cp := *a
	return &cp, nil
}

func (c *Coordinator) statusLocked(a *domain.Agent, now time.Time) string {
	if a.Disabled {
		return domain.AgentStatusDisabled
	}
	seen := c.bootAt
	if a.LastSeenAt != nil && a.LastSeenAt.After(seen) {
		seen = *a.LastSeenAt
	}
	if now.Sub(seen) > c.opts.OfflineAfter {
		return domain.AgentStatusOffline
	}
	if a.LastSeenAt == nil {
		return domain.AgentStatusOffline
	}
	return domain.AgentStatusOnline
}

func publicAgent(a domain.Agent) domain.Agent {
	a.CredentialHash = ""
	return a
}

// ListAgents returns all agents with their live status (credential hashes stripped).
func (c *Coordinator) ListAgents(ctx context.Context) []domain.Agent {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLoadedLocked(ctx)
	now := c.now()
	out := make([]domain.Agent, 0, len(c.agents))
	for _, a := range c.agents {
		cp := publicAgent(*a)
		cp.Status = c.statusLocked(a, now)
		cp.CurrentRunID = ""
		for _, j := range c.jobs {
			if j.AgentID == a.ID && !j.Done && j.Instance != "" {
				cp.CurrentRunID = j.RunID
			}
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnrolledAt.Before(out[j].EnrolledAt) })
	return out
}

// GetAgent returns one agent (credential hash stripped).
func (c *Coordinator) GetAgent(ctx context.Context, id string) (*domain.Agent, error) {
	for _, a := range c.ListAgents(ctx) {
		if a.ID == id {
			return &a, nil
		}
	}
	return nil, db.ErrNotFound
}

// UpdateAgent changes the operator-managed fields.
func (c *Coordinator) UpdateAgent(ctx context.Context, id string, name, site *string, disabled *bool) (*domain.Agent, error) {
	c.mu.Lock()
	c.ensureLoadedLocked(ctx)
	a, ok := c.agents[id]
	if !ok {
		c.mu.Unlock()
		return nil, db.ErrNotFound
	}
	if name != nil && strings.TrimSpace(*name) != "" {
		a.Name = clip(*name, 80)
	}
	if site != nil {
		a.Site = clip(*site, 80)
	}
	if disabled != nil {
		a.Disabled = *disabled
	}
	c.saveAgentsLocked(ctx)
	c.mu.Unlock()
	if disabled != nil && *disabled {
		c.wakeAgent(id)
	}
	return c.GetAgent(ctx, id)
}

// DeleteAgent removes an agent; its credential stops working immediately and its active runs
// are stopped with a note.
func (c *Coordinator) DeleteAgent(ctx context.Context, id string) error {
	c.mu.Lock()
	c.ensureLoadedLocked(ctx)
	a, ok := c.agents[id]
	if !ok {
		c.mu.Unlock()
		return db.ErrNotFound
	}
	name := a.Name
	delete(c.agents, id)
	c.saveAgentsLocked(ctx)
	var runIDs []string
	for _, j := range c.jobs {
		if j.AgentID == id && !j.Done {
			runIDs = append(runIDs, j.RunID)
		}
	}
	c.mu.Unlock()
	for _, rid := range runIDs {
		c.finalizeRun(ctx, rid, domain.ScanStatusStopped, fmt.Sprintf("Agent %q was deleted - scan stopped.", name))
	}
	return nil
}

// finalizeRun puts an agent run into a terminal state with a note and closes its job.
func (c *Coordinator) finalizeRun(ctx context.Context, runID, status, note string) {
	l := c.runLock(runID)
	l.Lock()
	defer l.Unlock()
	if run, err := c.store.GetScanRun(ctx, runID); err == nil && isActive(run.Status) {
		now := c.now()
		run.Status = status
		run.FinishedAt = &now
		run.Notes = appendNote(run.Notes, note)
		run.RawNmapXML = ""
		_ = c.store.UpdateScanRun(ctx, run)
	}
	c.mu.Lock()
	if j, ok := c.jobs[runID]; ok {
		j.Done = true
		j.Control = ControlStop
		j.UpdatedAt = c.now()
	}
	c.saveJobsLocked(ctx)
	c.mu.Unlock()
}

func appendNote(notes, note string) string {
	return strings.TrimSpace(strings.TrimSpace(notes) + "\n" + note)
}

func isActive(status string) bool {
	switch status {
	case domain.ScanStatusQueued, domain.ScanStatusCalibrating, domain.ScanStatusRunning,
		domain.ScanStatusPausedWindow, domain.ScanStatusPausedUser:
		return true
	}
	return false
}

// AgentExists reports whether id names an enrolled agent (profile validation).
func (c *Coordinator) AgentExists(ctx context.Context, id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLoadedLocked(ctx)
	_, ok := c.agents[id]
	return ok
}

func (c *Coordinator) wakeAgent(agentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.wake[agentID]; ok {
		close(ch)
		delete(c.wake, agentID)
	}
}

func (c *Coordinator) wakeChanLocked(agentID string) chan struct{} {
	ch, ok := c.wake[agentID]
	if !ok {
		ch = make(chan struct{})
		c.wake[agentID] = ch
	}
	return ch
}
