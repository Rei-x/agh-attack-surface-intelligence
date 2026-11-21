// Package agent is the remote scanning agent (`dzieciol agent`): a lightweight daemon placed
// inside a network segment that connects OUT to the central Dzięcioł server over HTTPS,
// pulls scan jobs, runs the regular scanner engine locally and uploads the results. It
// never listens on a port. See internal/agenthub for the server side and the protocol.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/localdata"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// ErrCredentialRejected means the server no longer accepts this agent (deleted on the
// server or credential replaced): re-enrollment with a new token is needed.
var ErrCredentialRejected = errors.New("the server rejected this agent's credential (agent deleted on the server?) - remove agent.json from the data directory and enroll again with a new token")

// Config configures one agent process.
type Config struct {
	ServerURL  string
	Token      string // one-time enrollment token (first run only)
	Name       string
	DataDir    string
	CAFile     string
	Insecure   bool
	AllowCIDRs []string // local safety allowlist; empty = no restriction
	Version    string

	// Tuning / test seams.
	PollWait      time.Duration // long-poll wait for jobs (default 25s)
	ProgressEvery time.Duration // progress/event upload interval (default 2s)
	EngineConfig  func(scanner.EngineConfig) scanner.EngineConfig
	Logf          func(format string, args ...any)
}

// Agent is a running agent process.
type Agent struct {
	cfg    Config
	st     *state
	c      *client
	box    *outbox
	allow  []netip.Prefix
	caps   domain.AgentCapabilities
	logf   func(string, ...any)
	hbSec  int
	lock   *localdata.Lock
	events *eventBuf

	mu  sync.Mutex
	cur *jobCtl
}

type jobCtl struct {
	runID  string
	cancel context.CancelFunc
	mu     sync.Mutex
	reason string // pause | stop | lost
}

func (j *jobCtl) signal(reason string) {
	j.mu.Lock()
	if j.reason == "" {
		j.reason = reason
	}
	j.mu.Unlock()
	j.cancel()
}

func (j *jobCtl) why() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.reason
}

// ParseAllowCIDRs parses --allow-cidr values (CIDRs or single IPs, comma separated).
func ParseAllowCIDRs(values []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if p, err := netip.ParsePrefix(part); err == nil {
				out = append(out, p.Masked())
				continue
			}
			a, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("invalid --allow-cidr %q", part)
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	return out, nil
}

// New validates the configuration and opens (locks) the data directory.
func New(cfg Config) (*Agent, error) {
	if cfg.PollWait <= 0 {
		cfg.PollWait = 25 * time.Second
	}
	if cfg.ProgressEvery <= 0 {
		cfg.ProgressEvery = 2 * time.Second
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	allow, err := ParseAllowCIDRs(cfg.AllowCIDRs)
	if err != nil {
		return nil, err
	}
	if cfg.DataDir == "" {
		return nil, errors.New("data directory is required")
	}
	dir, err := localdata.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	lock, err := dir.Acquire(localdata.LockInfo{Command: "agent"})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Agent, error) {
		lock.Release()
		return nil, err
	}
	st, err := loadState(cfg.DataDir)
	if err != nil {
		return fail(err)
	}
	server := cfg.ServerURL
	if server == "" {
		server = st.ServerURL
	}
	if server == "" {
		return fail(errors.New("--server is required on the first run"))
	}
	base, err := checkServerURL(server, cfg.Insecure)
	if err != nil {
		return fail(err)
	}
	hc, err := newHTTPClient(cfg.CAFile, cfg.Insecure)
	if err != nil {
		return fail(err)
	}
	box, err := openOutbox(cfg.DataDir)
	if err != nil {
		return fail(err)
	}
	if st.InstanceID == "" {
		st.InstanceID = randomID()
	}
	a := &Agent{
		cfg:    cfg,
		st:     st,
		box:    box,
		allow:  allow,
		logf:   logf,
		hbSec:  15,
		lock:   lock,
		events: &eventBuf{max: 2000},
		c: &client{
			base:       base,
			http:       hc,
			credential: st.Credential,
			instance:   st.InstanceID,
			userAgent:  "dzieciol-agent/" + cfg.Version,
		},
	}
	a.st.ServerURL = base.String()
	a.caps = a.detectCapabilities()
	return a, nil
}

// Close releases the data directory lock.
func (a *Agent) Close() { a.lock.Release() }

// AgentID returns the enrolled agent id ("" before enrollment).
func (a *Agent) AgentID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.st.AgentID
}

func (a *Agent) detectCapabilities() domain.AgentCapabilities {
	host, _ := os.Hostname()
	caps := domain.AgentCapabilities{
		Nmap:       scanner.NmapAvailable(),
		Privileged: os.Geteuid() == 0,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Hostname:   host,
	}
	for _, p := range a.allow {
		caps.AllowCIDRs = append(caps.AllowCIDRs, p.String())
	}
	return caps
}

func backoff(ctx context.Context, attempt int) {
	d := time.Second << min(attempt, 6) // 1s .. 64s
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	d += time.Duration(rand.Int64N(int64(d / 4)))
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Enroll exchanges the one-time token for a credential (no-op when already enrolled).
func (a *Agent) Enroll(ctx context.Context) error {
	if a.st.Credential != "" {
		if a.cfg.Token != "" {
			a.logf("[INFO] already enrolled as %q (%s); ignoring --token", a.st.Name, a.st.AgentID)
		}
		return saveState(a.cfg.DataDir, a.st) // persists server URL / instance id changes
	}
	if strings.TrimSpace(a.cfg.Token) == "" {
		return errors.New("not enrolled yet: pass --token <one-time enrollment token> from Admin > Agents")
	}
	req := agenthub.EnrollRequest{
		Token: a.cfg.Token, Name: a.cfg.Name, Version: a.cfg.Version,
		InstanceID: a.st.InstanceID, Capabilities: a.caps,
	}
	for attempt := 0; ; attempt++ {
		var resp agenthub.EnrollResponse
		_, err := a.c.do(ctx, 30*time.Second, http.MethodPost, "/api/v1/agent/enroll", req, &resp)
		if err == nil {
			a.mu.Lock()
			a.st.AgentID, a.st.Name, a.st.Site = resp.AgentID, resp.Name, resp.Site
			a.st.Credential = resp.Credential
			a.st.EnrolledAt = time.Now().UTC()
			a.mu.Unlock()
			a.c.credential = resp.Credential
			if resp.HeartbeatSec > 0 {
				a.hbSec = resp.HeartbeatSec
			}
			if err := saveState(a.cfg.DataDir, a.st); err != nil {
				return fmt.Errorf("enrolled as %s but could not save the credential: %w", resp.AgentID, err)
			}
			a.logf("[INFO] enrolled as agent %q (%s); credential stored in %s (0600)", resp.Name, resp.AgentID, a.cfg.DataDir)
			return nil
		}
		if !retryable(err) {
			return fmt.Errorf("enrollment failed: %w", err)
		}
		a.logf("[WARN] enrollment: server unreachable (%v), retrying", err)
		backoff(ctx, attempt)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// Run enrolls if needed and serves jobs until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.Enroll(ctx); err != nil {
		return err
	}
	a.logf("[INFO] agent %q connected to %s (instance %s, nmap=%v, allowlist=%v)",
		a.st.Name, a.st.ServerURL, a.st.InstanceID[:8], a.caps.Nmap, a.caps.AllowCIDRs)
	if len(a.allow) == 0 {
		a.logf("[WARN] no --allow-cidr set: the agent will scan whatever targets the server sends")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var fatalMu sync.Mutex
	var fatal error
	go func() {
		if err := a.heartbeatLoop(runCtx); err != nil {
			fatalMu.Lock()
			fatal = err
			fatalMu.Unlock()
			cancel()
		}
	}()

	for attempt := 0; runCtx.Err() == nil; {
		// Results of an earlier run (or of a previous process) go first, so the server's
		// ledger is complete before it hands out the next job.
		if err := a.drainOutbox(runCtx, true); err != nil {
			if errors.Is(err, ErrCredentialRejected) {
				return err
			}
			continue
		}
		var spec agenthub.JobSpec
		code, err := a.c.do(runCtx, a.cfg.PollWait+20*time.Second, http.MethodPost,
			fmt.Sprintf("/api/v1/agent/jobs/next?wait=%d", int(a.cfg.PollWait/time.Second)), map[string]any{}, &spec)
		if err != nil {
			if runCtx.Err() != nil {
				break
			}
			if statusOf(err) == http.StatusUnauthorized {
				return ErrCredentialRejected
			}
			if attempt%5 == 0 {
				a.logf("[WARN] job poll failed: %v", err)
			}
			backoff(runCtx, attempt)
			attempt++
			continue
		}
		attempt = 0
		if code == http.StatusNoContent || spec.RunID == "" {
			continue
		}
		a.runJob(runCtx, &spec)
	}
	fatalMu.Lock()
	defer fatalMu.Unlock()
	return fatal
}

func (a *Agent) current() *jobCtl {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cur
}

func (a *Agent) applyControl(runID, action string) {
	if action == "" {
		return
	}
	if j := a.current(); j != nil && j.runID == runID {
		if j.why() == "" {
			a.logf("[INFO] server requested %s of run %s", action, runID)
		}
		j.signal(action)
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) error {
	fails := 0
	for {
		req := agenthub.HeartbeatRequest{Version: a.cfg.Version, Capabilities: a.caps}
		if j := a.current(); j != nil {
			req.CurrentRunID = j.runID
		}
		var resp agenthub.HeartbeatResponse
		_, err := a.c.do(ctx, 20*time.Second, http.MethodPost, "/api/v1/agent/heartbeat", req, &resp)
		switch {
		case err == nil:
			if fails > 0 {
				a.logf("[INFO] server reachable again")
			}
			fails = 0
			if resp.HeartbeatSec > 0 {
				a.hbSec = resp.HeartbeatSec
			}
			for runID, action := range resp.Control {
				a.applyControl(runID, action)
			}
		case ctx.Err() != nil:
			return nil
		case statusOf(err) == http.StatusUnauthorized:
			return ErrCredentialRejected
		default:
			if fails == 0 {
				a.logf("[WARN] heartbeat failed: %v (scanning continues, results are buffered on disk)", err)
			}
			fails++
		}
		t := time.NewTimer(time.Duration(a.hbSec) * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// drainOutbox uploads buffered results in order. With untilEmpty it retries (with backoff)
// until the queue is empty or ctx ends; otherwise it makes one pass and stops at the first
// retryable failure.
func (a *Agent) drainOutbox(ctx context.Context, untilEmpty bool) error {
	attempt := 0
	for ctx.Err() == nil {
		names := a.box.list()
		if len(names) == 0 {
			return nil
		}
		progressed := false
		var lastErr error
		for _, name := range names {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err := a.uploadRecord(ctx, name)
			if err == nil {
				progressed = true
				continue
			}
			if errors.Is(err, ErrCredentialRejected) {
				return err
			}
			lastErr = err
			break
		}
		if lastErr == nil {
			continue
		}
		if !untilEmpty {
			return lastErr
		}
		if progressed {
			attempt = 0
		}
		if attempt%5 == 0 {
			a.logf("[WARN] %d buffered result(s) waiting for the server: %v", a.box.pending(), lastErr)
		}
		backoff(ctx, attempt)
		attempt++
	}
	return ctx.Err()
}

// uploadRecord sends one buffered record. nil means the record is settled (accepted,
// duplicate, or permanently unacceptable) and was removed from the queue.
func (a *Agent) uploadRecord(ctx context.Context, name string) error {
	rec, err := a.box.read(name)
	if err != nil {
		a.logf("[WARN] unreadable outbox record %s: %v", name, err)
		a.box.quarantine(name)
		return nil
	}
	var path string
	timeout := 2 * time.Minute
	switch rec.Kind {
	case "chunk":
		path = "/api/v1/agent/jobs/" + rec.RunID + "/chunks"
	case "finish":
		path = "/api/v1/agent/jobs/" + rec.RunID + "/finish"
		timeout = 10 * time.Minute
	default:
		a.box.quarantine(name)
		return nil
	}
	var resp agenthub.ControlResponse
	_, err = a.c.do(ctx, timeout, http.MethodPost, path, rec.Body, &resp)
	if err != nil {
		switch statusOf(err) {
		case 0, http.StatusTooManyRequests, http.StatusRequestTimeout:
			return err
		case http.StatusUnauthorized:
			return ErrCredentialRejected
		case http.StatusNotFound, http.StatusForbidden:
			a.logf("[WARN] dropping %s result for run %s: %v", rec.Kind, rec.RunID, err)
			a.box.remove(name)
			return nil
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
			a.logf("[ERROR] server rejected %s result for run %s (%v); moved to outbox/rejected", rec.Kind, rec.RunID, err)
			a.box.quarantine(name)
			return nil
		}
		if retryable(err) {
			return err
		}
		a.box.quarantine(name)
		return nil
	}
	a.box.remove(name)
	if resp.Control != "" {
		a.applyControl(rec.RunID, resp.Control)
	}
	if resp.Error != "" {
		a.logf("[ERROR] server could not store results of run %s: %s", rec.RunID, resp.Error)
	}
	return nil
}
