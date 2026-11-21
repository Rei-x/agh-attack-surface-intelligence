package agenthub

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Add(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

type fixture struct {
	t     *testing.T
	ctx   context.Context
	store *db.MemoryStore
	c     *Coordinator
	clock *fakeClock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewMemoryStore(vault)
	clock := &fakeClock{t: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
	pipeline := ingest.NewPipeline(store, ingest.NewDefaultAnalyzer(), nil)
	c := New(store, pipeline, nil, Options{Now: clock.Now, OfflineAfter: 90 * time.Second, LeaseTTL: 60 * time.Second})
	return &fixture{t: t, ctx: context.Background(), store: store, c: c, clock: clock}
}

// enroll creates a token and enrolls an agent, returning its id and credential.
func (f *fixture) enroll(name string) (string, string) {
	f.t.Helper()
	tok, _, err := f.c.CreateEnrollToken(f.ctx, name, "lab", time.Hour, "admin")
	if err != nil {
		f.t.Fatal(err)
	}
	resp, err := f.c.Enroll(f.ctx, EnrollRequest{Token: tok, Version: "test"}, "192.0.2.10")
	if err != nil {
		f.t.Fatal(err)
	}
	return resp.AgentID, resp.Credential
}

// queue creates a saved agent-bound profile and a queued run for it.
func (f *fixture) queue(agentID string, targets ...string) *domain.ScanRun {
	f.t.Helper()
	p := &domain.ScanProfile{Name: "p-" + targets[0], Targets: targets, AllowedPorts: "80", AgentID: agentID, MissingThreshold: 1, GracePeriodHours: 1}
	if err := f.store.CreateProfile(f.ctx, p); err != nil {
		f.t.Fatal(err)
	}
	run := &domain.ScanRun{ID: db.NewID(), ProfileID: p.ID, Name: p.Name, RunType: domain.ScanTypeActive, Status: domain.ScanStatusQueued, StartedAt: f.clock.Now()}
	if err := f.store.CreateScanRun(f.ctx, run); err != nil {
		f.t.Fatal(err)
	}
	if err := f.c.Enqueue(f.ctx, run, p); err != nil {
		f.t.Fatal(err)
	}
	return run
}

func chunk(runID string, idx int, ips ...string) domain.ScanChunk {
	return domain.ScanChunk{ID: runID + "-c" + string(rune('0'+idx)), ScanRunID: runID, ChunkIndex: idx, Targets: ips, IPCount: len(ips), Status: domain.ChunkStatusPending}
}

func (f *fixture) run(id string) *domain.ScanRun {
	f.t.Helper()
	r, err := f.store.GetScanRun(f.ctx, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func TestEnrollTokenSingleUseExpiryAndHashedStorage(t *testing.T) {
	f := newFixture(t)
	tok, rec, err := f.c.CreateEnrollToken(f.ctx, "wydzial-eaiib", "EAIiIB", time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rec.TokenHash != "" {
		t.Fatal("API view of the token must not carry its hash")
	}
	// Stored form: only the SHA-256, never the token itself.
	var stored []domain.AgentEnrollToken
	if _, err := f.store.GetSetting(f.ctx, settingTokens, &stored); err != nil || len(stored) != 1 {
		t.Fatalf("stored tokens: %v %v", stored, err)
	}
	raw, _ := json.Marshal(stored)
	if strings.Contains(string(raw), tok) || stored[0].TokenHash != hashSecret(tok) {
		t.Fatalf("token must be stored hashed only: %s", raw)
	}

	resp, err := f.c.Enroll(f.ctx, EnrollRequest{Token: tok, Name: "ignored", Version: "1.2"}, "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Name != "wydzial-eaiib" || !strings.HasPrefix(resp.Credential, CredentialPrefix+resp.AgentID+".") {
		t.Fatalf("enroll response: %+v", resp)
	}
	// Single use.
	if _, err := f.c.Enroll(f.ctx, EnrollRequest{Token: tok}, "198.51.100.7"); err != ErrTokenInvalid {
		t.Fatalf("second enrollment with the same token: %v", err)
	}
	// Credential stored hashed, works, and a wrong secret does not.
	var agents []domain.Agent
	_, _ = f.store.GetSetting(f.ctx, settingAgents, &agents)
	raw, _ = json.Marshal(agents)
	secret := resp.Credential[strings.LastIndex(resp.Credential, ".")+1:]
	if len(agents) != 1 || strings.Contains(string(raw), secret) || agents[0].CredentialHash != hashSecret(secret) {
		t.Fatalf("credential must be stored hashed only: %s", raw)
	}
	if a, err := f.c.Authenticate(f.ctx, resp.Credential, "198.51.100.7"); err != nil || a.ID != resp.AgentID || a.RemoteIP != "198.51.100.7" {
		t.Fatalf("authenticate: %v %v", a, err)
	}
	if _, err := f.c.Authenticate(f.ctx, resp.Credential+"x", ""); err != ErrUnauthorized {
		t.Fatalf("tampered credential: %v", err)
	}
	for _, a := range f.c.ListAgents(f.ctx) {
		if a.CredentialHash != "" {
			t.Fatal("ListAgents leaks the credential hash")
		}
	}

	// Expiry.
	tok2, _, _ := f.c.CreateEnrollToken(f.ctx, "late", "", time.Hour, "admin")
	f.clock.Add(61 * time.Minute)
	if _, err := f.c.Enroll(f.ctx, EnrollRequest{Token: tok2}, ""); err != ErrTokenInvalid {
		t.Fatalf("expired token: %v", err)
	}
	// Revoked.
	tok3, rec3, _ := f.c.CreateEnrollToken(f.ctx, "revoked", "", time.Hour, "admin")
	if err := f.c.RevokeEnrollToken(f.ctx, rec3.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Enroll(f.ctx, EnrollRequest{Token: tok3}, ""); err != ErrTokenInvalid {
		t.Fatalf("revoked token: %v", err)
	}
	// Disabled agent is locked out; deleted agent too.
	off := true
	if _, err := f.c.UpdateAgent(f.ctx, resp.AgentID, nil, nil, &off); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Authenticate(f.ctx, resp.Credential, ""); err != ErrAgentOff {
		t.Fatalf("disabled agent: %v", err)
	}
	if err := f.c.DeleteAgent(f.ctx, resp.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Authenticate(f.ctx, resp.Credential, ""); err != ErrUnauthorized {
		t.Fatalf("deleted agent: %v", err)
	}
}

func TestEnrollmentStatePersistsAcrossRestart(t *testing.T) {
	f := newFixture(t)
	id, cred := f.enroll("persist")
	run := f.queue(id, "10.0.0.1")
	// A fresh coordinator on the same store (server restart) knows the agent and the job.
	c2 := New(f.store, nil, nil, Options{Now: f.clock.Now})
	if _, err := c2.Authenticate(f.ctx, cred, ""); err != nil {
		t.Fatalf("credential after restart: %v", err)
	}
	if !c2.IsAgentRun(run.ID) {
		t.Fatal("job lost across restart")
	}
}

func TestJobQueueNoDoubleAssignment(t *testing.T) {
	f := newFixture(t)
	a1, _ := f.enroll("a1")
	a2, _ := f.enroll("a2")
	r1 := f.queue(a1, "10.0.0.1")
	r2 := f.queue(a1, "10.0.0.2")

	// Another agent never sees a1's jobs.
	if spec, err := f.c.NextJob(f.ctx, a2, "i-a2", 0); err != nil || spec != nil {
		t.Fatalf("foreign agent got a job: %+v %v", spec, err)
	}
	// Concurrent claims by two instances of a1: exactly one gets the oldest run.
	var wg sync.WaitGroup
	got := make([]*JobSpec, 2)
	for i, inst := range []string{"i-A", "i-B"} {
		wg.Add(1)
		go func(i int, inst string) {
			defer wg.Done()
			got[i], _ = f.c.NextJob(f.ctx, a1, inst, 0)
		}(i, inst)
	}
	wg.Wait()
	winner := "i-A"
	if got[0] == nil {
		winner = "i-B"
	}
	if (got[0] == nil) == (got[1] == nil) {
		t.Fatalf("want exactly one claim, got %+v / %+v", got[0], got[1])
	}
	spec := got[0]
	if spec == nil {
		spec = got[1]
	}
	if spec.RunID != r1.ID {
		t.Fatalf("claimed %s, want oldest %s", spec.RunID, r1.ID)
	}
	loser := "i-A"
	if winner == "i-A" {
		loser = "i-B"
	}
	// While the lease is live, the other instance gets nothing (one run per agent).
	if s, _ := f.c.NextJob(f.ctx, a1, loser, 0); s != nil {
		t.Fatalf("second instance got %s while the lease is held", s.RunID)
	}
	if _, err := f.c.Start(f.ctx, a1, winner, r1.ID, StartRequest{TotalIPs: 1, Chunks: []domain.ScanChunk{chunk(r1.ID, 0, "10.0.0.1")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Progress(f.ctx, a1, loser, r1.ID, ProgressRequest{}); err != ErrLeased {
		t.Fatalf("progress from a non-holder: %v", err)
	}
	// The holder asking again (restart) resumes the same run, not the next one.
	if s, _ := f.c.NextJob(f.ctx, a1, winner, 0); s == nil || s.RunID != r1.ID || len(s.Chunks) != 1 {
		t.Fatalf("resume: %+v", s)
	}
	// Finish r1 -> the next claim hands out r2.
	ch := chunk(r1.ID, 0, "10.0.0.1")
	ch.Status = domain.ChunkStatusDone
	if _, err := f.c.UploadChunk(f.ctx, a1, winner, r1.ID, ChunkUpload{Chunk: ch}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Finish(f.ctx, a1, winner, r1.ID, FinishRequest{SegmentID: "s1", Outcome: OutcomeCompleted}); err != nil {
		t.Fatal(err)
	}
	if st := f.run(r1.ID).Status; st != domain.ScanStatusCompleted {
		t.Fatalf("r1 status %s", st)
	}
	if s, _ := f.c.NextJob(f.ctx, a1, loser, 0); s == nil || s.RunID != r2.ID {
		t.Fatalf("next job after finish: %+v", s)
	}
}

func TestChunkUploadIdempotent(t *testing.T) {
	f := newFixture(t)
	a, _ := f.enroll("idem")
	r := f.queue(a, "10.0.0.1", "10.0.0.2")
	if s, _ := f.c.NextJob(f.ctx, a, "i", 0); s == nil {
		t.Fatal("no job")
	}
	c0 := chunk(r.ID, 0, "10.0.0.1", "10.0.0.2")
	if _, err := f.c.Start(f.ctx, a, "i", r.ID, StartRequest{TotalIPs: 2, Chunks: []domain.ScanChunk{c0}}); err != nil {
		t.Fatal(err)
	}
	done := c0
	done.Status, done.ActiveHosts, done.Services = domain.ChunkStatusDone, 1, 1
	up := ChunkUpload{Chunk: done, Observations: []domain.ObservedHost{
		{IP: "10.0.0.1", IsAlive: true, ObservedAt: f.clock.Now(), Services: []domain.ObservedService{{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http"}}},
		{IP: "10.0.0.2", IsAlive: false, ObservedAt: f.clock.Now()},
		{IP: "203.0.113.9", IsAlive: true, ObservedAt: f.clock.Now()}, // not in the chunk: dropped
	}}
	resp, err := f.c.UploadChunk(f.ctx, a, "i", r.ID, up)
	if err != nil || resp.Duplicate || resp.Dropped != 1 {
		t.Fatalf("first upload: %+v %v", resp, err)
	}
	// Retry after a lost response (network): acknowledged, not ingested again.
	resp, err = f.c.UploadChunk(f.ctx, a, "i", r.ID, up)
	if err != nil || !resp.Duplicate {
		t.Fatalf("retried upload: %+v %v", resp, err)
	}
	hosts, _, _ := f.store.ListHosts(f.ctx, db.HostFilter{})
	if len(hosts) != 1 || hosts[0].IP != "10.0.0.1" || hosts[0].TotalScansSeen != 1 {
		t.Fatalf("hosts after duplicate upload: %+v", hosts)
	}
	run := f.run(r.ID)
	if run.CompletedChunks != 1 || run.ScannedIPs != 2 || run.ActiveHosts != 1 || run.ServicesFound != 1 {
		t.Fatalf("counters: %+v", run)
	}
	// Finish is idempotent too.
	for i := 0; i < 2; i++ {
		resp, err := f.c.Finish(f.ctx, a, "i", r.ID, FinishRequest{SegmentID: "seg-1", Outcome: OutcomeCompleted,
			RawNmapXML: `<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>`})
		if err != nil || resp.Duplicate != (i == 1) {
			t.Fatalf("finish #%d: %+v %v", i, resp, err)
		}
	}
	run = f.run(r.ID)
	if run.Status != domain.ScanStatusCompleted || !strings.Contains(run.RawNmapXML, "10.0.0.1") {
		t.Fatalf("run after finish: %s xml=%q", run.Status, run.RawNmapXML)
	}
}

func TestOfflineAgentPausesRunAndResumesFromCheckpoint(t *testing.T) {
	f := newFixture(t)
	a, cred := f.enroll("flaky")
	r := f.queue(a, "10.0.0.1", "10.0.0.2")
	if s, _ := f.c.NextJob(f.ctx, a, "i", 0); s == nil {
		t.Fatal("no job")
	}
	c0, c1 := chunk(r.ID, 0, "10.0.0.1"), chunk(r.ID, 1, "10.0.0.2")
	if _, err := f.c.Start(f.ctx, a, "i", r.ID, StartRequest{TotalIPs: 2, Chunks: []domain.ScanChunk{c0, c1}}); err != nil {
		t.Fatal(err)
	}
	c0.Status = domain.ChunkStatusDone
	if _, err := f.c.UploadChunk(f.ctx, a, "i", r.ID, ChunkUpload{Chunk: c0}); err != nil {
		t.Fatal(err)
	}
	c1r := c1
	c1r.Status = domain.ChunkStatusRunning
	if _, err := f.c.Progress(f.ctx, a, "i", r.ID, ProgressRequest{Chunks: []domain.ScanChunk{c0, c1r}}); err != nil {
		t.Fatal(err)
	}

	// Silent for less than OfflineAfter: nothing happens.
	f.clock.Add(60 * time.Second)
	f.c.Sweep(f.ctx)
	if st := f.run(r.ID).Status; st != domain.ScanStatusRunning {
		t.Fatalf("paused too early: %s", st)
	}
	// Silent past OfflineAfter and the lease: agent offline, run parked with a note.
	f.clock.Add(61 * time.Second)
	f.c.Sweep(f.ctx)
	run := f.run(r.ID)
	if run.Status != domain.ScanStatusPausedWindow || !strings.Contains(run.Notes, "offline") {
		t.Fatalf("after offline: status=%s notes=%q", run.Status, run.Notes)
	}
	if ag, _ := f.c.GetAgent(f.ctx, a); ag.Status != domain.AgentStatusOffline {
		t.Fatalf("agent status %s", ag.Status)
	}
	for _, ch := range run.Chunks {
		if ch.ID == c1.ID && ch.Status != domain.ChunkStatusPending {
			t.Fatalf("interrupted chunk should be PENDING, got %s", ch.Status)
		}
	}

	// Agent comes back: it gets the same run with the checkpoint (chunk 0 done).
	if _, err := f.c.Authenticate(f.ctx, cred, ""); err != nil {
		t.Fatal(err)
	}
	spec, err := f.c.NextJob(f.ctx, a, "i", 0)
	if err != nil || spec == nil || spec.RunID != r.ID {
		t.Fatalf("resume after offline: %+v %v", spec, err)
	}
	if spec.Run.CompletedChunks != 1 || spec.Chunks[0].Status != domain.ChunkStatusDone || spec.Chunks[1].Status != domain.ChunkStatusPending {
		t.Fatalf("checkpoint not preserved: %+v", spec)
	}
	run = f.run(r.ID)
	if run.Status != domain.ScanStatusRunning || !strings.Contains(run.Notes, "resumed") {
		t.Fatalf("after resume: %s %q", run.Status, run.Notes)
	}
	c1.Status = domain.ChunkStatusDone
	if _, err := f.c.UploadChunk(f.ctx, a, "i", r.ID, ChunkUpload{Chunk: c1}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Finish(f.ctx, a, "i", r.ID, FinishRequest{SegmentID: "s2", Outcome: OutcomeCompleted}); err != nil {
		t.Fatal(err)
	}
	if run = f.run(r.ID); run.Status != domain.ScanStatusCompleted || run.CompletedChunks != 2 {
		t.Fatalf("final: %s %d", run.Status, run.CompletedChunks)
	}
}

func TestUserPauseStopReachAgent(t *testing.T) {
	f := newFixture(t)
	a, _ := f.enroll("ctl")
	r := f.queue(a, "10.0.0.1")
	_, _ = f.c.NextJob(f.ctx, a, "i", 0)
	_, _ = f.c.Start(f.ctx, a, "i", r.ID, StartRequest{TotalIPs: 1, Chunks: []domain.ScanChunk{chunk(r.ID, 0, "10.0.0.1")}})
	if err := f.c.Pause(f.ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	hb, _ := f.c.Heartbeat(f.ctx, a, "i", HeartbeatRequest{CurrentRunID: r.ID})
	if hb.Control[r.ID] != ControlPause {
		t.Fatalf("heartbeat control: %+v", hb.Control)
	}
	if _, err := f.c.Finish(f.ctx, a, "i", r.ID, FinishRequest{SegmentID: "p", Outcome: OutcomePausedUser}); err != nil {
		t.Fatal(err)
	}
	if st := f.run(r.ID).Status; st != domain.ScanStatusPausedUser {
		t.Fatalf("status %s", st)
	}
	// A user-paused run is not handed out until resumed.
	if s, _ := f.c.NextJob(f.ctx, a, "i", 0); s != nil {
		t.Fatal("paused run handed out")
	}
	if err := f.c.Resume(f.ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.c.NextJob(f.ctx, a, "i", 0); s == nil || s.RunID != r.ID {
		t.Fatal("resumed run not handed out")
	}
	if err := f.c.Stop(f.ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	resp, _ := f.c.Progress(f.ctx, a, "i", r.ID, ProgressRequest{})
	if resp.Control != ControlStop {
		t.Fatalf("progress control after stop: %+v", resp)
	}
}

// Agent registry, tokens and jobs survive a restart of the single-binary encrypted file store.
func TestAgentStateInEncryptedFileSnapshot(t *testing.T) {
	ctx := context.Background()
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dzieciol-store.enc")
	fs1, err := db.OpenFileStore(path, vault, db.FileStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c1 := New(fs1, nil, nil, Options{})
	tok, _, _ := c1.CreateEnrollToken(ctx, "snapshot-agent", "", time.Hour, "admin")
	enr, err := c1.Enroll(ctx, EnrollRequest{Token: tok}, "")
	if err != nil {
		t.Fatal(err)
	}
	fs1.Close()
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "snapshot-agent") || strings.Contains(string(raw), enr.AgentID) {
		t.Fatal("agent state stored in clear text")
	}
	fs2, err := db.OpenFileStore(path, vault, db.FileStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer fs2.Close()
	c2 := New(fs2, nil, nil, Options{})
	if _, err := c2.Authenticate(ctx, enr.Credential, ""); err != nil {
		t.Fatalf("credential after reopening the file store: %v", err)
	}
	if _, err := c2.Enroll(ctx, EnrollRequest{Token: tok}, ""); err != ErrTokenInvalid {
		t.Fatalf("used token after reopen: %v", err)
	}
}

func TestRelayFiltersEvents(t *testing.T) {
	f := newFixture(t)
	var got []domain.LiveEvent
	f.c.emit = func(ev domain.LiveEvent) { got = append(got, ev) }
	f.c.relay("run-1", []domain.LiveEvent{
		{Type: "scan.progress", ScanRunID: "other"},
		{Type: "change.detected"}, // only the server's pipeline emits these
		{Type: "agent.enrolled"},
	})
	if len(got) != 1 || got[0].ScanRunID != "run-1" {
		t.Fatalf("relayed: %+v", got)
	}
}
