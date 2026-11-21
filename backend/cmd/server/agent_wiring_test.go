package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// inventoryFingerprint renders what a scan produced (hosts, lifecycle, services, analysis,
// change events) without ids and run references, so two stores can be compared.
func inventoryFingerprint(t *testing.T, store db.Store) string {
	t.Helper()
	ctx := context.Background()
	hosts, _, err := store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP < hosts[j].IP })
	var b strings.Builder
	for _, h := range hosts {
		fmt.Fprintf(&b, "%s state=%s seen=%d checked=%d misses=%d score=%d env=%s tags=%v\n",
			h.IP, h.LifecycleState, h.TotalScansSeen, h.TotalScansChecked, h.ConsecutiveMisses, h.Interestingness, h.Environment, h.Tags)
		svcs, _ := store.ListServices(ctx, db.ServiceFilter{HostID: h.ID})
		sort.Slice(svcs, func(i, j int) bool { return svcs[i].Port < svcs[j].Port })
		for _, s := range svcs {
			tags := append([]string(nil), s.Tags...)
			sort.Strings(tags)
			fmt.Fprintf(&b, "  %d/%s %s product=%q version=%q admin=%v staging=%v score=%d tags=%v sigs=%d\n",
				s.Port, s.Protocol, s.ServiceName, s.Product, s.Version, s.IsAdminPanel, s.IsStagingEnv, s.Interestingness, tags, len(s.MatchedSignatures))
		}
	}
	changes, _ := store.ListChangeEvents(ctx, db.ChangeFilter{Limit: 1000})
	var evs []string
	for _, c := range changes {
		evs = append(evs, c.EventType+" "+c.HostIP+" "+c.Severity)
	}
	sort.Strings(evs)
	fmt.Fprintf(&b, "changes=%v\n", evs)
	return b.String()
}

func newTestStore(t *testing.T) (*db.MemoryStore, *ingest.Pipeline) {
	t.Helper()
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewMemoryStore(vault)
	return store, ingest.NewPipeline(store, NewIntelligenceAnalyzer(), nil)
}

// TestAgentResultsIdenticalToLocalScan feeds the same observations once through the local
// runner's ingest path and once through agent chunk uploads (two chunks, one retried): the
// resulting inventory, lifecycle transitions (incl. missing-host scoping) and change events
// must be identical.
func TestAgentResultsIdenticalToLocalScan(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	scope := []string{"10.9.0.1", "10.9.0.2", "10.9.0.3"}
	obs := []domain.ObservedHost{
		{IP: "10.9.0.1", IsAlive: true, ObservedAt: now, Services: []domain.ObservedService{
			{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http", Product: "nginx", Version: "1.24.0",
				HTTP: &domain.HTTPFingerprint{StatusCode: 200, Title: "Grafana", Headers: map[string]string{"Server": "nginx/1.24.0"}}},
			{Port: 22, Protocol: "tcp", State: "open", ServiceName: "ssh", Product: "OpenSSH", Version: "9.6"},
		}},
		{IP: "10.9.0.2", IsAlive: true, ObservedAt: now, Services: []domain.ObservedService{
			{Port: 443, Protocol: "tcp", State: "open", ServiceName: "https", HTTP: &domain.HTTPFingerprint{StatusCode: 200, Title: "Staging USOS"}},
		}},
		{IP: "10.9.0.3", IsAlive: false, ObservedAt: now}, // known before, now silent -> missing
	}
	profile := domain.ScanProfile{Name: "eq", Targets: []string{"10.9.0.0/30"}, AllowedPorts: "22,80,443", MissingThreshold: 1, GracePeriodHours: 1}

	seed := func(store db.Store, p *ingest.Pipeline) {
		// Earlier inventory: 10.9.0.3 in scope (must go missing), 10.8.0.1 out of scope (untouched).
		if _, err := p.ProcessObservations(ctx, ingest.IngestRequest{RunType: domain.ScanTypeManual, Observations: []domain.ObservedHost{
			{IP: "10.9.0.3", IsAlive: true, ObservedAt: now.Add(-48 * time.Hour), Services: []domain.ObservedService{{Port: 22, Protocol: "tcp", State: "open", ServiceName: "ssh"}}},
			{IP: "10.8.0.1", IsAlive: true, ObservedAt: now.Add(-48 * time.Hour), Services: []domain.ObservedService{{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http"}}},
		}}); err != nil {
			t.Fatal(err)
		}
	}

	// Local scan path (LiveScanRunner.ingestSegment, as after Engine.Execute).
	storeA, pipeA := newTestStore(t)
	seed(storeA, pipeA)
	pA := profile
	_ = storeA.CreateProfile(ctx, &pA)
	runA := &domain.ScanRun{ID: db.NewID(), ProfileID: pA.ID, Name: "eq", RunType: domain.ScanTypeActive, Status: domain.ScanStatusRunning}
	_ = storeA.CreateScanRun(ctx, runA)
	local := NewLiveScanRunner(storeA, pipeA, nil)
	if err := local.ingestSegment(ctx, runA, pA, &scanner.RunResult{ObservedHosts: obs, ScannedIPs: scope}); err != nil {
		t.Fatal(err)
	}

	// Agent path.
	storeB, pipeB := newTestStore(t)
	seed(storeB, pipeB)
	coord := agenthub.New(storeB, pipeB, nil, agenthub.Options{})
	tok, _, _ := coord.CreateEnrollToken(ctx, "eq", "", time.Hour, "admin")
	enr, err := coord.Enroll(ctx, agenthub.EnrollRequest{Token: tok}, "")
	if err != nil {
		t.Fatal(err)
	}
	pB := profile
	pB.AgentID = enr.AgentID
	_ = storeB.CreateProfile(ctx, &pB)
	runB := &domain.ScanRun{ID: db.NewID(), ProfileID: pB.ID, Name: "eq", RunType: domain.ScanTypeActive, Status: domain.ScanStatusQueued}
	_ = storeB.CreateScanRun(ctx, runB)
	if err := coord.Enqueue(ctx, runB, &pB); err != nil {
		t.Fatal(err)
	}
	if spec, err := coord.NextJob(ctx, enr.AgentID, "i", 0); err != nil || spec == nil {
		t.Fatalf("claim: %v %v", spec, err)
	}
	c0 := domain.ScanChunk{ID: "c0", ChunkIndex: 0, Targets: scope[:2], IPCount: 2, Status: domain.ChunkStatusPending}
	c1 := domain.ScanChunk{ID: "c1", ChunkIndex: 1, Targets: scope[2:], IPCount: 1, Status: domain.ChunkStatusPending}
	if _, err := coord.Start(ctx, enr.AgentID, "i", runB.ID, agenthub.StartRequest{TotalIPs: 3, Chunks: []domain.ScanChunk{c0, c1}}); err != nil {
		t.Fatal(err)
	}
	c0.Status, c1.Status = domain.ChunkStatusDone, domain.ChunkStatusDone
	for _, up := range []agenthub.ChunkUpload{
		{Chunk: c0, Observations: obs[:2]},
		{Chunk: c0, Observations: obs[:2]}, // retry after a lost response
		{Chunk: c1, Observations: obs[2:]},
	} {
		if _, err := coord.UploadChunk(ctx, enr.AgentID, "i", runB.ID, up); err != nil {
			t.Fatal(err)
		}
	}

	a, b := inventoryFingerprint(t, storeA), inventoryFingerprint(t, storeB)
	if a != b {
		t.Fatalf("agent ingest differs from local ingest\n--- local ---\n%s--- agent ---\n%s", a, b)
	}
	if !strings.Contains(a, "10.9.0.3 state=MISSING") && !strings.Contains(a, "10.9.0.3 state=INACTIVE") {
		t.Fatalf("missing-host detection did not run:\n%s", a)
	}
	if !strings.Contains(a, "10.8.0.1 state=NEW") && !strings.Contains(a, "10.8.0.1 state=ACTIVE") {
		t.Fatalf("out-of-scope host was touched:\n%s", a)
	}
	ra, _ := storeA.GetScanRun(ctx, runA.ID)
	rb, _ := storeB.GetScanRun(ctx, runB.ID)
	if ra.ChangesDetected != rb.ChangesDetected {
		t.Fatalf("changes detected: local %d, agent %d", ra.ChangesDetected, rb.ChangesDetected)
	}
	if rb.ScannedIPs != 3 || rb.CompletedChunks != 2 {
		t.Fatalf("agent run counters: %+v", rb)
	}
	snapA, _ := storeA.GetScanSnapshot(ctx, runA.ID)
	snapB, _ := storeB.GetScanSnapshot(ctx, runB.ID)
	if len(snapA) != len(snapB) || !reflect.DeepEqual(ipsOf(snapA), ipsOf(snapB)) {
		t.Fatalf("scan snapshots differ: %v vs %v", ipsOf(snapA), ipsOf(snapB))
	}
}

// The unit written by `aegis agent install` and the shipped deploy/aegis-agent.service match.
func TestSystemdUnitMatchesDeployFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "aegis-agent.service"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != systemdUnit {
		t.Fatal("deploy/aegis-agent.service differs from systemdUnit in cmd_agent.go")
	}
}

func ipsOf(hosts []domain.Host) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.IP)
	}
	sort.Strings(out)
	return out
}

// Boot recovery and the window watcher must leave agent runs to the agent coordinator.
func TestLocalRunnerSkipsAgentRuns(t *testing.T) {
	ctx := context.Background()
	store, pipe := newTestStore(t)
	coord := agenthub.New(store, pipe, nil, agenthub.Options{})
	tok, _, _ := coord.CreateEnrollToken(ctx, "skip", "", time.Hour, "admin")
	enr, _ := coord.Enroll(ctx, agenthub.EnrollRequest{Token: tok}, "")
	p := &domain.ScanProfile{Name: "remote", Targets: []string{"10.0.0.1"}, AllowedPorts: "80", AgentID: enr.AgentID}
	_ = store.CreateProfile(ctx, p)
	run := &domain.ScanRun{ID: db.NewID(), ProfileID: p.ID, Name: "remote", RunType: domain.ScanTypeActive, Status: domain.ScanStatusQueued}
	_ = store.CreateScanRun(ctx, run)
	if err := coord.Enqueue(ctx, run, p); err != nil {
		t.Fatal(err)
	}
	run.Status = domain.ScanStatusRunning
	_ = store.UpdateScanRun(ctx, run)
	_ = store.SaveScanChunks(ctx, run.ID, []domain.ScanChunk{{ID: "c", ChunkIndex: 0, Targets: []string{"10.0.0.1"}, IPCount: 1, Status: domain.ChunkStatusRunning}})

	r := NewLiveScanRunner(store, pipe, nil)
	r.isRemoteRun = coord.IsAgentRun
	if n, _ := r.RecoverInterrupted(ctx); n != 0 {
		t.Fatalf("recovered %d agent runs", n)
	}
	if got, _ := store.GetScanRun(ctx, run.ID); got.Status != domain.ScanStatusRunning {
		t.Fatalf("agent run touched by local recovery: %s", got.Status)
	}
	got, _ := store.GetScanRun(ctx, run.ID)
	got.Status = domain.ScanStatusPausedWindow
	_ = store.UpdateScanRun(ctx, got)
	r.checkPausedWindowScans(ctx)
	if r.IsScanActive(run.ID) {
		t.Fatal("window watcher resumed an agent run locally")
	}
}
