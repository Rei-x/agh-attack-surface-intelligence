package agent

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func pfx(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

func TestPrivateSubnetsFromFakeInterfaces(t *testing.T) {
	ifaces := []Interface{
		{Name: "lo0", Up: true, Loopback: true, Addrs: pfx("127.0.0.1/8", "::1/128")},
		{Name: "docker0", Up: true, Addrs: pfx("172.17.0.1/16")},
		{Name: "en0", Up: true, Addrs: pfx("fe80::1/64", "192.168.1.23/24", "fd12:3456:789a::5/64", "203.0.113.7/24")},
		{Name: "en1", Up: true, Addrs: pfx("192.168.1.40/24")}, // same network twice: listed once
		{Name: "tailscale0", Up: true, Addrs: pfx("100.101.102.103/32")},
		{Name: "eth9", Up: false, Addrs: pfx("10.9.9.9/24")},   // down
		{Name: "wide", Up: true, Addrs: pfx("10.1.2.3/7")},     // clamped to 10.0.0.0/8
		{Name: "pub", Up: true, Addrs: pfx("8.8.8.8/24")},      // public
		{Name: "ll", Up: true, Addrs: pfx("169.254.10.10/16")}, // link-local
	}
	got := PrivateSubnets(ifaces)
	want := []domain.LocalSubnet{
		{CIDR: "192.168.1.0/24", Address: "192.168.1.23", Interface: "en0"},
		{CIDR: "100.101.102.103/32", Address: "100.101.102.103", Interface: "tailscale0"},
		{CIDR: "10.0.0.0/8", Address: "10.1.2.3", Interface: "wide"},
		{CIDR: "fd12:3456:789a::/64", Address: "fd12:3456:789a::5", Interface: "en0"},
		{CIDR: "172.17.0.0/16", Address: "172.17.0.1", Interface: "docker0", Virtual: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PrivateSubnets:\n got %+v\nwant %+v", got, want)
	}
	if got := PrivateSubnets(nil); len(got) != 0 {
		t.Fatalf("no interfaces: %+v", got)
	}
}

func TestSystemInterfacesListsLoopback(t *testing.T) {
	ifaces, err := SystemInterfaces()
	if err != nil {
		t.Skipf("no interfaces here: %v", err)
	}
	for _, ifc := range ifaces {
		for _, a := range ifc.Addrs {
			if a.Addr().IsLoopback() {
				return
			}
		}
	}
	t.Skip("no loopback address reported")
}

// recordingLog collects log lines (the agent logs from several goroutines).
type recordingLog struct {
	t     *testing.T
	mu    sync.Mutex
	lines []string
}

func (l *recordingLog) logf(format string, args ...any) {
	l.t.Logf(format, args...)
	l.mu.Lock()
	l.lines = append(l.lines, format)
	l.mu.Unlock()
}

func (l *recordingLog) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// Without --allow-cidr the agent scans only the private networks of its own interfaces,
// says so in its log, reports them to the server, and refuses jobs outside them.
func TestAgentDefaultAllowlistFromInterfaces(t *testing.T) {
	ts := newTestServer(t)
	rec := &recordingLog{t: t}
	cfg := Config{ServerURL: ts.http.URL, Token: ts.token(), DataDir: t.TempDir(), Version: "test", PollWait: time.Second,
		EngineConfig: fakeNetwork(nil), Logf: rec.logf, Interfaces: labInterfaces}
	a, stop := startAgent(t, cfg)
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	for a.AgentID() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if a.AgentID() == "" {
		t.Fatal("agent did not enroll")
	}
	if !reflect.DeepEqual(a.caps.AllowCIDRs, []string{"10.77.0.0/16"}) || !a.caps.AllowFromInterfaces {
		t.Fatalf("default allowlist: %+v from interfaces=%v", a.caps.AllowCIDRs, a.caps.AllowFromInterfaces)
	}
	for !rec.has("no --allow-cidr given: scanning only this host's private networks") {
		if time.Now().After(deadline) {
			t.Fatal("the default allowlist is not logged")
		}
		time.Sleep(10 * time.Millisecond)
	}

	ag, err := ts.srv.Agents().GetAgent(context.Background(), a.AgentID())
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.LocalSubnet{{CIDR: "10.77.0.0/16", Address: "10.77.0.5", Interface: "eth0"}}
	if !reflect.DeepEqual(ag.Capabilities.LocalSubnets, want) || !ag.Capabilities.AllowFromInterfaces {
		t.Fatalf("server sees subnets %+v (from interfaces=%v)", ag.Capabilities.LocalSubnets, ag.Capabilities.AllowFromInterfaces)
	}

	refused := ts.queueRun(a.AgentID(), "10.78.0.0/28")
	run := ts.waitRun(refused, 10*time.Second, func(r *domain.ScanRun) bool { return r.Status == domain.ScanStatusFailed })
	if !strings.Contains(run.Notes, "refused") || !strings.Contains(run.Notes, "private networks 10.77.0.0/16") {
		t.Fatalf("refusal note: %q", run.Notes)
	}
	ok := ts.queueRun(a.AgentID(), "10.77.3.0/28")
	ts.waitRun(ok, 10*time.Second, func(r *domain.ScanRun) bool { return r.Status == domain.ScanStatusCompleted })
}

// A host with no private network refuses every job (the default never means "anything").
func TestAgentWithoutPrivateNetworkRefusesEverything(t *testing.T) {
	ts := newTestServer(t)
	rec := &recordingLog{t: t}
	public := func() ([]Interface, error) {
		return []Interface{{Name: "eth0", Up: true, Addrs: pfx("203.0.113.9/24")}}, nil
	}
	cfg := Config{ServerURL: ts.http.URL, Token: ts.token(), DataDir: t.TempDir(), Version: "test", PollWait: time.Second,
		EngineConfig: fakeNetwork(nil), Logf: rec.logf, Interfaces: public}
	a, stop := startAgent(t, cfg)
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	for a.AgentID() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	runID := ts.queueRun(a.AgentID(), "203.0.113.0/28")
	run := ts.waitRun(runID, 10*time.Second, func(r *domain.ScanRun) bool { return r.Status == domain.ScanStatusFailed })
	if !strings.Contains(run.Notes, "refused") {
		t.Fatalf("refusal note: %q", run.Notes)
	}
	if !rec.has("every scan job will be refused") {
		t.Fatal("missing warning about the empty allowlist")
	}
}

// An explicit --allow-cidr wins over the interfaces, and 0.0.0.0/0 allows any target.
func TestExplicitAllowCIDRWinsOverInterfaces(t *testing.T) {
	a, err := New(Config{ServerURL: "http://127.0.0.1:1", DataDir: t.TempDir(), AllowCIDRs: []string{"0.0.0.0/0"},
		Interfaces: labInterfaces, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.allowAuto || a.caps.AllowFromInterfaces || !reflect.DeepEqual(a.caps.AllowCIDRs, []string{"0.0.0.0/0"}) {
		t.Fatalf("explicit allowlist: %+v auto=%v", a.caps.AllowCIDRs, a.allowAuto)
	}
	if bad := a.outsideAllowlist([]string{"198.51.100.1", "10.1.1.1"}); bad != "" {
		t.Fatalf("0.0.0.0/0 refused %s", bad)
	}
	if len(a.caps.LocalSubnets) != 1 {
		t.Fatalf("local subnets are reported even with an explicit allowlist: %+v", a.caps.LocalSubnets)
	}
}
