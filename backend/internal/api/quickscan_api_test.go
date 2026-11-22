package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/selfdist"
)

func TestInstallScriptCarriesTheInstanceURL(t *testing.T) {
	_, _, h := setupTestServer(t)
	get := func(host, proto string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
		req.Host = host
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := get("dzieciol.example.edu", "https") // behind a TLS proxy, no login needed
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(body, "#!/bin/sh\n") ||
		!strings.Contains(body, "\nSERVER_DOWNLOAD_BASE='https://dzieciol.example.edu/download'\n") {
		t.Fatalf("install.sh: %d\n%.400s", rec.Code, body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Fatalf("content type %q", ct)
	}

	t.Setenv("DZIECIOL_PUBLIC_URL", "https://scanner.agh.edu.pl/")
	if body := get("internal:8080", "").Body.String(); !strings.Contains(body, "SERVER_DOWNLOAD_BASE='https://scanner.agh.edu.pl/download'") {
		t.Fatal("DZIECIOL_PUBLIC_URL not used")
	}
	t.Setenv("DZIECIOL_PUBLIC_URL", "")
	// A forged Host header cannot put shell code into the script.
	if body := get("x$(id)", "").Body.String(); !strings.Contains(body, "\nSERVER_DOWNLOAD_BASE=\"\"\n") || strings.Contains(body, "$(id)") {
		t.Fatal("unsafe host reached the script")
	}
}

func TestDownloadRoutesArePublicWithChecksums(t *testing.T) {
	srv, _, h := setupTestServer(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dzieciol-linux-arm64"), []byte("arm build"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv.dist = &selfdist.Dist{Dir: dir}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/download/checksums.txt", nil))
	if rec.Code != http.StatusOK || !strings.HasSuffix(rec.Body.String(), "  dzieciol-linux-arm64\n") {
		t.Fatalf("checksums: %d %q", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/download/dzieciol-linux-arm64", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "arm build" {
		t.Fatalf("binary: %d %q", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/download/..%2Fapi_test.go", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("traversal: %d", rec.Code)
	}
}

func TestAgentTokenCommandsUseThisServer(t *testing.T) {
	_, _, h := setupTestServer(t)
	admin := loginTest(t, h, "admin", "Admin123!")
	rec := doJSON(h, http.MethodPost, "/api/v1/agents/tokens", admin, map[string]any{"ttl_hours": 2})
	var created struct {
		Token      string `json:"token"`
		Install    string `json:"install_command"`
		Foreground string `json:"foreground_command"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	server := "http://example.com" // httptest's default host
	want := "curl -fsSL " + server + "/install.sh | sudo sh -s -- --agent --server " + server + " --token " + created.Token
	if created.Install != want {
		t.Fatalf("install command:\n got %s\nwant %s", created.Install, want)
	}
	want = "curl -fsSL " + server + "/install.sh | sh -s -- --agent --foreground --server " + server + " --token " + created.Token
	if created.Foreground != want {
		t.Fatalf("foreground command:\n got %s\nwant %s", created.Foreground, want)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return v
}

type quickInfo struct {
	Lab struct {
		Available   bool     `json:"available"`
		Reason      string   `json:"reason"`
		ProfileName string   `json:"profile_name"`
		Targets     []string `json:"targets"`
		TotalIPs    int      `json:"total_ips"`
		AgentName   string   `json:"agent_name"`
		ActiveRunID string   `json:"active_run_id"`
	} `json:"lab"`
	ServerURL   string   `json:"server_url"`
	TokenAdmins []string `json:"token_admins"`
}

type quickStart struct {
	Run    domain.ScanRun `json:"run"`
	Joined bool           `json:"joined"`
}

func nextJob(t *testing.T, h http.Handler, credential string) agenthub.JobSpec {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/jobs/next", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+credential)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("jobs/next: %d %s", rec.Code, rec.Body)
	}
	return decodeBody[agenthub.JobSpec](t, rec)
}

// The lab option runs the lab profile in small chunks through its agent; a second click (or a
// second person) joins the scan instead of queueing another one.
func TestQuickScanLabStartsOnceAndJoins(t *testing.T) {
	_, store, h := setupTestServer(t)
	admin := loginTest(t, h, "admin", "Admin123!")
	operator := loginTest(t, h, "operator", "Operator123!")

	// Without configuration the smallest "lab" profile is offered (the seeded local one).
	info := decodeBody[quickInfo](t, doJSON(h, http.MethodGet, "/api/v1/quickscan", operator, nil))
	if !info.Lab.Available || !strings.Contains(info.Lab.ProfileName, "Lab") || info.ServerURL != "http://example.com" {
		t.Fatalf("default lab option: %+v", info)
	}
	if len(info.TokenAdmins) != 1 || info.TokenAdmins[0] != "admin" {
		t.Fatalf("operator should be told who can create agent commands: %v", info.TokenAdmins)
	}
	if info := decodeBody[quickInfo](t, doJSON(h, http.MethodGet, "/api/v1/quickscan", admin, nil)); info.TokenAdmins != nil {
		t.Fatalf("admin needs no hint: %v", info.TokenAdmins)
	}

	enr := enrollViaAPI(t, h, admin, "lab-agent")
	p := &domain.ScanProfile{Name: "Lab AGH whole network", Targets: []string{"10.66.0.0/18"}, AllowedPorts: "22,80,443",
		MaxRatePPS: 500, HTTPRPS: 25, Concurrency: 16, ChunkTargetSec: 60, Enabled: true, AgentID: enr.AgentID,
		MissingThreshold: 2, GracePeriodHours: 24, EnableHTTPFingerprint: true}
	if err := store.CreateProfile(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DZIECIOL_QUICKSCAN_PROFILE", "lab agh whole network")
	info = decodeBody[quickInfo](t, doJSON(h, http.MethodGet, "/api/v1/quickscan", operator, nil))
	if !info.Lab.Available || info.Lab.AgentName != "lab-agent" || info.Lab.TotalIPs != 1024 ||
		len(info.Lab.Targets) != 1 || info.Lab.Targets[0] != "10.66.0.0/22" {
		t.Fatalf("configured lab option: %+v", info.Lab)
	}

	rec := doJSON(h, http.MethodPost, "/api/v1/quickscan/lab", operator, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	first := decodeBody[quickStart](t, rec)
	if first.Joined || first.Run.ID == "" {
		t.Fatalf("first click: %+v", first)
	}
	waitFor(t, func() bool { run, _ := store.GetScanRun(context.Background(), first.Run.ID); return run.Notes != "" })
	rec = doJSON(h, http.MethodPost, "/api/v1/quickscan/lab", admin, nil)
	second := decodeBody[quickStart](t, rec)
	if rec.Code != http.StatusOK || !second.Joined || second.Run.ID != first.Run.ID {
		t.Fatalf("second click should join %s: %d %+v", first.Run.ID, rec.Code, second)
	}

	spec := nextJob(t, h, enr.Credential)
	if spec.RunID != first.Run.ID || spec.Profile.ChunkTargetSec != quickChunkTargetSec || spec.Profile.MaxRatePPS != 500 ||
		spec.Profile.AllowedPorts != "22,80,443" || strings.Join(spec.Profile.Targets, ",") != "10.66.0.0/22" {
		t.Fatalf("job for the agent: %+v", spec.Profile)
	}
	if viewer := loginTest(t, h, "viewer", "Viewer123!"); doJSON(h, http.MethodPost, "/api/v1/quickscan/lab", viewer, nil).Code != http.StatusForbidden {
		t.Fatal("viewer may not start scans")
	}
}

func TestQuickScanThroughAgentStaysInsideItsNetworks(t *testing.T) {
	_, store, h := setupTestServer(t)
	admin := loginTest(t, h, "admin", "Admin123!")
	tok := decodeBody[struct {
		Token string `json:"token"`
	}](t, doJSON(h, http.MethodPost, "/api/v1/agents/tokens", admin, map[string]any{"ttl_hours": 1}))
	caps := domain.AgentCapabilities{Hostname: "jury-laptop", AllowCIDRs: []string{"192.168.1.0/24", "172.17.0.0/16"}, AllowFromInterfaces: true,
		LocalSubnets: []domain.LocalSubnet{{CIDR: "192.168.1.0/24", Address: "192.168.1.23", Interface: "en0"},
			{CIDR: "172.17.0.0/16", Address: "172.17.0.1", Interface: "docker0", Virtual: true}}}
	rec := doJSON(h, http.MethodPost, "/api/v1/agent/enroll", "", map[string]any{"token": tok.Token, "version": "test", "capabilities": caps})
	enr := decodeBody[agenthub.EnrollResponse](t, rec)

	agents := decodeBody[struct {
		Agents []domain.Agent `json:"agents"`
	}](t, doJSON(h, http.MethodGet, "/api/v1/agents", admin, nil))
	if len(agents.Agents) != 1 || len(agents.Agents[0].Capabilities.LocalSubnets) != 2 || agents.Agents[0].Name != "jury-laptop" {
		t.Fatalf("agent list: %+v", agents.Agents)
	}

	for target, code := range map[string]int{
		"10.0.0.0/24":    http.StatusBadRequest, // not its network
		"172.17.0.0/16":  http.StatusBadRequest, // its network, but too large for a quick scan
		"192.168.0.0/16": http.StatusBadRequest,
		"example.com":    http.StatusBadRequest,
	} {
		rec := doJSON(h, http.MethodPost, "/api/v1/quickscan/agent", admin, map[string]any{"agent_id": enr.AgentID, "target": target})
		if rec.Code != code {
			t.Errorf("%s: %d %s, want %d", target, rec.Code, rec.Body, code)
		}
	}
	rec = doJSON(h, http.MethodPost, "/api/v1/quickscan/agent", admin, map[string]any{"agent_id": enr.AgentID, "target": "192.168.1.0/24"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("subnet scan: %d %s", rec.Code, rec.Body)
	}
	started := decodeBody[quickStart](t, rec)
	waitFor(t, func() bool { run, _ := store.GetScanRun(context.Background(), started.Run.ID); return run.Notes != "" })
	spec := nextJob(t, h, enr.Credential)
	if spec.RunID != started.Run.ID || spec.Profile.MaxRatePPS != quickAgentRatePPS || spec.Profile.AllowedPorts != scanner.AutoWidePorts ||
		spec.Profile.ChunkTargetSec != 1 || strings.Join(spec.Profile.Targets, ",") != "192.168.1.0/24" {
		t.Fatalf("conservative defaults: %+v", spec.Profile)
	}
	if rec := doJSON(h, http.MethodPost, "/api/v1/quickscan/agent", admin, map[string]any{"agent_id": "nope", "target": "192.168.1.0/24"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown agent: %d", rec.Code)
	}
}

func TestAgentMayScan(t *testing.T) {
	caps := domain.AgentCapabilities{AllowCIDRs: []string{"10.20.0.0/16"}}
	for target, ok := range map[string]bool{"10.20.3.0/24": true, "10.20.0.0/16": true, "10.0.0.0/8": false, "10.21.0.0/24": false} {
		if got := agentMayScan(caps, mustPrefix(t, target)); got != ok {
			t.Errorf("%s: %v", target, got)
		}
	}
	// An older agent that reports subnets but no allowlist: only its subnets.
	old := domain.AgentCapabilities{LocalSubnets: []domain.LocalSubnet{{CIDR: "192.168.5.0/24"}}}
	if !agentMayScan(old, mustPrefix(t, "192.168.5.0/24")) || agentMayScan(old, mustPrefix(t, "192.168.6.0/24")) {
		t.Fatal("old agent subnets")
	}
	// Default allowlist from interfaces with no private network: nothing.
	if agentMayScan(domain.AgentCapabilities{AllowFromInterfaces: true}, mustPrefix(t, "192.168.5.0/24")) {
		t.Fatal("empty default allowlist must allow nothing")
	}
}

func TestQuickLabTargets(t *testing.T) {
	for in, want := range map[string]string{
		"10.66.0.0/18":   "10.66.0.0/22",
		"10.66.0.0/22":   "10.66.0.0/22",
		"10.66.0.0/24":   "10.66.0.0/24",
		"172.28.0.10-14": "172.28.0.10-14",
	} {
		if got := strings.Join(quickLabTargets([]string{in}), ","); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
