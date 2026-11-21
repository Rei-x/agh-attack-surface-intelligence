package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

// TestScale10kHostsGraphPaginationClustersAndDashboard verifies that 10,240 encrypted hosts
// across 40 /24 subnets are handled cleanly without bloating API responses or freezing the UI.
func TestScale10kHostsGraphPaginationClustersAndDashboard(t *testing.T) {
	ctx := context.Background()
	vault, err := crypto.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	store := db.NewMemoryStore(vault)
	if err := db.SeedDefaults(ctx, store, true); err != nil {
		t.Fatalf("seed: %v", err)
	}

	hub := NewSSEHub()
	analyzer := ingest.NewDefaultAnalyzer()
	pipeline := ingest.NewPipeline(store, analyzer, hub.Publish)
	runner := NewStubScanRunner(store, pipeline, hub)
	srv := NewServer(Config{
		JWTSecret: vault.JWTSecret("test-scale-secret"),
		TokenTTL:  time.Hour,
		SeedDemo:  true,
	}, store, vault, pipeline, runner, hub)

	const totalHosts = 10240 // 40 x /24 subnets (>10,000 IPs!)
	now := time.Now().UTC()

	templates := []struct {
		port    int
		service string
		product string
		version string
		title   string
		admin   bool
		staging bool
		iot     bool
		score   int
		tech    string
		cat     string
	}{
		{80, "http", "WordPress", "6.4.2", "AGH Wydział Portal", false, false, false, 20, "WordPress", "cms"},
		{443, "https", "Keycloak", "24.0.2", "AGH SSO Admin", true, true, false, 78, "Keycloak", "admin_panel"},
		{8080, "http", "HP LaserJet", "M428", "HP LaserJet Pro MFP", false, false, true, 35, "HP LaserJet", "iot"},
		{443, "https", "GitLab CE", "16.9.2", "AGH Faculty GitLab", false, false, false, 18, "GitLab", "server"},
		{80, "http", "phpMyAdmin", "5.2.1", "phpMyAdmin Console", true, false, false, 72, "phpMyAdmin", "admin_panel"},
		{8080, "http", "Spring Boot", "3.2.1", "Swagger UI Dev", false, true, false, 52, "Spring Boot", "framework"},
	}

	t0 := time.Now()
	for i := 0; i < totalHosts; i++ {
		third := i / 256
		fourth := i % 256
		ip := fmt.Sprintf("10.10.%d.%d", third, fourth)
		tpl := templates[i%len(templates)]

		state := domain.HostStateActive
		if i%25 == 0 {
			state = domain.HostStateIntermittent
		} else if i%40 == 0 {
			state = domain.HostStateInactive
		}

		h := &domain.Host{
			IP:                ip,
			Hostname:          fmt.Sprintf("host-%d-%d.agh.edu.pl", third, fourth),
			LifecycleState:    state,
			Environment:       "prod",
			FirstSeen:         now,
			LastSeen:          now,
			TotalScansSeen:    3,
			TotalScansChecked: 3,
			StabilityScore:    92,
			Interestingness:   tpl.score,
			Tags:              []string{tpl.cat},
		}
		if tpl.staging {
			h.Environment = "staging"
		}
		savedHost, err := store.UpsertObservedHost(ctx, h)
		if err != nil {
			t.Fatalf("upsert host %d: %v", i, err)
		}
		svc := &domain.Service{
			HostID:          savedHost.ID,
			HostIP:          ip,
			Port:            tpl.port,
			Protocol:        "tcp",
			State:           "open",
			ServiceName:     tpl.service,
			Product:         tpl.product,
			Version:         tpl.version,
			IsAdminPanel:    tpl.admin,
			IsStagingEnv:    tpl.staging,
			IsIoT:           tpl.iot,
			Interestingness: tpl.score,
			TriageStatus:    "new",
			Technologies: []domain.DetectedTechnology{{
				Name:       tpl.tech,
				Category:   tpl.cat,
				Version:    tpl.version,
				Confidence: 90,
			}},
			HTTP: &domain.HTTPFingerprint{
				StatusCode: 200,
				Title:      tpl.title,
			},
			FirstSeen: now,
			LastSeen:  now,
		}
		if _, err := store.UpsertObservedService(ctx, svc); err != nil {
			t.Fatalf("upsert service %d: %v", i, err)
		}
	}
	t.Logf("Populated %d encrypted hosts + services in %v", totalHosts, time.Since(t0))

	// Authenticate as admin
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "Admin123!"})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
	token := loginResp.Token
	doGet := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s -> %d: %s", path, rec.Code, rec.Body.String())
		}
		return rec
	}

	// 1. Paginated Hosts API must return 50 items out of 10,240
	t1 := time.Now()
	recHosts := doGet("/api/v1/hosts?page=1&limit=50")
	var hostsResp struct {
		Hosts      []domain.Host `json:"hosts"`
		Total      int           `json:"total"`
		Page       int           `json:"page"`
		Limit      int           `json:"limit"`
		TotalPages int           `json:"total_pages"`
	}
	if err := json.Unmarshal(recHosts.Body.Bytes(), &hostsResp); err != nil {
		t.Fatalf("decode hosts: %v", err)
	}
	if hostsResp.Total != totalHosts || len(hostsResp.Hosts) != 50 || hostsResp.TotalPages != 205 {
		t.Fatalf("unexpected pagination: total=%d len=%d total_pages=%d", hostsResp.Total, len(hostsResp.Hosts), hostsResp.TotalPages)
	}
	t.Logf("GET /api/v1/hosts?page=1&limit=50 (10,240 hosts) took %v", time.Since(t1))

	// 2. Graph API must auto-cluster 10,240 hosts into a crisp UI-safe node count (<= 160 nodes!)
	t2 := time.Now()
	recGraph := doGet("/api/v1/graph")
	var graphResp GraphResponse
	if err := json.Unmarshal(recGraph.Body.Bytes(), &graphResp); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	if !graphResp.Clustered || graphResp.TotalHosts != totalHosts || len(graphResp.Subnets) != 40 {
		t.Fatalf("expected auto-clustered graph for 10,240 hosts across 40 subnets, got clustered=%v total=%d subnets=%d",
			graphResp.Clustered, graphResp.TotalHosts, len(graphResp.Subnets))
	}
	if len(graphResp.Nodes) > 160 || len(graphResp.Nodes) < 10 {
		t.Fatalf("expected UI-safe node count in [10..160], got %d", len(graphResp.Nodes))
	}
	t.Logf("GET /api/v1/graph auto-clustered 10,240 hosts -> %d nodes, %d edges across %d subnets in %v",
		len(graphResp.Nodes), len(graphResp.Edges), len(graphResp.Subnets), time.Since(t2))

	// 3. Drill-down into a single /24 subnet with detailed cap
	recSub := doGet("/api/v1/graph?subnet=10.10.0.0/24&mode=detailed&limit=30")
	var subGraph GraphResponse
	if err := json.Unmarshal(recSub.Body.Bytes(), &subGraph); err != nil {
		t.Fatalf("decode subnet graph: %v", err)
	}
	if subGraph.Clustered || subGraph.ShownHosts != 30 {
		t.Fatalf("expected detailed drill-down with 30 hosts, got clustered=%v shown=%d", subGraph.Clustered, subGraph.ShownHosts)
	}

	// 4. Service Clusters across all 10,240 hosts
	t3 := time.Now()
	recClusters := doGet("/api/v1/clusters")
	var clResp struct {
		Clusters []domain.ServiceCluster `json:"clusters"`
	}
	if err := json.Unmarshal(recClusters.Body.Bytes(), &clResp); err != nil {
		t.Fatalf("decode clusters: %v", err)
	}
	if len(clResp.Clusters) == 0 {
		t.Fatalf("expected service clusters across 10,240 hosts")
	}
	t.Logf("GET /api/v1/clusters grouped 10,240 services -> %d clusters (top=%q count=%d) in %v",
		len(clResp.Clusters), clResp.Clusters[0].Label, clResp.Clusters[0].Count, time.Since(t3))

	// 5. Dashboard Summary across 10,240 hosts
	t4 := time.Now()
	recDash := doGet("/api/v1/dashboard/summary")
	var dash map[string]any
	if err := json.Unmarshal(recDash.Body.Bytes(), &dash); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if int(dash["total_hosts"].(float64)) != totalHosts {
		t.Fatalf("expected dashboard total_hosts=%d, got %v", totalHosts, dash["total_hosts"])
	}
	t.Logf("GET /api/v1/dashboard/summary across 10,240 hosts took %v", time.Since(t4))
}
