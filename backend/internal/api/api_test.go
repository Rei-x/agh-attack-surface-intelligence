package api

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

func setupTestServer(t *testing.T) (*Server, *db.MemoryStore, http.Handler) {
	t.Helper()
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	store := db.NewMemoryStore(vault)
	if err := db.SeedDefaults(context.Background(), store, true); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	hub := NewSSEHub()
	pipeline := ingest.NewPipeline(store, ingest.NewDefaultAnalyzer(), hub.Publish)
	runner := NewStubScanRunner(store, pipeline, hub)
	srv := NewServer(Config{
		JWTSecret: vault.JWTSecret(""),
		SeedDemo:  true,
	}, store, vault, pipeline, runner, hub)
	return srv, store, srv.Handler()
}

func loginTest(t *testing.T, h http.Handler, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s failed: code=%d body=%s", username, rec.Code, rec.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.Token
}

func doJSON(h http.Handler, method, path, token string, payload any) *httptest.ResponseRecorder {
	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEndToEndAPIWorkflowRBACOverridesCryptoAndDefectDojo(t *testing.T) {
	_, _, h := setupTestServer(t)

	// 1. Health check
	rec := doJSON(h, http.MethodGet, "/api/v1/health", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"encryption_active":true`) {
		t.Fatalf("health failed: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 2. Login all 4 RBAC roles
	adminTok := loginTest(t, h, "admin", "Admin123!")
	opTok := loginTest(t, h, "operator", "Operator123!")
	analystTok := loginTest(t, h, "analyst", "Analyst123!")
	viewerTok := loginTest(t, h, "viewer", "Viewer123!")

	// 3. Enforce strict 403 Forbidden across roles
	if r := doJSON(h, http.MethodPost, "/api/v1/scans", viewerTok, map[string]any{"targets": []string{"172.28.0.10"}}); r.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /scans expected 403 got %d", r.Code)
	}
	if r := doJSON(h, http.MethodPost, "/api/v1/scans", analystTok, map[string]any{"targets": []string{"172.28.0.10"}}); r.Code != http.StatusForbidden {
		t.Fatalf("analyst POST /scans expected 403 got %d", r.Code)
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/admin/users", opTok, nil); r.Code != http.StatusForbidden {
		t.Fatalf("operator GET /admin/users expected 403 got %d", r.Code)
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/admin/users", adminTok, nil); r.Code != http.StatusOK {
		t.Fatalf("admin GET /admin/users expected 200 got %d", r.Code)
	}

	// 4. Create custom RBAC role & verify immediate enforcement
	roleRec := doJSON(h, http.MethodPost, "/api/v1/admin/roles", adminTok, map[string]any{
		"slug":        "auditor_custom",
		"name":        "Audytor Bezpieczeństwa",
		"permissions": []string{domain.PermDashboardRead, domain.PermAdminAudit},
	})
	if roleRec.Code != http.StatusCreated {
		t.Fatalf("create custom role failed: %d %s", roleRec.Code, roleRec.Body.String())
	}
	userRec := doJSON(h, http.MethodPost, "/api/v1/admin/users", adminTok, map[string]any{
		"username":  "auditor1",
		"email":     "auditor@cbi.agh.edu.pl",
		"password":  "Auditor123!",
		"role_slug": "auditor_custom",
	})
	if userRec.Code != http.StatusCreated {
		t.Fatalf("create custom user failed: %d %s", userRec.Code, userRec.Body.String())
	}
	auditorTok := loginTest(t, h, "auditor1", "Auditor123!")
	if r := doJSON(h, http.MethodGet, "/api/v1/admin/audit", auditorTok, nil); r.Code != http.StatusOK {
		t.Fatalf("custom role GET /admin/audit expected 200 got %d", r.Code)
	}
	if r := doJSON(h, http.MethodDelete, "/api/v1/hosts/nonexistent", auditorTok, nil); r.Code != http.StatusForbidden {
		t.Fatalf("custom role DELETE /hosts expected 403 got %d", r.Code)
	}

	// 5. Large-scale target estimate (10.0.0.0/18 = 16,384 IPs - 256 excluded = 16,128)
	estRec := doJSON(h, http.MethodPost, "/api/v1/targets/estimate", opTok, map[string]any{
		"targets":    []string{"10.0.0.0/18"},
		"exclusions": []string{"10.0.0.0/24"},
		"ports":      "22,80,443,8080",
	})
	if estRec.Code != http.StatusOK || !strings.Contains(estRec.Body.String(), `"effective_ips":16128`) {
		t.Fatalf("estimate failed: %d %s", estRec.Code, estRec.Body.String())
	}

	// 6. Multipart CSV import (Scan 1) -> Analyst Override -> JSON import (Scan 2) -> Diff
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	_ = mw.WriteField("format", "csv")
	_ = mw.WriteField("scan_name", "Baseline CSV")
	fw, _ := mw.CreateFormFile("file", "baseline.csv")
	_, _ = fw.Write([]byte("ip,hostname,port,service,product,http_title\n172.28.0.14,moodle.agh.edu.pl,80,http,nginx,AGH Moodle\n"))
	mw.Close()
	impReq := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/import", &mp)
	impReq.Header.Set("Authorization", "Bearer "+opTok)
	impReq.Header.Set("Content-Type", mw.FormDataContentType())
	impRec := httptest.NewRecorder()
	h.ServeHTTP(impRec, impReq)
	if impRec.Code != http.StatusCreated {
		t.Fatalf("CSV multipart import failed: %d %s", impRec.Code, impRec.Body.String())
	}
	var res1 struct {
		ScanRun domain.ScanRun `json:"scan_run"`
	}
	_ = json.Unmarshal(impRec.Body.Bytes(), &res1)

	hostsRec := doJSON(h, http.MethodGet, "/api/v1/hosts?q=172.28.0.14", analystTok, nil)
	var hostsResp struct {
		Hosts []domain.Host `json:"hosts"`
	}
	_ = json.Unmarshal(hostsRec.Body.Bytes(), &hostsResp)
	if len(hostsResp.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hostsResp.Hosts))
	}
	hostID := hostsResp.Hosts[0].ID

	// Analyst pins owner & notes
	ovRec := doJSON(h, http.MethodPatch, "/api/v1/hosts/"+hostID+"/overrides", analystTok, map[string]any{
		"owner": "CBI E-Learning",
		"notes": "Pinned override must survive rescan",
	})
	if ovRec.Code != http.StatusOK {
		t.Fatalf("PATCH overrides failed: %d %s", ovRec.Code, ovRec.Body.String())
	}

	// Scan 2 via JSON import with mutated title
	res2Rec := doJSON(h, http.MethodPost, "/api/v1/ingest/import", opTok, map[string]any{
		"format":    "json",
		"scan_name": "Post Mutation JSON",
		"observations": []map[string]any{
			{
				"ip":         "172.28.0.14",
				"hostname":   "moodle-changed.agh.edu.pl",
				"port":       80,
				"service":    "http",
				"product":    "nginx",
				"http_title": "AGH Moodle Admin Exposed",
			},
		},
	})
	if res2Rec.Code != http.StatusCreated {
		t.Fatalf("JSON import failed: %d %s", res2Rec.Code, res2Rec.Body.String())
	}
	var res2 struct {
		ScanRun domain.ScanRun `json:"scan_run"`
	}
	_ = json.Unmarshal(res2Rec.Body.Bytes(), &res2)

	// Verify override preserved & diff captured title change
	hostAfter := doJSON(h, http.MethodGet, "/api/v1/hosts/"+hostID, viewerTok, nil)
	if !strings.Contains(hostAfter.Body.String(), "CBI E-Learning") {
		t.Fatalf("override lost after Scan 2: %s", hostAfter.Body.String())
	}
	diffRec := doJSON(h, http.MethodGet, "/api/v1/scans/diff?from="+res1.ScanRun.ID+"&to="+res2.ScanRun.ID, analystTok, nil)
	if diffRec.Code != http.StatusOK || !strings.Contains(diffRec.Body.String(), "AGH Moodle Admin Exposed") {
		t.Fatalf("scan diff failed: %d %s", diffRec.Code, diffRec.Body.String())
	}

	// 7. Signature safety validator & retroactive test
	badSig := doJSON(h, http.MethodPost, "/api/v1/signatures/validate", analystTok, map[string]any{
		"name":     "Traversal",
		"matchers": []map[string]any{{"type": "safe_path", "key": "/../../etc/passwd", "pattern": "root:"}},
	})
	if !strings.Contains(badSig.Body.String(), `"valid":false`) {
		t.Fatalf("expected unsafe signature rejected, got %s", badSig.Body.String())
	}
	testSig := doJSON(h, http.MethodPost, "/api/v1/signatures/test", analystTok, map[string]any{
		"name":     "Moodle Admin Check",
		"matchers": []map[string]any{{"type": "html_body", "pattern": "Moodle Admin"}},
	})
	if testSig.Code != http.StatusOK || !strings.Contains(testSig.Body.String(), `"total_matches":1`) {
		t.Fatalf("retroactive test expected 1 match, got %d %s", testSig.Code, testSig.Body.String())
	}

	// 8. Crypto status proof & DEK key rotation
	cryptoRec := doJSON(h, http.MethodGet, "/api/v1/admin/crypto/status", adminTok, nil)
	if cryptoRec.Code != http.StatusOK || !strings.Contains(cryptoRec.Body.String(), "enc:v1:dek-v1:") {
		t.Fatalf("crypto status missing raw ciphertext proof: %d %s", cryptoRec.Code, cryptoRec.Body.String())
	}
	rotRec := doJSON(h, http.MethodPost, "/api/v1/admin/crypto/rotate", adminTok, nil)
	if rotRec.Code != http.StatusOK || !strings.Contains(rotRec.Body.String(), "dek-v2") {
		t.Fatalf("crypto rotate failed: %d %s", rotRec.Code, rotRec.Body.String())
	}

	// 9. Graph, Clusters & Dashboard summary
	if r := doJSON(h, http.MethodGet, "/api/v1/graph", viewerTok, nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "172.28.0.14") {
		t.Fatalf("graph failed: %d %s", r.Code, r.Body.String())
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/dashboard/summary", viewerTok, nil); r.Code != http.StatusOK {
		t.Fatalf("dashboard summary failed: %d", r.Code)
	}
}
