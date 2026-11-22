package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/digest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/notify"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/policy"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/remediation"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scheduler"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/screenshot"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/verify"
)

// AppVersion is overridden at build time via -ldflags "-X .../internal/api.AppVersion=..."
var AppVersion = "1.0.0"

// Config holds runtime options for the HTTP API server.
type Config struct {
	JWTSecret []byte
	TokenTTL  time.Duration
	SeedDemo  bool
	StaticDir string
	// StaticFS serves the SPA from an fs.FS (e.g. the go:embed UI) when StaticDir is empty.
	StaticFS fs.FS
	// StaticFallback is served for "/" when neither StaticDir nor StaticFS has an index.html.
	StaticFallback string
	AllowedOrigin  string
	// Agents is the remote scanning agent coordinator (nil: a private one is created, so the
	// agent API always exists).
	Agents *agenthub.Coordinator
}

// Server serves the complete Dzięcioł v1 REST API, SSE stream, and embedded/static SPA.
type Server struct {
	cfg      Config
	store    db.Store
	vault    *crypto.Vault
	authMW   *auth.Middleware
	pipeline *ingest.Pipeline
	runner   ScanRunner
	dojo     *defectdojo.Client
	hub      *SSEHub
	mux      *http.ServeMux

	schedOnce  sync.Once
	localSched *scheduler.Scheduler

	notifier *notify.Notifier // outbound alert webhook (fed by the ingest pipeline)
	agents   *agenthub.Coordinator
	policy   *policy.Engine // zone policies (handlers_policy.go)

	remediation *remediation.Service // owner tickets verified by scans (handlers_remediation.go)
	digest      *digest.Service      // morning digest

	routes []string      // registered mux patterns (see handle)
	logins *loginLimiter // failed-login throttling

	shots *screenshot.Store // web screenshot gallery (handlers_screenshots.go), nil = off

	verify *verify.Service // safe verification checks (handlers_verify.go), nil = unavailable

	dojoSyncMu    sync.Mutex
	dojoSyncTimer *time.Timer // debounced triage -> DefectDojo sync (queueDojoSync)
}

// NewServer constructs a fully wired Dzięcioł HTTP Server.
func NewServer(cfg Config, store db.Store, vault *crypto.Vault, pipeline *ingest.Pipeline, runner ScanRunner, hub *SSEHub) *Server {
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = 24 * time.Hour
	}
	if hub == nil {
		hub = NewSSEHub()
	}
	if pipeline == nil {
		pipeline = ingest.NewPipeline(store, ingest.NewDefaultAnalyzer(), hub.Publish)
	}
	if runner == nil {
		runner = NewStubScanRunner(store, pipeline, hub)
	}

	s := &Server{
		cfg:      cfg,
		store:    store,
		vault:    vault,
		authMW:   auth.NewMiddleware(cfg.JWTSecret, store, store),
		pipeline: pipeline,
		runner:   runner,
		dojo:     defectdojo.NewClient(),
		hub:      hub,
		mux:      http.NewServeMux(),
		logins:   newLoginLimiter(),
	}
	s.authMW.IsNotFound = func(err error) bool { return errors.Is(err, db.ErrNotFound) }
	hub.mu.Lock()
	hub.observer = s.observeRunTelemetry
	hub.mu.Unlock()
	s.agents = cfg.Agents
	if ar, ok := runner.(*AgentAwareRunner); ok && s.agents == nil {
		s.agents = ar.Agents
	}
	if s.agents == nil {
		s.agents = agenthub.New(store, pipeline, hub.Publish, agenthub.Options{})
	}
	s.runner = NewAgentAwareRunner(runner, s.agents)
	s.notifier = notify.New(store)
	pipeline.SetNotifier(s.notifier)
	s.initPolicy()
	s.initRemediation()
	s.initVerify()
	s.registerRoutes()
	return s
}

// Handler returns the root HTTP handler wrapped with security headers, CORS policy and
// request body limits.
func (s *Server) Handler() http.Handler {
	return s.hardeningMiddleware(s.mux)
}

func (s *Server) registerRoutes() {
	mw := s.authMW

	s.handle("GET /api/v1/health", s.handleHealth)
	s.handle("GET /api/v1/auth/demo-accounts", s.handleDemoAccounts)
	s.handle("POST /api/v1/auth/login", s.handleLogin)
	s.handle("GET /api/v1/auth/me", mw.Authenticate(s.handleMe))

	s.handle("GET /api/v1/dashboard/summary", mw.RequirePerm(domain.PermDashboardRead, s.handleDashboardSummary))
	s.handle("GET /api/v1/graph", mw.RequirePerm(domain.PermAssetsRead, s.handleGraph))
	s.handle("GET /api/v1/clusters", mw.RequirePerm(domain.PermAssetsRead, s.handleClusters))
	s.handle("GET /api/v1/inventory", mw.RequirePerm(domain.PermAssetsRead, s.handleInventory))
	s.handle("GET /api/v1/events/stream", mw.Authenticate(s.hub.ServeHTTP))

	s.handle("GET /api/v1/targets", mw.RequirePerm(domain.PermScansRead, s.handleListTargets))
	s.handle("POST /api/v1/targets", mw.RequirePerm(domain.PermScansWrite, s.handleCreateTarget))
	s.handle("DELETE /api/v1/targets/{id}", mw.RequirePerm(domain.PermScansDelete, s.handleDeleteTarget))
	s.handle("POST /api/v1/targets/estimate", mw.RequirePerm(domain.PermScansRead, s.handleEstimateTargets))

	s.handle("GET /api/v1/exclusions", mw.RequirePerm(domain.PermScansRead, s.handleListExclusions))
	s.handle("POST /api/v1/exclusions", mw.RequirePerm(domain.PermScansWrite, s.handleCreateExclusion))
	s.handle("DELETE /api/v1/exclusions/{id}", mw.RequirePerm(domain.PermScansDelete, s.handleDeleteExclusion))

	s.handle("GET /api/v1/profiles", mw.RequirePerm(domain.PermScansRead, s.handleListProfiles))
	s.handle("POST /api/v1/profiles", mw.RequirePerm(domain.PermScansWrite, s.handleCreateProfile))
	s.handle("GET /api/v1/profiles/{id}", mw.RequirePerm(domain.PermScansRead, s.handleGetProfile))
	s.handle("PUT /api/v1/profiles/{id}", mw.RequirePerm(domain.PermScansWrite, s.handleUpdateProfile))
	s.handle("POST /api/v1/profiles/{id}/run", mw.RequirePerm(domain.PermScansRun, s.handleRunProfileNow))
	s.handle("DELETE /api/v1/profiles/{id}", mw.RequirePerm(domain.PermScansDelete, s.handleDeleteProfile))

	s.handle("GET /api/v1/scans", mw.RequirePerm(domain.PermScansRead, s.handleListScans))
	s.handle("POST /api/v1/scans", mw.RequirePerm(domain.PermScansRun, s.handleStartScan))
	s.handle("GET /api/v1/scans/diff", mw.RequirePerm(domain.PermScansRead, s.handleScanDiff))
	s.handle("GET /api/v1/scans/{id}", mw.RequirePerm(domain.PermScansRead, s.handleGetScan))
	s.handle("GET /api/v1/scans/{id}/nmap.xml", mw.RequirePerm(domain.PermScansRead, s.handleScanNmapXML))
	s.handle("PUT /api/v1/scans/{id}", mw.RequirePerm(domain.PermScansWrite, s.handleUpdateScanMeta))
	s.handle("POST /api/v1/scans/{id}/pause", mw.RequirePerm(domain.PermScansRun, s.handlePauseScan))
	s.handle("POST /api/v1/scans/{id}/resume", mw.RequirePerm(domain.PermScansRun, s.handleResumeScan))
	s.handle("POST /api/v1/scans/{id}/stop", mw.RequirePerm(domain.PermScansRun, s.handleStopScan))
	s.handle("DELETE /api/v1/scans/{id}", mw.RequirePerm(domain.PermScansDelete, s.handleDeleteScan))

	s.handle("GET /api/v1/hosts", mw.RequirePerm(domain.PermAssetsRead, s.handleListHosts))
	s.handle("GET /api/v1/hosts/{id}", mw.RequirePerm(domain.PermAssetsRead, s.handleGetHost))
	s.handle("PATCH /api/v1/hosts/{id}/overrides", mw.RequirePerm(domain.PermAssetsWrite, s.handlePatchHostOverrides))
	s.handle("DELETE /api/v1/hosts/{id}", mw.RequirePerm(domain.PermAssetsDelete, s.handleDeleteHost))

	s.handle("GET /api/v1/services", mw.RequirePerm(domain.PermAssetsRead, s.handleListServices))
	s.handle("PATCH /api/v1/services/{id}/overrides", mw.RequirePerm(domain.PermAssetsWrite, s.handlePatchServiceOverrides))
	s.handle("GET /api/v1/services/{id}/observations", mw.RequirePerm(domain.PermAssetsRead, s.handleServiceObservations))

	s.handle("GET /api/v1/changes", mw.RequirePerm(domain.PermAssetsRead, s.handleListChanges))
	s.handle("POST /api/v1/changes/{id}/acknowledge", mw.RequirePerm(domain.PermAssetsWrite, s.handleAcknowledgeChange))

	s.handle("GET /api/v1/hosts/{id}/timeline", mw.RequirePerm(domain.PermAssetsRead, s.handleHostTimeline))
	s.handle("GET /api/v1/tag-rules", mw.RequirePerm(domain.PermAssetsRead, s.handleListTagRules))
	s.handle("PUT /api/v1/tag-rules", mw.RequirePerm(domain.PermAssetsWrite, s.handleSaveTagRules))
	s.handle("POST /api/v1/tag-rules/apply", mw.RequirePerm(domain.PermAssetsWrite, s.handleApplyTagRules))
	s.handle("GET /api/v1/integrations/webhook", mw.RequirePerm(domain.PermAdminSettings, s.handleGetWebhook))
	s.handle("PUT /api/v1/integrations/webhook", mw.RequirePerm(domain.PermAdminSettings, s.handleSaveWebhook))
	s.handle("POST /api/v1/integrations/webhook/test", mw.RequirePerm(domain.PermAdminSettings, s.handleTestWebhook))

	s.handle("POST /api/v1/ingest/manual", mw.RequirePerm(domain.PermAssetsWrite, s.handleIngestManual))
	s.handle("POST /api/v1/ingest/import", mw.RequirePerm(domain.PermImportWrite, s.handleIngestImport))
	s.handle("GET /api/v1/export", mw.RequirePerm(domain.PermExportRead, s.handleExport))

	s.handle("GET /api/v1/signatures", mw.RequirePerm(domain.PermSignaturesRead, s.handleListSignatures))
	s.handle("POST /api/v1/signatures", mw.RequirePerm(domain.PermSignaturesWrite, s.handleCreateSignature))
	s.handle("POST /api/v1/signatures/validate", mw.RequirePerm(domain.PermSignaturesRead, s.handleValidateSignature))
	s.handle("POST /api/v1/signatures/test", mw.RequirePerm(domain.PermSignaturesRead, s.handleTestSignature))
	s.handle("POST /api/v1/signatures/import", mw.RequirePerm(domain.PermSignaturesWrite, s.handleImportSignatures))
	s.handle("GET /api/v1/signatures/export", mw.RequirePerm(domain.PermSignaturesRead, s.handleExportSignatures))
	s.handle("PUT /api/v1/signatures/{id}", mw.RequirePerm(domain.PermSignaturesWrite, s.handleUpdateSignature))
	s.handle("DELETE /api/v1/signatures/{id}", mw.RequirePerm(domain.PermSignaturesDelete, s.handleDeleteSignature))

	s.handle("GET /api/v1/integrations/defectdojo", mw.RequirePerm(domain.PermDefectDojoPush, s.handleGetDefectDojoConfig))
	s.handle("PUT /api/v1/integrations/defectdojo", mw.RequirePerm(domain.PermAdminSettings, s.handleSaveDefectDojoConfig))
	s.handle("PUT /api/v1/integrations/defectdojo/login", mw.RequirePerm(domain.PermAdminSettings, s.handleSaveDefectDojoLogin))
	s.handle("DELETE /api/v1/integrations/defectdojo/login", mw.RequirePerm(domain.PermAdminSettings, s.handleClearDefectDojoLogin))
	s.handle("POST /api/v1/integrations/defectdojo/test", mw.RequirePerm(domain.PermDefectDojoPush, s.handleTestDefectDojo))
	s.handle("POST /api/v1/integrations/defectdojo/push-findings", mw.RequirePerm(domain.PermDefectDojoPush, s.handlePushDefectDojoFindings))
	s.handle("POST /api/v1/integrations/defectdojo/push-nmap", mw.RequirePerm(domain.PermDefectDojoPush, s.handlePushDefectDojoNmap))
	s.handle("GET /api/v1/integrations/defectdojo/history", mw.RequirePerm(domain.PermDefectDojoPush, s.handleDefectDojoHistory))
	s.handle("GET /api/v1/integrations/defectdojo/status", mw.RequirePerm(domain.PermAssetsRead, s.handleDefectDojoStatus))
	s.handle("GET /api/v1/integrations/defectdojo/services", mw.RequirePerm(domain.PermAssetsRead, s.handleDefectDojoServiceStatus))
	s.handle("POST /api/v1/integrations/defectdojo/sync", mw.RequirePerm(domain.PermDefectDojoPush, s.handleDefectDojoSyncNow))

	s.handle("GET /api/v1/admin/users", mw.RequirePerm(domain.PermAdminUsers, s.handleListUsers))
	s.handle("POST /api/v1/admin/users", mw.RequirePerm(domain.PermAdminUsers, s.handleCreateUser))
	s.handle("PUT /api/v1/admin/users/{id}", mw.RequirePerm(domain.PermAdminUsers, s.handleUpdateUser))
	s.handle("DELETE /api/v1/admin/users/{id}", mw.RequirePerm(domain.PermAdminUsers, s.handleDeleteUser))

	s.handle("GET /api/v1/admin/roles", mw.RequirePerm(domain.PermAdminRoles, s.handleListRoles))
	s.handle("POST /api/v1/admin/roles", mw.RequirePerm(domain.PermAdminRoles, s.handleCreateRole))
	s.handle("PUT /api/v1/admin/roles/{id}", mw.RequirePerm(domain.PermAdminRoles, s.handleUpdateRole))
	s.handle("DELETE /api/v1/admin/roles/{id}", mw.RequirePerm(domain.PermAdminRoles, s.handleDeleteRole))
	s.handle("GET /api/v1/admin/permissions", mw.RequirePerm(domain.PermAdminRoles, s.handleListPermissions))

	s.handle("GET /api/v1/admin/crypto/status", mw.RequirePerm(domain.PermAdminSettings, s.handleCryptoStatus))
	s.handle("POST /api/v1/admin/crypto/rotate", mw.RequirePerm(domain.PermAdminSettings, s.handleCryptoRotate))
	s.handle("GET /api/v1/admin/audit", mw.RequirePerm(domain.PermAdminAudit, s.handleListAudit))

	// Remote scanning agents: management routes take user credentials, the agent protocol
	// (internal/agenthub) takes agent credentials only. Neither opens the other's routes.
	s.handle("GET /api/v1/agents", mw.RequirePerm(domain.PermScansRead, s.handleListAgents))
	s.handle("PUT /api/v1/agents/{id}", mw.RequirePerm(domain.PermAdminSettings, s.handleUpdateAgent))
	s.handle("DELETE /api/v1/agents/{id}", mw.RequirePerm(domain.PermAdminSettings, s.handleDeleteAgent))
	s.handle("GET /api/v1/agents/tokens", mw.RequirePerm(domain.PermAdminSettings, s.handleListAgentTokens))
	s.handle("POST /api/v1/agents/tokens", mw.RequirePerm(domain.PermAdminSettings, s.handleCreateAgentToken))
	s.handle("DELETE /api/v1/agents/tokens/{id}", mw.RequirePerm(domain.PermAdminSettings, s.handleRevokeAgentToken))
	for _, rt := range s.agents.Routes() {
		s.handle(rt.Pattern, rt.Handler)
	}

	s.registerScreenshotRoutes()
	s.registerPolicyRoutes()
	s.registerRemediationRoutes()
	s.registerVerifyRoutes()

	s.handle("/", s.handleSPA)
}

func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusNotFound, "endpoint not found")
		return
	}
	staticDir := strings.TrimSpace(s.cfg.StaticDir)
	if staticDir == "" && s.cfg.StaticFS != nil {
		s.serveSPAFromFS(w, r)
		return
	}
	if staticDir == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "Dzięcioł API",
			"version": AppVersion,
			"docs":    "/api/v1/health",
		})
		return
	}

	cleaned := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if cleaned == "." || cleaned == "" {
		cleaned = "index.html"
	}
	fullPath := filepath.Join(staticDir, cleaned)
	// Prevent directory traversal outside staticDir
	absDir, _ := filepath.Abs(staticDir)
	absFile, _ := filepath.Abs(fullPath)
	if !strings.HasPrefix(absFile, absDir) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if info, err := os.Stat(absFile); err == nil && !info.IsDir() {
		http.ServeFile(w, r, absFile)
		return
	}
	// SPA fallback -> index.html
	indexPath := filepath.Join(absDir, "index.html")
	if _, err := os.Stat(indexPath); err == nil {
		http.ServeFile(w, r, indexPath)
		return
	}
	http.NotFound(w, r)
}

// serveSPAFromFS serves the embedded SPA with an index.html fallback for client-side routes.
// Hashed Vite assets are immutable and cached aggressively; index.html is always revalidated.
func (s *Server) serveSPAFromFS(w http.ResponseWriter, r *http.Request) {
	fsys := s.cfg.StaticFS
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	if info, err := fs.Stat(fsys, name); err == nil && !info.IsDir() {
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeFileFS(w, r, fsys, name)
		return
	}
	if strings.HasPrefix(name, "assets/") {
		http.NotFound(w, r)
		return
	}
	if _, err := fs.Stat(fsys, "index.html"); err == nil {
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, fsys, "index.html")
		return
	}
	if s.cfg.StaticFallback != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(s.cfg.StaticFallback))
		return
	}
	http.NotFound(w, r)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func writeStoreErr(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if errors.Is(err, db.ErrConflict) {
		msg := "already exists"
		if err.Error() != db.ErrConflict.Error() { // a descriptive conflict (e.g. invalid scan state)
			msg = strings.TrimSuffix(err.Error(), ": "+db.ErrConflict.Error())
		}
		writeErr(w, http.StatusConflict, msg)
		return
	}
	writeErr(w, http.StatusInternalServerError, err.Error())
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(dst)
}

func queryInt(r *http.Request, key string, def int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func queryBool(r *http.Request, key string) bool {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key)))
	return v == "true" || v == "1" || v == "yes"
}

func currentUsername(r *http.Request) string {
	if u := auth.UserFromContext(r.Context()); u != nil {
		return u.Username
	}
	return "system"
}
