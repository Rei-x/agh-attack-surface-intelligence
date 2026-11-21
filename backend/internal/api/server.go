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

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scheduler"
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
}

// Server serves the complete AegisASI v1 REST API, SSE stream, and embedded/static SPA.
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
}

// NewServer constructs a fully wired AegisASI HTTP Server.
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
	}
	s.registerRoutes()
	return s
}

// Handler returns the root HTTP handler wrapped with CORS middleware.
func (s *Server) Handler() http.Handler {
	return s.corsMiddleware(s.mux)
}

func (s *Server) registerRoutes() {
	mw := s.authMW

	// Public Health & Auth
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/auth/demo-accounts", s.handleDemoAccounts)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("GET /api/v1/auth/me", mw.Authenticate(s.handleMe))

	// Dashboard, Graph, Clusters, SSE
	s.mux.HandleFunc("GET /api/v1/dashboard/summary", mw.RequirePerm(domain.PermDashboardRead, s.handleDashboardSummary))
	s.mux.HandleFunc("GET /api/v1/graph", mw.RequirePerm(domain.PermAssetsRead, s.handleGraph))
	s.mux.HandleFunc("GET /api/v1/clusters", mw.RequirePerm(domain.PermAssetsRead, s.handleClusters))
	s.mux.HandleFunc("GET /api/v1/events/stream", mw.Authenticate(s.hub.ServeHTTP))

	// Targets, Exclusions, Profiles
	s.mux.HandleFunc("GET /api/v1/targets", mw.RequirePerm(domain.PermScansRead, s.handleListTargets))
	s.mux.HandleFunc("POST /api/v1/targets", mw.RequirePerm(domain.PermScansWrite, s.handleCreateTarget))
	s.mux.HandleFunc("DELETE /api/v1/targets/{id}", mw.RequirePerm(domain.PermScansDelete, s.handleDeleteTarget))
	s.mux.HandleFunc("POST /api/v1/targets/estimate", mw.RequirePerm(domain.PermScansRead, s.handleEstimateTargets))

	s.mux.HandleFunc("GET /api/v1/exclusions", mw.RequirePerm(domain.PermScansRead, s.handleListExclusions))
	s.mux.HandleFunc("POST /api/v1/exclusions", mw.RequirePerm(domain.PermScansWrite, s.handleCreateExclusion))
	s.mux.HandleFunc("DELETE /api/v1/exclusions/{id}", mw.RequirePerm(domain.PermScansDelete, s.handleDeleteExclusion))

	s.mux.HandleFunc("GET /api/v1/profiles", mw.RequirePerm(domain.PermScansRead, s.handleListProfiles))
	s.mux.HandleFunc("POST /api/v1/profiles", mw.RequirePerm(domain.PermScansWrite, s.handleCreateProfile))
	s.mux.HandleFunc("GET /api/v1/profiles/{id}", mw.RequirePerm(domain.PermScansRead, s.handleGetProfile))
	s.mux.HandleFunc("PUT /api/v1/profiles/{id}", mw.RequirePerm(domain.PermScansWrite, s.handleUpdateProfile))
	s.mux.HandleFunc("POST /api/v1/profiles/{id}/run", mw.RequirePerm(domain.PermScansRun, s.handleRunProfileNow))
	s.mux.HandleFunc("DELETE /api/v1/profiles/{id}", mw.RequirePerm(domain.PermScansDelete, s.handleDeleteProfile))

	// Scan Runs & Diff
	s.mux.HandleFunc("GET /api/v1/scans", mw.RequirePerm(domain.PermScansRead, s.handleListScans))
	s.mux.HandleFunc("POST /api/v1/scans", mw.RequirePerm(domain.PermScansRun, s.handleStartScan))
	s.mux.HandleFunc("GET /api/v1/scans/diff", mw.RequirePerm(domain.PermScansRead, s.handleScanDiff))
	s.mux.HandleFunc("GET /api/v1/scans/{id}", mw.RequirePerm(domain.PermScansRead, s.handleGetScan))
	s.mux.HandleFunc("GET /api/v1/scans/{id}/nmap.xml", mw.RequirePerm(domain.PermScansRead, s.handleScanNmapXML))
	s.mux.HandleFunc("PUT /api/v1/scans/{id}", mw.RequirePerm(domain.PermScansWrite, s.handleUpdateScanMeta))
	s.mux.HandleFunc("POST /api/v1/scans/{id}/pause", mw.RequirePerm(domain.PermScansRun, s.handlePauseScan))
	s.mux.HandleFunc("POST /api/v1/scans/{id}/resume", mw.RequirePerm(domain.PermScansRun, s.handleResumeScan))
	s.mux.HandleFunc("POST /api/v1/scans/{id}/stop", mw.RequirePerm(domain.PermScansRun, s.handleStopScan))
	s.mux.HandleFunc("DELETE /api/v1/scans/{id}", mw.RequirePerm(domain.PermScansDelete, s.handleDeleteScan))

	// Hosts, Services & Preserved Overrides
	s.mux.HandleFunc("GET /api/v1/hosts", mw.RequirePerm(domain.PermAssetsRead, s.handleListHosts))
	s.mux.HandleFunc("GET /api/v1/hosts/{id}", mw.RequirePerm(domain.PermAssetsRead, s.handleGetHost))
	s.mux.HandleFunc("PATCH /api/v1/hosts/{id}/overrides", mw.RequirePerm(domain.PermAssetsWrite, s.handlePatchHostOverrides))
	s.mux.HandleFunc("DELETE /api/v1/hosts/{id}", mw.RequirePerm(domain.PermAssetsDelete, s.handleDeleteHost))

	s.mux.HandleFunc("GET /api/v1/services", mw.RequirePerm(domain.PermAssetsRead, s.handleListServices))
	s.mux.HandleFunc("PATCH /api/v1/services/{id}/overrides", mw.RequirePerm(domain.PermAssetsWrite, s.handlePatchServiceOverrides))
	s.mux.HandleFunc("GET /api/v1/services/{id}/observations", mw.RequirePerm(domain.PermAssetsRead, s.handleServiceObservations))

	// Changes
	s.mux.HandleFunc("GET /api/v1/changes", mw.RequirePerm(domain.PermAssetsRead, s.handleListChanges))
	s.mux.HandleFunc("POST /api/v1/changes/{id}/acknowledge", mw.RequirePerm(domain.PermAssetsWrite, s.handleAcknowledgeChange))

	// Unified Manual Entry, Import & Export
	s.mux.HandleFunc("POST /api/v1/ingest/manual", mw.RequirePerm(domain.PermAssetsWrite, s.handleIngestManual))
	s.mux.HandleFunc("POST /api/v1/ingest/import", mw.RequirePerm(domain.PermImportWrite, s.handleIngestImport))
	s.mux.HandleFunc("GET /api/v1/export", mw.RequirePerm(domain.PermExportRead, s.handleExport))

	// Signatures Studio
	s.mux.HandleFunc("GET /api/v1/signatures", mw.RequirePerm(domain.PermSignaturesRead, s.handleListSignatures))
	s.mux.HandleFunc("POST /api/v1/signatures", mw.RequirePerm(domain.PermSignaturesWrite, s.handleCreateSignature))
	s.mux.HandleFunc("POST /api/v1/signatures/validate", mw.RequirePerm(domain.PermSignaturesRead, s.handleValidateSignature))
	s.mux.HandleFunc("POST /api/v1/signatures/test", mw.RequirePerm(domain.PermSignaturesRead, s.handleTestSignature))
	s.mux.HandleFunc("POST /api/v1/signatures/import", mw.RequirePerm(domain.PermSignaturesWrite, s.handleImportSignatures))
	s.mux.HandleFunc("GET /api/v1/signatures/export", mw.RequirePerm(domain.PermSignaturesRead, s.handleExportSignatures))
	s.mux.HandleFunc("PUT /api/v1/signatures/{id}", mw.RequirePerm(domain.PermSignaturesWrite, s.handleUpdateSignature))
	s.mux.HandleFunc("DELETE /api/v1/signatures/{id}", mw.RequirePerm(domain.PermSignaturesDelete, s.handleDeleteSignature))

	// DefectDojo v2 Integration
	s.mux.HandleFunc("GET /api/v1/integrations/defectdojo", mw.RequirePerm(domain.PermDefectDojoPush, s.handleGetDefectDojoConfig))
	s.mux.HandleFunc("PUT /api/v1/integrations/defectdojo", mw.RequirePerm(domain.PermAdminSettings, s.handleSaveDefectDojoConfig))
	s.mux.HandleFunc("POST /api/v1/integrations/defectdojo/test", mw.RequirePerm(domain.PermDefectDojoPush, s.handleTestDefectDojo))
	s.mux.HandleFunc("POST /api/v1/integrations/defectdojo/push-findings", mw.RequirePerm(domain.PermDefectDojoPush, s.handlePushDefectDojoFindings))
	s.mux.HandleFunc("POST /api/v1/integrations/defectdojo/push-nmap", mw.RequirePerm(domain.PermDefectDojoPush, s.handlePushDefectDojoNmap))
	s.mux.HandleFunc("GET /api/v1/integrations/defectdojo/history", mw.RequirePerm(domain.PermDefectDojoPush, s.handleDefectDojoHistory))

	// Admin: Users, Dynamic Roles, Permissions, Crypto Proof & Rotation, Audit
	s.mux.HandleFunc("GET /api/v1/admin/users", mw.RequirePerm(domain.PermAdminUsers, s.handleListUsers))
	s.mux.HandleFunc("POST /api/v1/admin/users", mw.RequirePerm(domain.PermAdminUsers, s.handleCreateUser))
	s.mux.HandleFunc("PUT /api/v1/admin/users/{id}", mw.RequirePerm(domain.PermAdminUsers, s.handleUpdateUser))
	s.mux.HandleFunc("DELETE /api/v1/admin/users/{id}", mw.RequirePerm(domain.PermAdminUsers, s.handleDeleteUser))

	s.mux.HandleFunc("GET /api/v1/admin/roles", mw.RequirePerm(domain.PermAdminRoles, s.handleListRoles))
	s.mux.HandleFunc("POST /api/v1/admin/roles", mw.RequirePerm(domain.PermAdminRoles, s.handleCreateRole))
	s.mux.HandleFunc("PUT /api/v1/admin/roles/{id}", mw.RequirePerm(domain.PermAdminRoles, s.handleUpdateRole))
	s.mux.HandleFunc("DELETE /api/v1/admin/roles/{id}", mw.RequirePerm(domain.PermAdminRoles, s.handleDeleteRole))
	s.mux.HandleFunc("GET /api/v1/admin/permissions", mw.RequirePerm(domain.PermAdminRoles, s.handleListPermissions))

	s.mux.HandleFunc("GET /api/v1/admin/crypto/status", mw.RequirePerm(domain.PermAdminSettings, s.handleCryptoStatus))
	s.mux.HandleFunc("POST /api/v1/admin/crypto/rotate", mw.RequirePerm(domain.PermAdminSettings, s.handleCryptoRotate))
	s.mux.HandleFunc("GET /api/v1/admin/audit", mw.RequirePerm(domain.PermAdminAudit, s.handleListAudit))

	// Static SPA fallback
	s.mux.HandleFunc("/", s.handleSPA)
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
			"service": "AegisASI API",
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

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := s.cfg.AllowedOrigin
		if origin == "" {
			origin = r.Header.Get("Origin")
			if origin == "" {
				origin = "*"
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
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
		writeErr(w, http.StatusConflict, "already exists")
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
