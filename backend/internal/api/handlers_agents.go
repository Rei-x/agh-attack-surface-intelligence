package api

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Agents exposes the remote scanning agent coordinator (for wiring and tests).
func (s *Server) Agents() *agenthub.Coordinator { return s.agents }

func (s *Server) auditAgent(r *http.Request, action string, details map[string]any) {
	entry := &domain.AuditLog{
		Action:    action,
		Resource:  "agents",
		Status:    "success",
		Details:   details,
		IPAddress: agenthub.RemoteIP(r),
		CreatedAt: time.Now().UTC(),
	}
	if u := auth.UserFromContext(r.Context()); u != nil {
		entry.UserID, entry.Username, entry.RoleSlug = u.ID, u.Username, u.RoleSlug
	}
	_ = s.store.AddAuditLog(r.Context(), entry)
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"agents":            s.agents.ListAgents(r.Context()),
		"offline_after_sec": int(s.agents.Options().OfflineAfter / time.Second),
	})
}

func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     *string `json:"name"`
		Site     *string `json:"site"`
		Disabled *bool   `json:"disabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	a, err := s.agents.UpdateAgent(r.Context(), r.PathValue("id"), req.Name, req.Site, req.Disabled)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	s.auditAgent(r, "PUT /api/v1/agents/{id}", map[string]any{"agent_id": a.ID, "disabled": a.Disabled})
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.agents.DeleteAgent(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.auditAgent(r, "DELETE /api/v1/agents/{id}", map[string]any{"agent_id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAgentTokens(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tokens": s.agents.ListEnrollTokens(r.Context())})
}

// handleCreateAgentToken creates a one-time enrollment token. The token is in this response
// only (stored as SHA-256), together with ready-to-paste install commands.
func (s *Server) handleCreateAgentToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string  `json:"name"`
		Site     string  `json:"site"`
		TTLHours float64 `json:"ttl_hours"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(req.Name) > 80 || len(req.Site) > 80 {
		writeErr(w, http.StatusBadRequest, "name or site too long")
		return
	}
	ttl := time.Duration(req.TTLHours * float64(time.Hour))
	if req.TTLHours < 0 || req.TTLHours > 24*30 {
		writeErr(w, http.StatusBadRequest, "ttl_hours must be 0..720")
		return
	}
	token, rec, err := s.agents.CreateEnrollToken(r.Context(), req.Name, req.Site, ttl, currentUsername(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditAgent(r, "POST /api/v1/agents/tokens", map[string]any{"token_id": rec.ID, "name": rec.Name, "site": rec.Site, "expires_at": rec.ExpiresAt})
	server := publicBaseURL(r)
	q := shellQuote
	nameArg := ""
	if rec.Name != "" {
		nameArg = " --name " + q(rec.Name)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":        token,
		"enroll_token": rec,
		"server_url":   server,
		"install_command": "curl -fsSL https://raw.githubusercontent.com/Rei-x/agh-attack-surface-intelligence/main/install.sh | sudo sh -s -- --agent --server " +
			q(server) + " --token " + q(token) + nameArg,
		"run_command": "dzieciol agent --server " + q(server) + " --token " + q(token) + nameArg,
	})
}

func (s *Server) handleRevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.agents.RevokeEnrollToken(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.auditAgent(r, "DELETE /api/v1/agents/tokens/{id}", map[string]any{"token_id": id})
	w.WriteHeader(http.StatusNoContent)
}

// validateProfileAgent rejects a profile that points at an unknown agent.
func (s *Server) validateProfileAgent(ctx context.Context, p *domain.ScanProfile) string {
	p.AgentID = strings.TrimSpace(p.AgentID)
	if p.AgentID == "" || s.agents.AgentExists(ctx, p.AgentID) {
		return ""
	}
	return "unknown scanning agent"
}

// publicBaseURL is the URL agents should use to reach this server: DZIECIOL_PUBLIC_URL, else the
// scheme/host the admin's browser used (honouring a TLS-terminating reverse proxy).
func publicBaseURL(r *http.Request) string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("DZIECIOL_PUBLIC_URL")), "/"); v != "" {
		return v
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); p == "https" || p == "http" {
		scheme = p
	}
	host := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0])
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
