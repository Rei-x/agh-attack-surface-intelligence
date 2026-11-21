package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	dbStatus := s.store.BackendName()
	if err := s.store.Ping(r.Context()); err != nil {
		dbStatus = "error: " + err.Error()
	}
	st := s.vault.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ok",
		"version":           AppVersion,
		"db":                dbStatus,
		"nmap_available":    s.runner.NmapAvailable(),
		"encryption_active": st.Active,
		"key_version":       st.ActiveKeyVersion,
	})
}

func (s *Server) handleDemoAccounts(w http.ResponseWriter, _ *http.Request) {
	if !s.cfg.SeedDemo {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":  false,
			"accounts": []any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  true,
		"accounts": auth.DemoAccounts,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	user, err := s.store.GetUserByUsername(r.Context(), strings.TrimSpace(req.Username))
	if err != nil || !user.Active || !crypto.VerifyPassword(req.Password, user.PasswordHash) {
		_ = s.store.AddAuditLog(r.Context(), &domain.AuditLog{
			Username:  req.Username,
			Action:    "POST /api/v1/auth/login",
			Resource:  "auth",
			Status:    "denied",
			Details:   map[string]any{"reason": "invalid credentials"},
			CreatedAt: time.Now().UTC(),
		})
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := auth.SignToken(s.cfg.JWTSecret, user, s.cfg.TokenTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to sign jwt")
		return
	}
	_ = s.store.AddAuditLog(r.Context(), &domain.AuditLog{
		UserID:    user.ID,
		Username:  user.Username,
		RoleSlug:  user.RoleSlug,
		Action:    "POST /api/v1/auth/login",
		Resource:  "auth",
		Status:    "success",
		CreatedAt: time.Now().UTC(),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user": map[string]any{
			"id":          user.ID,
			"username":    user.Username,
			"email":       user.Email,
			"role_id":     user.RoleID,
			"role":        user.RoleSlug,
			"role_slug":   user.RoleSlug,
			"role_name":   user.RoleName,
			"permissions": user.Permissions,
			"active":      user.Active,
		},
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"role_id":     user.RoleID,
		"role":        user.RoleSlug,
		"role_slug":   user.RoleSlug,
		"role_name":   user.RoleName,
		"permissions": user.Permissions,
		"active":      user.Active,
	})
}
