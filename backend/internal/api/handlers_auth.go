package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	dbStatus, status, code := s.store.BackendName(), "ok", http.StatusOK
	if err := s.store.Ping(r.Context()); err != nil {
		// 503 so container health checks and load balancers notice (DB down, disk full).
		dbStatus, status, code = "error: "+err.Error(), "degraded", http.StatusServiceUnavailable
	}
	st := s.vault.Status()
	writeJSON(w, code, map[string]any{
		"status":            status,
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

// passwordCheckSlots bounds concurrent Argon2id verifications (64 MiB each).
var passwordCheckSlots = make(chan struct{}, 4)

// dummyPasswordHash is verified for unknown usernames to equalize login timing.
var dummyPasswordHash = func() string {
	h, _ := crypto.HashPassword("dzieciol-timing-equalizer")
	return h
}()

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	if len(req.Username) > 256 || len(req.Password) > 1024 {
		writeErr(w, http.StatusBadRequest, "nazwa użytkownika lub hasło jest za długie / username or password too long")
		return
	}
	keys := loginKeys(r, req.Username)
	if wait := s.logins.blocked(keys); wait > 0 {
		writeTooManyLogins(w, wait)
		return
	}
	// Argon2id costs 64 MiB per verification: bound concurrent checks so a login flood
	// cannot exhaust memory.
	select {
	case passwordCheckSlots <- struct{}{}:
		defer func() { <-passwordCheckSlots }()
	case <-r.Context().Done():
		return
	}
	user, err := s.store.GetUserByUsername(r.Context(), strings.TrimSpace(req.Username))
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		writeErr(w, http.StatusServiceUnavailable, "baza danych jest niedostępna - spróbuj ponownie za chwilę / database unavailable")
		return
	}
	ok := false
	if err == nil && user != nil {
		ok = crypto.VerifyPassword(req.Password, user.PasswordHash) && user.Active
	} else {
		// Same work for unknown users, so response timing does not reveal valid usernames.
		crypto.VerifyPassword(req.Password, dummyPasswordHash)
	}
	if !ok {
		s.logins.fail(keys)
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

	s.logins.succeed(keys)
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
