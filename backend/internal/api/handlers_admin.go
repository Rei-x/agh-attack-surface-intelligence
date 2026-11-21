package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// --- Users ---

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		RoleID   string `json:"role_id"`
		RoleSlug string `json:"role_slug"`
		Active   *bool  `json:"active"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Password) < minPasswordLen {
		writeErr(w, http.StatusBadRequest, "wymagana nazwa użytkownika i hasło (min. 8 znaków) / username and password (min 8 chars) are required")
		return
	}
	if len(req.Username) > 64 || len(req.Password) > 1024 {
		writeErr(w, http.StatusBadRequest, "nazwa użytkownika lub hasło za długie / username or password too long")
		return
	}

	roleID := strings.TrimSpace(req.RoleID)
	if roleID == "" && strings.TrimSpace(req.RoleSlug) != "" {
		role, err := s.store.GetRoleBySlug(ctx, strings.TrimSpace(req.RoleSlug))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unknown role_slug")
			return
		}
		roleID = role.ID
	}
	if roleID == "" {
		writeErr(w, http.StatusBadRequest, "role_id or role_slug is required")
		return
	}
	if _, err := s.store.GetRole(ctx, roleID); err != nil {
		writeErr(w, http.StatusBadRequest, "nieznana rola / unknown role_id")
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed hashing password")
		return
	}
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	user := &domain.User{
		Username:     req.Username,
		Email:        strings.TrimSpace(req.Email),
		PasswordHash: hash,
		RoleID:       roleID,
		Active:       active,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.store.CreateUser(ctx, user); err != nil {
		writeStoreErr(w, err)
		return
	}
	created, err := s.store.GetUser(ctx, user.ID)
	if err != nil {
		writeJSON(w, http.StatusCreated, user)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	existing, err := s.store.GetUser(ctx, id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		RoleID   string `json:"role_id"`
		RoleSlug string `json:"role_slug"`
		Active   *bool  `json:"active"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	roleID := existing.RoleID
	if strings.TrimSpace(req.RoleID) != "" {
		roleID = strings.TrimSpace(req.RoleID)
	} else if strings.TrimSpace(req.RoleSlug) != "" {
		role, err := s.store.GetRoleBySlug(ctx, strings.TrimSpace(req.RoleSlug))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unknown role_slug")
			return
		}
		roleID = role.ID
	}

	if roleID != existing.RoleID {
		if _, err := s.store.GetRole(ctx, roleID); err != nil {
			writeErr(w, http.StatusBadRequest, "nieznana rola / unknown role_id")
			return
		}
	}
	upd := &domain.User{
		ID:     id,
		Email:  strings.TrimSpace(req.Email),
		RoleID: roleID,
		Active: existing.Active,
	}
	if req.Active != nil {
		upd.Active = *req.Active
	}
	if err := s.guardLastAdmin(ctx, func(u *domain.User) bool {
		if u.ID == id {
			u.RoleID, u.Active = upd.RoleID, upd.Active
		}
		return true
	}, nil); err != nil {
		writeGuardErr(w, err)
		return
	}
	if req.Password != "" && (len(req.Password) < minPasswordLen || len(req.Password) > 1024) {
		writeErr(w, http.StatusBadRequest, "hasło musi mieć 8-1024 znaków / password must be 8-1024 characters")
		return
	}
	if req.Password != "" {
		hash, err := crypto.HashPassword(req.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed hashing password")
			return
		}
		upd.PasswordHash = hash
	}
	if err := s.store.UpdateUser(ctx, upd); err != nil {
		writeStoreErr(w, err)
		return
	}
	updated, err := s.store.GetUser(ctx, id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.guardLastAdmin(r.Context(), func(u *domain.User) bool { return u.ID != id }, nil); err != nil {
		writeGuardErr(w, err)
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Dynamic RBAC Roles & Permissions ---

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Slug        string   `json:"slug"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	req.Name = strings.TrimSpace(req.Name)
	if req.Slug == "" || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "slug and name are required")
		return
	}
	role := &domain.Role{
		Slug:        req.Slug,
		Name:        req.Name,
		Description: req.Description,
		IsSystem:    false,
		Permissions: req.Permissions,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateRole(r.Context(), role); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Slug        string   `json:"slug"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	role := &domain.Role{
		ID:          r.PathValue("id"),
		Slug:        req.Slug,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}
	if err := s.guardLastAdmin(r.Context(), nil, func(ro *domain.Role) {
		if ro.ID == role.ID { // the store replaces the permission set
			ro.Permissions = req.Permissions
		}
	}); err != nil {
		writeGuardErr(w, err)
		return
	}
	if err := s.store.UpdateRole(r.Context(), role); err != nil {
		writeStoreErr(w, err)
		return
	}
	updated, err := s.store.GetRole(r.Context(), role.ID)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRole(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListPermissions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"permissions": domain.AllPermissions,
	})
}

// --- Encryption At Rest Proof & Key Rotation ---

func (s *Server) handleCryptoStatus(w http.ResponseWriter, r *http.Request) {
	st := s.vault.Status()
	proof, _ := s.store.GetCryptoProofSample(r.Context())

	var sampleObj map[string]any
	var samples []map[string]any
	if proof != nil {
		sampleObj = map[string]any{
			"table":            proof.Table,
			"record_id":        proof.RecordID,
			"column":           proof.Column,
			"aad":              proof.AAD,
			"raw_ciphertext":   proof.RawCiphertext,
			"ciphertext":       proof.RawCiphertext,
			"decrypted_value":  proof.DecryptedSample,
			"plaintext":        proof.DecryptedSample,
			"blind_index_col":  proof.BlindIndexCol,
			"blind_index":      proof.BlindIndexValue,
		}
		samples = []map[string]any{sampleObj}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":            st.Active,
		"encryption_active": st.Active,
		"algorithm":         st.Algorithm,
		"blind_index":       st.BlindIndexAlgo,
		"format":            st.Format,
		"key_version":       st.ActiveKeyVersion,
		"active_kid":        st.ActiveKeyVersion,
		"key_count":         st.KeyCount,
		"dev_key_generated": st.DevKeyGenerated,
		"encrypted_tables": []string{
			"hosts (ip_enc, hostname_enc, domains_enc, os_guess_enc, notes_enc)",
			"services (banner_enc, http_enc, notes_enc)",
			"service_observations (banner_enc, http_enc)",
			"asset_overrides (value_enc)",
			"scan_runs (notes_enc, raw_nmap_xml_enc)",
			"scan_snapshots (payload_enc)",
			"change_events (host_ip_enc, before_enc, after_enc)",
			"defectdojo_config (api_token_enc)",
			"users (email_enc)",
		},
		"sample":  sampleObj,
		"samples": samples,
	})
}

func (s *Server) handleCryptoRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	newKID, wrapped, err := s.vault.RotateDEK()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SaveCryptoKey(ctx, newKID, wrapped, true); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	reencrypted, err := s.store.ReEncryptAll(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":               "rotated",
		"active_key_version":   newKID,
		"key_version":          newKID,
		"reencrypted_fields":   reencrypted,
		"rotated_at":           time.Now().UTC(),
	})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	logs, err := s.store.ListAuditLogs(r.Context(), queryInt(r, "limit", 200))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	actionFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action")))
	if statusFilter != "" || actionFilter != "" {
		filtered := make([]domain.AuditLog, 0, len(logs))
		for _, l := range logs {
			if statusFilter != "" && !strings.EqualFold(l.Status, statusFilter) {
				continue
			}
			if actionFilter != "" && !strings.Contains(strings.ToLower(l.Action), actionFilter) {
				continue
			}
			filtered = append(filtered, l)
		}
		logs = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "audit": logs})
}
