package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

type stubUserLoader struct {
	users map[string]*domain.User
}

func (s *stubUserLoader) GetUser(_ context.Context, id string) (*domain.User, error) {
	return s.users[id], nil
}

type stubAuditLogger struct {
	entries []*domain.AuditLog
}

func (a *stubAuditLogger) AddAuditLog(_ context.Context, entry *domain.AuditLog) error {
	a.entries = append(a.entries, entry)
	return nil
}

func TestJWTSignVerifyAndTamper(t *testing.T) {
	secret := []byte("super-secret-jwt-key-32-bytes-long")
	user := &domain.User{
		ID:       "u-1",
		Username: "admin",
		RoleID:   "r-admin",
		RoleSlug: "admin",
		RoleName: "Administracja",
	}

	tok, err := SignToken(secret, user, time.Hour)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	claims, err := VerifyToken(secret, tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Sub != "u-1" || claims.RoleSlug != "admin" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// Wrong secret rejected
	if _, err := VerifyToken([]byte("wrong-secret"), tok); err == nil {
		t.Fatalf("expected invalid signature with wrong secret")
	}

	// Expired token rejected
	expiredTok, err := SignToken(secret, user, -time.Minute)
	if err != nil {
		t.Fatalf("SignToken expired: %v", err)
	}
	if _, err := VerifyToken(secret, expiredTok); err == nil {
		t.Fatalf("expected expired jwt error")
	}
}

func TestRBACMiddlewareAllFourRolesAndCustomRole(t *testing.T) {
	secret := []byte("rbac-test-secret-key-32-bytes!!")
	users := &stubUserLoader{users: map[string]*domain.User{}}
	audit := &stubAuditLogger{}

	for _, r := range DefaultRoles {
		users.users["u-"+r.Slug] = &domain.User{
			ID:          "u-" + r.Slug,
			Username:    r.Slug,
			RoleID:      "role-" + r.Slug,
			RoleSlug:    r.Slug,
			RoleName:    r.Name,
			Permissions: r.Permissions,
			Active:      true,
		}
	}
	// Custom role with only defectdojo:push + dashboard:read
	users.users["u-custom"] = &domain.User{
		ID:          "u-custom",
		Username:    "soc_dojo",
		RoleID:      "role-custom",
		RoleSlug:    "soc_dojo",
		RoleName:    "SOC DefectDojo",
		Permissions: []string{domain.PermDashboardRead, domain.PermDefectDojoPush},
		Active:      true,
	}

	mw := NewMiddleware(secret, users, audit)
	okHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	cases := []struct {
		userID   string
		perm     string
		method   string
		wantCode int
	}{
		{"u-admin", domain.PermAdminRoles, http.MethodPost, http.StatusOK},
		{"u-admin", domain.PermScansRun, http.MethodPost, http.StatusOK},
		{"u-operator", domain.PermScansRun, http.MethodPost, http.StatusOK},
		{"u-operator", domain.PermAssetsDelete, http.MethodDelete, http.StatusOK},
		{"u-operator", domain.PermDefectDojoPush, http.MethodPost, http.StatusOK},
		{"u-operator", domain.PermAdminRoles, http.MethodPost, http.StatusForbidden},
		{"u-analyst", domain.PermAssetsWrite, http.MethodPatch, http.StatusOK},
		{"u-analyst", domain.PermAssetsDelete, http.MethodDelete, http.StatusForbidden},
		{"u-analyst", domain.PermScansRun, http.MethodPost, http.StatusForbidden},
		{"u-analyst", domain.PermImportWrite, http.MethodPost, http.StatusForbidden},
		{"u-viewer", domain.PermAssetsRead, http.MethodGet, http.StatusOK},
		{"u-viewer", domain.PermAssetsWrite, http.MethodPatch, http.StatusForbidden},
		{"u-viewer", domain.PermScansRun, http.MethodPost, http.StatusForbidden},
		{"u-viewer", domain.PermAdminAudit, http.MethodGet, http.StatusForbidden},
		{"u-custom", domain.PermDefectDojoPush, http.MethodPost, http.StatusOK},
		{"u-custom", domain.PermAssetsWrite, http.MethodPatch, http.StatusForbidden},
	}

	deniedCount := 0
	for _, tc := range cases {
		tok, err := SignToken(secret, users.users[tc.userID], time.Hour)
		if err != nil {
			t.Fatalf("SignToken(%s): %v", tc.userID, err)
		}
		req := httptest.NewRequest(tc.method, "/api/v1/test", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mw.RequirePerm(tc.perm, okHandler)(rec, req)
		if rec.Code != tc.wantCode {
			t.Errorf("user=%s perm=%s: got %d want %d", tc.userID, tc.perm, rec.Code, tc.wantCode)
		}
		if tc.wantCode == http.StatusForbidden {
			deniedCount++
		}
	}

	loggedDenied := 0
	for _, e := range audit.entries {
		if e.Status == "denied" {
			loggedDenied++
		}
	}
	if loggedDenied != deniedCount {
		t.Fatalf("expected %d denied audit logs, got %d", deniedCount, loggedDenied)
	}
}
