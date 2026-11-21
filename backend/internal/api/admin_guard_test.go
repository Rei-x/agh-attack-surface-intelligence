package api

import (
	"context"
	"net/http"
	"testing"
)

func TestCannotRemoveLastAdministrator(t *testing.T) {
	_, store, h := setupTestServer(t)
	tok := loginTest(t, h, "admin", "Admin123!")
	ctx := context.Background()
	admin, _ := store.GetUserByUsername(ctx, "admin")
	adminRole, _ := store.GetRoleBySlug(ctx, "admin")
	viewerRole, _ := store.GetRoleBySlug(ctx, "viewer")

	for name, req := range map[string]struct {
		method, path string
		body         any
	}{
		"deactivate self":  {http.MethodPut, "/api/v1/admin/users/" + admin.ID, map[string]any{"active": false}},
		"demote self":      {http.MethodPut, "/api/v1/admin/users/" + admin.ID, map[string]any{"role_id": viewerRole.ID}},
		"delete self":      {http.MethodDelete, "/api/v1/admin/users/" + admin.ID, nil},
		"strip admin role": {http.MethodPut, "/api/v1/admin/roles/" + adminRole.ID, map[string]any{"name": "Administracja", "permissions": []string{"dashboard.read"}}},
	} {
		rec := doJSON(h, req.method, req.path, tok, req.body)
		if rec.Code != http.StatusConflict {
			t.Errorf("%s: got %d %s, want 409", name, rec.Code, rec.Body.String())
		}
	}
	if u, _ := store.GetUserByUsername(ctx, "admin"); !u.Active || u.RoleID != adminRole.ID {
		t.Fatalf("admin was modified: %+v", u)
	}

	// With a second admin, demoting the first is fine.
	rec := doJSON(h, http.MethodPost, "/api/v1/admin/users", tok, map[string]any{"username": "admin2", "password": "Second-admin-1", "role_slug": "admin"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create admin2: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(h, http.MethodPut, "/api/v1/admin/users/"+admin.ID, tok, map[string]any{"role_id": viewerRole.ID}); rec.Code != http.StatusOK {
		t.Fatalf("demote with another admin present: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUserPasswordAndRoleValidation(t *testing.T) {
	_, store, h := setupTestServer(t)
	tok := loginTest(t, h, "admin", "Admin123!")
	for _, body := range []map[string]any{
		{"username": "u1", "password": "short", "role_slug": "viewer"},
		{"username": "u2", "password": "long-enough-1", "role_id": "no-such-role"},
		{"username": "u3", "password": "long-enough-1", "role_slug": "no-such-role"},
	} {
		if rec := doJSON(h, http.MethodPost, "/api/v1/admin/users", tok, body); rec.Code != http.StatusBadRequest {
			t.Errorf("create %v: got %d %s", body, rec.Code, rec.Body.String())
		}
	}
	viewer, _ := store.GetUserByUsername(context.Background(), "viewer")
	if rec := doJSON(h, http.MethodPut, "/api/v1/admin/users/"+viewer.ID, tok, map[string]any{"password": "a"}); rec.Code != http.StatusBadRequest {
		t.Errorf("weak password on update: got %d", rec.Code)
	}
	if rec := doJSON(h, http.MethodPut, "/api/v1/admin/users/"+viewer.ID, tok, map[string]any{"role_id": "nope"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown role on update: got %d", rec.Code)
	}
}
