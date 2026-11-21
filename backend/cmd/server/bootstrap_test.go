package main

import (
	"context"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
)

func TestFreshInstallWithoutDemoGetsAnAdmin(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DZIECIOL_ADMIN_PASSWORD", "")
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	if err := db.SeedDefaults(ctx, store, false); err != nil {
		t.Fatal(err)
	}
	res, err := secureAccounts(ctx, store, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AdminCreated || len(res.AdminPassword) < 16 {
		t.Fatalf("expected a generated admin password, got %+v", res)
	}
	u, err := store.GetUserByUsername(ctx, "admin")
	if err != nil || !u.Active || !crypto.VerifyPassword(res.AdminPassword, u.PasswordHash) {
		t.Fatalf("admin not usable: %v %+v", err, u)
	}
	// Second start: admin exists, nothing regenerated.
	res2, err := secureAccounts(ctx, store, false)
	if err != nil || res2.AdminCreated {
		t.Fatalf("second start must not reset the admin: %+v %v", res2, err)
	}
}

func TestDisablingDemoModeClosesDemoAccounts(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DZIECIOL_ADMIN_PASSWORD", "a-strong-admin-pass")
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	if err := db.SeedDefaults(ctx, store, true); err != nil { // was a demo install
		t.Fatal(err)
	}
	res, err := secureAccounts(ctx, store, false) // restarted with DZIECIOL_SEED_DEMO=false
	if err != nil {
		t.Fatal(err)
	}
	if len(res.DemoDeactivated) != 4 {
		t.Fatalf("all 4 demo accounts should be closed, got %v", res.DemoDeactivated)
	}
	for _, name := range []string{"operator", "analyst", "viewer"} {
		if u, _ := store.GetUserByUsername(ctx, name); u == nil || u.Active {
			t.Fatalf("%s still active", name)
		}
	}
	admin, _ := store.GetUserByUsername(ctx, "admin")
	if !admin.Active || crypto.VerifyPassword("Admin123!", admin.PasswordHash) || !crypto.VerifyPassword("a-strong-admin-pass", admin.PasswordHash) {
		t.Fatal("admin must be re-enabled with DZIECIOL_ADMIN_PASSWORD, not the demo password")
	}
}
