package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// bootstrapResult tells the caller what to print once (never logged to files).
type bootstrapResult struct {
	AdminCreated    bool
	AdminPassword   string // set only when generated now
	DemoDeactivated []string
}

// secureAccounts runs after SeedDefaults when demo accounts are disabled:
//   - demo accounts that still have their publicly known password are deactivated, so turning
//     demo mode off actually closes them;
//   - if no active administrator remains (fresh install without demo accounts), an "admin"
//     account is created (or re-enabled) with ASI_ADMIN_PASSWORD or a random password that is
//     printed once to the terminal. Without this, ASI_SEED_DEMO=false meant nobody could log in.
func secureAccounts(ctx context.Context, store db.Store, seedDemo bool) (bootstrapResult, error) {
	var res bootstrapResult
	if seedDemo {
		return res, nil
	}
	users, err := store.ListUsers(ctx)
	if err != nil {
		return res, err
	}
	demoPw := map[string]string{}
	for _, d := range auth.DemoAccounts {
		demoPw[strings.ToLower(d.Username)] = d.Password
	}
	hasAdmin := false
	for i := range users {
		u := users[i]
		if pw, ok := demoPw[strings.ToLower(u.Username)]; ok && u.Active && crypto.VerifyPassword(pw, u.PasswordHash) {
			u.Active = false
			if err := store.UpdateUser(ctx, &u); err != nil {
				return res, fmt.Errorf("deactivate demo account %s: %w", u.Username, err)
			}
			res.DemoDeactivated = append(res.DemoDeactivated, u.Username)
			continue
		}
		if u.Active && u.RoleSlug == "admin" {
			hasAdmin = true
		}
	}
	if hasAdmin {
		return res, nil
	}

	password := strings.TrimSpace(os.Getenv("ASI_ADMIN_PASSWORD"))
	if password == "" {
		password, err = randomPassword(20)
		if err != nil {
			return res, err
		}
		res.AdminPassword = password
	} else if len(password) < 10 {
		return res, fmt.Errorf("ASI_ADMIN_PASSWORD must be at least 10 characters")
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return res, err
	}
	role, err := store.GetRoleBySlug(ctx, "admin")
	if err != nil {
		return res, fmt.Errorf("admin role missing: %w", err)
	}
	if existing, err := store.GetUserByUsername(ctx, "admin"); err == nil && existing != nil {
		existing.PasswordHash, existing.RoleID, existing.Active = hash, role.ID, true
		if err := store.UpdateUser(ctx, existing); err != nil {
			return res, err
		}
	} else {
		if err := store.CreateUser(ctx, &domain.User{
			ID: db.NewID(), Username: "admin", Email: "admin@localhost", PasswordHash: hash,
			RoleID: role.ID, RoleSlug: role.Slug, RoleName: role.Name, Active: true, CreatedAt: time.Now().UTC(),
		}); err != nil {
			return res, err
		}
	}
	res.AdminCreated = true
	log.Printf("[WARN] no active administrator existed: account 'admin' was created/re-enabled (password shown once on the terminal or taken from ASI_ADMIN_PASSWORD)")
	return res, nil
}

func randomPassword(n int) (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	for i := range b {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b), nil
}
