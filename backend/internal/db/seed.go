package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// SeedDefaults ensures the 4 mandatory RBAC roles exist, optionally seeds the 4 demo
// accounts (when seedDemo is true), and seeds starter scan profiles and exclusions.
func SeedDefaults(ctx context.Context, store Store, seedDemo bool) error {
	now := time.Now().UTC()

	// 1. Seed 4 predefined RBAC roles
	roleIDs := make(map[string]string, len(auth.DefaultRoles))
	for _, spec := range auth.DefaultRoles {
		existing, err := store.GetRoleBySlug(ctx, spec.Slug)
		if err == nil && existing != nil {
			roleIDs[spec.Slug] = existing.ID
			continue
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("check role %s: %w", spec.Slug, err)
		}
		role := &domain.Role{
			ID:          NewID(),
			Slug:        spec.Slug,
			Name:        spec.Name,
			Description: spec.Description,
			IsSystem:    true,
			Permissions: append([]string(nil), spec.Permissions...),
			CreatedAt:   now,
		}
		if err := store.CreateRole(ctx, role); err != nil {
			return fmt.Errorf("seed role %s: %w", spec.Slug, err)
		}
		roleIDs[spec.Slug] = role.ID
	}

	// 2. Seed 4 demo accounts when DZIECIOL_SEED_DEMO=true
	if seedDemo {
		for _, demo := range auth.DemoAccounts {
			existing, err := store.GetUserByUsername(ctx, demo.Username)
			if err == nil && existing != nil {
				continue
			}
			if err != nil && !errors.Is(err, ErrNotFound) {
				return fmt.Errorf("check user %s: %w", demo.Username, err)
			}
			hash, err := crypto.HashPassword(demo.Password)
			if err != nil {
				return fmt.Errorf("hash password for %s: %w", demo.Username, err)
			}
			u := &domain.User{
				ID:           NewID(),
				Username:     demo.Username,
				Email:        demo.Email,
				PasswordHash: hash,
				RoleID:       roleIDs[demo.RoleSlug],
				RoleSlug:     demo.RoleSlug,
				RoleName:     demo.RoleName,
				Active:       true,
				CreatedAt:    now,
			}
			if err := store.CreateUser(ctx, u); err != nil {
				return fmt.Errorf("seed user %s: %w", demo.Username, err)
			}
		}
	}

	// 3. Seed starter scan profiles if none exist yet
	profiles, err := store.ListProfiles(ctx)
	if err == nil && len(profiles) == 0 {
		starterProfiles := []*domain.ScanProfile{
			{
				ID:                    NewID(),
				Name:                  "CBI AGH Lab — Quick Scan Demo",
				Description:           "Deterministic test environment 172.28.0.0/24 (CMS, Admin, Staging TLS, IoT, Flapping)",
				Targets:               []string{"172.28.0.10-172.28.0.16"},
				AllowedPorts:          "80,443,8080,8443",
				MaxRatePPS:            500,
				HTTPRPS:               25,
				Concurrency:           16,
				ChunkTargetSec:        15,
				WindowEnabled:         false,
				WindowStart:           "00:00",
				WindowEnd:             "23:59",
				Timezone:              "Europe/Warsaw",
				MissingThreshold:      2,
				GracePeriodHours:      24,
				RetryUnstableCount:    2,
				EnableHTTPFingerprint: true,
				UserAgent:             "Dzieciol-CBI-AGH/1.0 (+https://cbi.agh.edu.pl)",
				Enabled:               true,
				CreatedAt:             now,
				UpdatedAt:             now,
			},
			{
				ID:                    NewID(),
				Name:                  "CBI AGH Campus — Night Window (/18)",
				Description:           "Large campus range 10.0.0.0/18 (16,384 IPs) with a hard 22:00–06:00 Europe/Warsaw time window",
				Targets:               []string{"10.0.0.0/18"},
				AllowedPorts:          "22,80,443,8080,8443",
				MaxRatePPS:            1000,
				HTTPRPS:               40,
				Concurrency:           64,
				ChunkTargetSec:        60,
				ScheduleCron:          "0 22 * * *",
				WindowEnabled:         true,
				WindowStart:           "22:00",
				WindowEnd:             "06:00",
				Timezone:              "Europe/Warsaw",
				MissingThreshold:      3,
				GracePeriodHours:      48,
				RetryUnstableCount:    2,
				EnableHTTPFingerprint: true,
				UserAgent:             "Dzieciol-CBI-AGH/1.0 (+https://cbi.agh.edu.pl)",
				Enabled:               true,
				CreatedAt:             now,
				UpdatedAt:             now,
			},
		}
		for _, p := range starterProfiles {
			_ = store.CreateProfile(ctx, p)
		}
	}

	// 4. Seed default safety exclusion if empty
	exclusions, err := store.ListExclusions(ctx)
	if err == nil && len(exclusions) == 0 {
		_ = store.CreateExclusion(ctx, &domain.TargetExclusion{
			ID:        NewID(),
			Value:     "127.0.0.0/8",
			Reason:    "Loopback safety exclusion",
			CreatedBy: "system",
			CreatedAt: now,
		})
	}

	return nil
}
