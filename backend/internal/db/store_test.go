package db

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestOverridePreservationAcrossScansAndEncryptionAtRest(t *testing.T) {
	ctx := context.Background()
	keyHex := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	vault, err := crypto.NewVault(keyHex)
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	store := NewMemoryStore(vault)

	// Scan 1 observes host + service
	now := time.Now().UTC()
	h1, err := store.UpsertObservedHost(ctx, &domain.Host{
		IP:             "172.28.0.14",
		Hostname:       "moodle-old.agh.edu.pl",
		LifecycleState: domain.HostStateNew,
		Environment:    "unknown",
		Notes:          "discovered in scan 1",
		Tags:           []string{"moodle"},
		FirstSeen:      now,
		LastSeen:       now,
	})
	if err != nil {
		t.Fatalf("UpsertObservedHost scan 1: %v", err)
	}

	// Verify encryption at rest
	rawIP := store.RawHostIPCiphertext(h1.ID)
	if !strings.HasPrefix(rawIP, "enc:v1:dek-v1:") || strings.Contains(rawIP, "172.28.0.14") {
		t.Fatalf("expected encrypted IP at rest, got %q", rawIP)
	}

	svc1, err := store.UpsertObservedService(ctx, &domain.Service{
		HostID:      h1.ID,
		HostIP:      h1.IP,
		Port:        80,
		Protocol:    "tcp",
		State:       "open",
		ServiceName: "http",
		Product:     "nginx",
		Version:     "1.24.0",
		HTTP:        &domain.HTTPFingerprint{Title: "AGH Moodle E-Learning"},
		FirstSeen:   now,
		LastSeen:    now,
	})
	if err != nil {
		t.Fatalf("UpsertObservedService scan 1: %v", err)
	}

	// Analyst edits overrides (hostname, environment, owner, notes + service product/triage)
	if err := store.PatchOverrides(ctx, "host", h1.ID, map[string]any{
		"hostname":    "usos-prod.cbi.agh.edu.pl",
		"environment": "prod",
		"owner":       "CBI-Team-A",
		"notes":       "Critical university service - DO NOT OVERWRITE",
	}, nil, "analyst"); err != nil {
		t.Fatalf("PatchOverrides host: %v", err)
	}
	if err := store.PatchOverrides(ctx, "service", svc1.ID, map[string]any{
		"product":       "Custom AGH Proxy",
		"triage_status": "accepted_risk",
	}, nil, "analyst"); err != nil {
		t.Fatalf("PatchOverrides service: %v", err)
	}

	// Scan 2 arrives with DIFFERENT observed hostname, notes, and product
	later := now.Add(time.Hour)
	h2, err := store.UpsertObservedHost(ctx, &domain.Host{
		IP:             "172.28.0.14",
		Hostname:       "moodle-mutated.agh.edu.pl",
		LifecycleState: domain.HostStateActive,
		Environment:    "staging",
		Notes:          "scanner overwrite attempt",
		Tags:           []string{"moodle", "changed"},
		FirstSeen:      now,
		LastSeen:       later,
	})
	if err != nil {
		t.Fatalf("UpsertObservedHost scan 2: %v", err)
	}

	if h2.Hostname != "usos-prod.cbi.agh.edu.pl" || h2.Environment != "prod" || h2.Owner != "CBI-Team-A" {
		t.Fatalf("analyst host overrides were overwritten! got %+v", h2)
	}
	if h2.ScannerObserved["hostname"] != "moodle-mutated.agh.edu.pl" {
		t.Fatalf("expected scanner_observed.hostname to record scanner value, got %+v", h2.ScannerObserved)
	}

	svc2, err := store.UpsertObservedService(ctx, &domain.Service{
		HostID:      h1.ID,
		HostIP:      h1.IP,
		Port:        80,
		Protocol:    "tcp",
		State:       "open",
		ServiceName: "http",
		Product:     "Apache",
		Version:     "2.4.58",
		FirstSeen:   now,
		LastSeen:    later,
	})
	if err != nil {
		t.Fatalf("UpsertObservedService scan 2: %v", err)
	}
	if svc2.Product != "Custom AGH Proxy" || svc2.TriageStatus != "accepted_risk" {
		t.Fatalf("analyst service overrides were overwritten! got %+v", svc2)
	}
	if svc2.ScannerObserved["product"] != "Apache" {
		t.Fatalf("expected scanner_observed.product=Apache, got %+v", svc2.ScannerObserved)
	}

	// Unlock hostname -> should immediately reveal scanner's observed value
	if err := store.PatchOverrides(ctx, "host", h1.ID, nil, []string{"hostname"}, "analyst"); err != nil {
		t.Fatalf("unlock hostname: %v", err)
	}
	h3, err := store.GetHost(ctx, h1.ID)
	if err != nil {
		t.Fatalf("GetHost after unlock: %v", err)
	}
	if h3.Hostname != "moodle-mutated.agh.edu.pl" {
		t.Fatalf("expected unlocked hostname to revert to scanner value, got %q", h3.Hostname)
	}

	// Rotate DEK and re-encrypt all rows
	newKID, wrapped, err := vault.RotateDEK()
	if err != nil {
		t.Fatalf("RotateDEK: %v", err)
	}
	if err := store.SaveCryptoKey(ctx, newKID, wrapped, true); err != nil {
		t.Fatalf("SaveCryptoKey: %v", err)
	}
	reencCount, err := store.ReEncryptAll(ctx)
	if err != nil || reencCount == 0 {
		t.Fatalf("ReEncryptAll: count=%d err=%v", reencCount, err)
	}
	if !strings.HasPrefix(store.RawHostIPCiphertext(h1.ID), "enc:v1:dek-v2:") {
		t.Fatalf("expected host IP re-encrypted under dek-v2, got %s", store.RawHostIPCiphertext(h1.ID))
	}
	// Blind index lookup still works after DEK rotation
	byIP, err := store.GetHostByIP(ctx, "172.28.0.14")
	if err != nil || byIP.ID != h1.ID {
		t.Fatalf("GetHostByIP after rotation failed: %v", err)
	}
}

func TestSeedDefaultsCreatesFourRolesAndDemoUsers(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := NewMemoryStore(vault)

	if err := SeedDefaults(ctx, store, true); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	roles, err := store.ListRoles(ctx)
	if err != nil || len(roles) != 4 {
		t.Fatalf("expected 4 roles, got %d (err=%v)", len(roles), err)
	}
	users, err := store.ListUsers(ctx)
	if err != nil || len(users) != 4 {
		t.Fatalf("expected 4 demo users, got %d (err=%v)", len(users), err)
	}
	admin, err := store.GetUserByUsername(ctx, "admin")
	if err != nil || !crypto.VerifyPassword("Admin123!", admin.PasswordHash) {
		t.Fatalf("admin login check failed: %v", err)
	}
}
