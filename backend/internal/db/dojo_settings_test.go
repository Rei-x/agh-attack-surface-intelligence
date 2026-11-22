package db

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestDefectDojoLoginEncryptedAndClearable(t *testing.T) {
	ctx := context.Background()
	vault, err := crypto.NewVault(hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore(vault)

	if l, err := LoadDefectDojoLogin(ctx, store); err != nil || l != nil {
		t.Fatalf("unset login: got %+v, %v", l, err)
	}
	want := domain.DefectDojoLogin{Username: "jury", Password: "Kx7m-Pq3w-Zr8t-Hn4v"}
	if err := SaveDefectDojoLogin(ctx, store, &want); err != nil {
		t.Fatal(err)
	}
	raw := store.settings[SettingDojoLogin]
	if raw == "" || strings.Contains(raw, want.Password) || strings.Contains(raw, want.Username) {
		t.Fatalf("login must be stored encrypted, raw=%q", raw)
	}
	got, err := LoadDefectDojoLogin(ctx, store)
	if err != nil || got == nil || *got != want {
		t.Fatalf("load: got %+v, %v", got, err)
	}

	if err := SaveDefectDojoLogin(ctx, store, nil); err != nil {
		t.Fatal(err)
	}
	if l, err := LoadDefectDojoLogin(ctx, store); err != nil || l != nil {
		t.Fatalf("cleared login: got %+v, %v", l, err)
	}
}
