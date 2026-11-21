package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
)

type failingPingStore struct{ *db.MemoryStore }

func (failingPingStore) Ping(context.Context) error { return errors.New("disk full") }

func TestHealthIs503WhenStoreCannotPersist(t *testing.T) {
	vault, _ := crypto.NewVault("")
	store := failingPingStore{db.NewMemoryStore(vault)}
	h := NewServer(Config{JWTSecret: vault.JWTSecret("")}, store, vault, nil, nil, nil).Handler()
	rec := doJSON(h, http.MethodGet, "/api/v1/health", "", nil)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "disk full") ||
		!strings.Contains(rec.Body.String(), `"status":"degraded"`) {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}
