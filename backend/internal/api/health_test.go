package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
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

// downStore simulates the database going away after startup.
type downStore struct {
	*db.MemoryStore
	down bool
}

func (d *downStore) GetUser(ctx context.Context, id string) (*domain.User, error) {
	if d.down {
		return nil, errors.New("connection refused")
	}
	return d.MemoryStore.GetUser(ctx, id)
}

func (d *downStore) GetUserByUsername(ctx context.Context, u string) (*domain.User, error) {
	if d.down {
		return nil, errors.New("connection refused")
	}
	return d.MemoryStore.GetUserByUsername(ctx, u)
}

// A database outage must answer 503, not 401: a 401 makes the UI log everyone out and the
// message "account inactive or not found" sends users chasing the wrong problem.
func TestDatabaseOutageIs503Not401(t *testing.T) {
	vault, _ := crypto.NewVault("")
	store := &downStore{MemoryStore: db.NewMemoryStore(vault)}
	if err := db.SeedDefaults(context.Background(), store, true); err != nil {
		t.Fatal(err)
	}
	h := NewServer(Config{JWTSecret: vault.JWTSecret(""), SeedDemo: true}, store, vault, nil, nil, nil).Handler()
	tok := loginTest(t, h, "viewer", "Viewer123!")
	store.down = true
	if rec := doJSON(h, http.MethodGet, "/api/v1/hosts", tok, nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("authenticated request during outage: got %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(h, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "viewer", "password": "Viewer123!"}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("login during outage: got %d %s", rec.Code, rec.Body.String())
	}
	store.down = false
	if rec := doJSON(h, http.MethodGet, "/api/v1/hosts", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("after recovery the same token works: got %d", rec.Code)
	}
}
