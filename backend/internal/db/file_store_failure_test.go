package db

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestFileStoreReportsPersistFailureViaPing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	ctx := context.Background()
	dir := t.TempDir()
	vault, _ := crypto.NewVault(testMasterKey)
	fs, err := OpenFileStore(filepath.Join(dir, "store.enc"), vault, FileStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err := fs.Ping(ctx); err != nil {
		t.Fatalf("healthy store: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // simulate a read-only / full data dir
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, err := fs.UpsertObservedHost(ctx, &domain.Host{IP: "10.0.0.1", LifecycleState: domain.HostStateNew}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Flush(); err == nil {
		t.Fatal("flush into a read-only dir should fail")
	}
	if err := fs.Ping(ctx); err == nil || !strings.Contains(err.Error(), "not saved") {
		t.Fatalf("Ping must surface the persist failure, got %v", err)
	}
	_ = os.Chmod(dir, 0o700)
	if err := fs.Flush(); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if err := fs.Ping(ctx); err != nil {
		t.Fatalf("Ping after recovery: %v", err)
	}
}

// A crash mid-write leaves only a temp file behind; the previous snapshot stays loadable and
// stray temp files are ignored.
func TestFileStoreSurvivesTornTempFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.enc")
	vault, _ := crypto.NewVault(testMasterKey)
	fs, err := OpenFileStore(path, vault, FileStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.UpsertObservedHost(ctx, &domain.Host{IP: "10.0.0.7", LifecycleState: domain.HostStateNew}); err != nil {
		t.Fatal(err)
	}
	fs.Close()
	good, _ := os.ReadFile(path)
	// Simulate kill -9 during the next write: half a temp file next to the snapshot.
	if err := os.WriteFile(filepath.Join(dir, ".store.enc.tmp-123"), good[:len(good)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	vault2, _ := crypto.NewVault(testMasterKey)
	fs2, err := OpenFileStore(path, vault2, FileStoreOptions{})
	if err != nil {
		t.Fatalf("reopen after torn temp file: %v", err)
	}
	defer fs2.Close()
	if _, err := fs2.GetHostByIP(ctx, "10.0.0.7"); err != nil {
		t.Fatalf("data lost: %v", err)
	}
	// A truncated snapshot itself (should never happen with atomic rename) is refused clearly.
	if err := os.WriteFile(path+"2", good[:len(good)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	vault3, _ := crypto.NewVault(testMasterKey)
	if _, err := OpenFileStore(path+"2", vault3, FileStoreOptions{ReadOnly: true}); err == nil {
		t.Fatal("truncated snapshot must be refused, not half-loaded")
	}
}
