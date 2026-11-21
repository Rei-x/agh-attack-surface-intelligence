package db

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const testMasterKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func TestFileStorePersistsEncryptedAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.enc")

	vault1, err := crypto.NewVault(testMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	fs1, err := OpenFileStore(path, vault1, FileStoreOptions{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !fs1.IsNew() {
		t.Fatalf("expected new store")
	}
	now := time.Now().UTC()
	h, err := fs1.UpsertObservedHost(ctx, &domain.Host{
		IP: "172.28.0.99", Hostname: "secret-host.agh.edu.pl", LifecycleState: domain.HostStateNew,
		Notes: "very-private-note", FirstSeen: now, LastSeen: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs1.UpsertObservedService(ctx, &domain.Service{
		HostID: h.ID, HostIP: h.IP, Port: 22, Protocol: "tcp", State: "open", ServiceName: "ssh",
		Banner: "SSH-2.0-SuperSecretBanner_9.9", FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Rotate the DEK so the restart must restore more than one key version.
	kid, wrapped, err := vault1.RotateDEK()
	if err != nil {
		t.Fatal(err)
	}
	if err := fs1.SaveCryptoKey(ctx, kid, wrapped, true); err != nil {
		t.Fatal(err)
	}
	if err := fs1.CreateUser(ctx, &domain.User{ID: NewID(), Username: "alice", Email: "alice@private.example", PasswordHash: "x", Active: true, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	fs1.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"172.28.0.99", "secret-host", "very-private-note", "SuperSecretBanner", "alice@private.example"} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Fatalf("store file contains plaintext %q", needle)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %v", info.Mode().Perm())
	}

	// Inner layer: decrypt the outer envelope and verify rows are still field-encrypted.
	inner, err := vault1.OpenBlob(raw[len(fileStoreMagic):], fileStoreAAD)
	if err != nil {
		t.Fatal(err)
	}
	zr, _ := gzip.NewReader(bytes.NewReader(inner))
	jsonRaw, _ := io.ReadAll(zr)
	for _, needle := range []string{"172.28.0.99", "secret-host", "SuperSecretBanner", "alice@private.example"} {
		if bytes.Contains(jsonRaw, []byte(needle)) {
			t.Fatalf("inner snapshot contains plaintext %q (field encryption missing)", needle)
		}
	}

	// Restart with a fresh vault from the same master key.
	vault2, _ := crypto.NewVault(testMasterKey)
	fs2, err := OpenFileStore(path, vault2, FileStoreOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer fs2.Close()
	if fs2.IsNew() {
		t.Fatalf("expected existing store")
	}
	got, err := fs2.GetHostByIP(ctx, "172.28.0.99")
	if err != nil {
		t.Fatalf("host lost after restart: %v", err)
	}
	if got.Hostname != "secret-host.agh.edu.pl" || len(got.Services) != 1 || got.Services[0].Banner != "SSH-2.0-SuperSecretBanner_9.9" {
		t.Fatalf("unexpected host after restart: %+v", got)
	}
	u, err := fs2.GetUserByUsername(ctx, "alice")
	if err != nil || u.Email != "alice@private.example" {
		t.Fatalf("user lost after restart: %v %+v", err, u)
	}
	if vault2.ActiveKID() != kid {
		t.Fatalf("active KID not restored: %s want %s", vault2.ActiveKID(), kid)
	}

	// Wrong master key must fail loudly instead of silently starting empty.
	vault3, _ := crypto.NewVault(strings.Repeat("ab", 32))
	if _, err := OpenFileStore(path, vault3, FileStoreOptions{ReadOnly: true}); err == nil {
		t.Fatalf("expected failure with wrong master key")
	}
}

func TestFileStoreDebouncedAutosave(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.enc")
	vault, _ := crypto.NewVault(testMasterKey)
	fs, err := OpenFileStore(path, vault, FileStoreOptions{Debounce: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	before, _ := os.Stat(path)
	if err := fs.CreateTarget(ctx, &domain.Target{ID: NewID(), Value: "10.0.0.0/24", Kind: "cidr", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fs.savedGenSnapshot() == fs.Generation() {
			after, _ := os.Stat(path)
			if after.ModTime().Equal(before.ModTime()) && after.Size() == before.Size() {
				t.Fatalf("file not rewritten")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("autosave did not happen within 2s")
}
