package localdata

import (
	"errors"
	"os"
	"testing"
)

func TestMasterKeyGeneratedOnceWith0600(t *testing.T) {
	t.Setenv("DZIECIOL_MASTER_KEY", "")
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	k1, src, err := d.MasterKey()
	if err != nil || src != KeyFileGenerated || len(k1) != 64 {
		t.Fatalf("first key: %q %s %v", k1, src, err)
	}
	info, _ := os.Stat(d.KeyPath())
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key perms %v", info.Mode().Perm())
	}
	k2, src, err := d.MasterKey()
	if err != nil || src != KeyFromFile || k2 != k1 {
		t.Fatalf("second key differs: %v %s", err, src)
	}
}

func TestMasterKeyRefusesRegenerationWhenStoreExists(t *testing.T) {
	t.Setenv("DZIECIOL_MASTER_KEY", "")
	d, _ := Open(t.TempDir())
	if err := os.WriteFile(d.StorePath(), []byte("AEGISDB1xxxx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.MasterKey(); err == nil {
		t.Fatalf("expected refusal to generate a new key over existing data")
	}
	t.Setenv("DZIECIOL_MASTER_KEY", "abc")
	if k, src, err := d.MasterKey(); err != nil || src != KeyFromEnv || k != "abc" {
		t.Fatalf("env key: %q %s %v", k, src, err)
	}
}

func TestLockIsExclusive(t *testing.T) {
	d, _ := Open(t.TempDir())
	l1, err := d.Acquire(LockInfo{Command: "serve", URL: "http://localhost:8080"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Acquire(LockInfo{Command: "scan"})
	var le *ErrLocked
	if !errors.As(err, &le) || le.Holder == nil || le.Holder.Command != "serve" || le.Holder.URL != "http://localhost:8080" {
		t.Fatalf("expected ErrLocked with holder info, got %v", err)
	}
	l1.Release()
	l2, err := d.Acquire(LockInfo{Command: "scan"})
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	l2.Release()
}
