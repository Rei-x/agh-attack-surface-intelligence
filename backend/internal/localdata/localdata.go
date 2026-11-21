// Package localdata manages the single-binary data directory (default ~/.aegis):
// the master key file, the encrypted store file and an exclusive instance lock.
package localdata

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
)

const (
	StoreFileName     = "aegis-store.enc"
	MasterKeyFileName = "master.key"
	LockFileName      = "aegis.lock"
)

// DefaultDir resolves the data directory: explicit flag > ASI_DATA_DIR > ~/.aegis.
func DefaultDir(flagValue string) (string, error) {
	dir := strings.TrimSpace(flagValue)
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv("ASI_DATA_DIR"))
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory (use --data-dir): %w", err)
		}
		dir = filepath.Join(home, ".aegis")
	}
	if strings.HasPrefix(dir, "~"+string(os.PathSeparator)) || dir == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, strings.TrimPrefix(dir, "~"))
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return abs, nil
}

// Dir is an opened data directory.
type Dir struct {
	Path string
}

// Open ensures the directory exists with 0700 permissions.
func Open(path string) (*Dir, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w", path, err)
	}
	return &Dir{Path: path}, nil
}

func (d *Dir) StorePath() string { return filepath.Join(d.Path, StoreFileName) }
func (d *Dir) KeyPath() string   { return filepath.Join(d.Path, MasterKeyFileName) }
func (d *Dir) LockPath() string  { return filepath.Join(d.Path, LockFileName) }

// StoreExists reports whether an encrypted store has already been written.
func (d *Dir) StoreExists() bool {
	_, err := os.Stat(d.StorePath())
	return err == nil
}

// KeySource describes where the master key came from (never the key itself).
type KeySource string

const (
	KeyFromEnv       KeySource = "ASI_MASTER_KEY"
	KeyFromFile      KeySource = "file"
	KeyFileGenerated KeySource = "generated"
)

// MasterKey returns the master key: ASI_MASTER_KEY when set, otherwise <dir>/master.key,
// generating a new random 256-bit key (0600) on first run. It refuses to generate a new key
// if an encrypted store already exists, because that data would become unreadable.
func (d *Dir) MasterKey() (string, KeySource, error) {
	if env := strings.TrimSpace(os.Getenv("ASI_MASTER_KEY")); env != "" {
		return env, KeyFromEnv, nil
	}
	raw, err := os.ReadFile(d.KeyPath())
	if err == nil {
		key := strings.TrimSpace(string(raw))
		if key == "" {
			return "", "", fmt.Errorf("%s is empty", d.KeyPath())
		}
		if info, statErr := os.Stat(d.KeyPath()); statErr == nil && info.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(d.KeyPath(), 0o600)
		}
		return key, KeyFromFile, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("read %s: %w", d.KeyPath(), err)
	}
	if d.StoreExists() {
		return "", "", fmt.Errorf("encrypted store %s exists but %s is missing and ASI_MASTER_KEY is not set; "+
			"restore the key file or set ASI_MASTER_KEY (refusing to generate a new key that could not decrypt existing data)",
			d.StorePath(), d.KeyPath())
	}
	key, err := crypto.GenerateMasterKey()
	if err != nil {
		return "", "", err
	}
	f, err := os.OpenFile(d.KeyPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("create %s: %w", d.KeyPath(), err)
	}
	if _, err := f.WriteString(key + "\n"); err != nil {
		f.Close()
		return "", "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", "", err
	}
	if err := f.Close(); err != nil {
		return "", "", err
	}
	return key, KeyFileGenerated, nil
}

// LockInfo is written into the lock file so other commands can explain who holds it.
type LockInfo struct {
	PID       int       `json:"pid"`
	Command   string    `json:"command"`
	URL       string    `json:"url,omitempty"`
	StartedAt time.Time `json:"started_at"`
}

// Lock is an exclusive OS-level lock on the data directory. It is released automatically
// by the OS if the process dies, so there are no stale locks after a crash.
type Lock struct {
	f    *os.File
	path string
}

// ErrLocked is returned when another aegis process holds the data directory.
type ErrLocked struct {
	Path   string
	Holder *LockInfo
}

func (e *ErrLocked) Error() string {
	if e.Holder != nil {
		msg := fmt.Sprintf("data directory is in use by `aegis %s` (pid %d, since %s)",
			e.Holder.Command, e.Holder.PID, e.Holder.StartedAt.Local().Format("2006-01-02 15:04:05"))
		if e.Holder.URL != "" {
			msg += " at " + e.Holder.URL
		}
		return msg
	}
	return "data directory is in use by another aegis process (" + e.Path + ")"
}

// Acquire takes the exclusive lock (non-blocking) and records info in the lock file.
func (d *Dir) Acquire(info LockInfo) (*Lock, error) {
	f, err := os.OpenFile(d.LockPath(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := tryLock(f); err != nil {
		f.Close()
		return nil, &ErrLocked{Path: d.LockPath(), Holder: d.ReadLockInfo()}
	}
	if info.PID == 0 {
		info.PID = os.Getpid()
	}
	if info.StartedAt.IsZero() {
		info.StartedAt = time.Now()
	}
	l := &Lock{f: f, path: d.LockPath()}
	_ = l.Update(info)
	return l, nil
}

// Update rewrites the holder info (e.g. once the listen URL is known).
func (l *Lock) Update(info LockInfo) error {
	raw, _ := json.Marshal(info)
	if err := l.f.Truncate(0); err != nil {
		return err
	}
	if _, err := l.f.WriteAt(append(raw, '\n'), 0); err != nil {
		return err
	}
	return l.f.Sync()
}

// Release unlocks and closes the lock file.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = l.f.Truncate(0)
	_ = unlock(l.f)
	_ = l.f.Close()
	l.f = nil
}

// ReadLockInfo returns the recorded holder, if any (best effort).
func (d *Dir) ReadLockInfo() *LockInfo {
	raw, err := os.ReadFile(d.LockPath())
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var info LockInfo
	if json.Unmarshal(raw, &info) != nil {
		return nil
	}
	return &info
}
