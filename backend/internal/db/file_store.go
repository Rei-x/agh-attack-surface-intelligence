package db

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
)

// File format of the local encrypted store:
//
//	"AEGISDB1" (8-byte magic) | nonce(12) | AES-256-GCM( gzip( JSON(memoryState) ) ) | tag(16)
//
// The GCM key is derived from the master key (KEK) via HMAC-SHA256 and the magic is bound
// as AAD. Inside, all sensitive fields are also envelope-encrypted per row with the
// versioned DEKs (like the PostgreSQL backend), so data is protected twice at rest. The
// magic, the AAD and the KDF labels predate the Dzięcioł rename and must not change, or
// existing store files no longer decrypt.
var fileStoreMagic = []byte("AEGISDB1")

const fileStoreAAD = "aegis-asi:store-snapshot:v1"

// FileStoreOptions tunes persistence timing.
type FileStoreOptions struct {
	// Debounce is the quiet period after a write before the snapshot is flushed.
	Debounce time.Duration
	// MaxDelay bounds how long a continuous stream of writes may postpone a flush.
	MaxDelay time.Duration
	// Interval is a periodic safety flush (only writes when something changed).
	Interval time.Duration
	// ReadOnly loads the snapshot but never writes it back (used by export/diff).
	ReadOnly bool
	// Retention, when set, is applied right after loading (writable stores only) and the
	// compacted state is written back before OpenFileStore returns. Callers apply it again
	// after every ingest (ingest.Pipeline.SetRetention).
	Retention *RetentionPolicy
}

// FileStore is a MemoryStore persisted to a single AES-256-GCM encrypted snapshot file with
// atomic writes (temp file + fsync + rename). It needs no external database and no cgo.
type FileStore struct {
	*MemoryStore

	path  string
	vault *crypto.Vault
	opts  FileStoreOptions
	isNew bool

	saveMu    sync.Mutex
	savedGen  uint64
	wroteOnce bool
	saveErr   error // last persist failure (disk full, read-only dir); nil after a good save
	lastSize  int   // size of the last file read or written (sizes the next write buffer)

	changeCh  chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}
	closeOnce sync.Once
}

// OpenFileStore loads (or creates) the encrypted store at path. The vault must be built from
// the same master key that sealed the file; persisted DEKs are loaded into the vault.
func OpenFileStore(path string, vault *crypto.Vault, opts FileStoreOptions) (*FileStore, error) {
	if opts.Debounce <= 0 {
		opts.Debounce = 1500 * time.Millisecond
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = 10 * time.Second
	}
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	fs := &FileStore{
		MemoryStore: NewMemoryStore(vault),
		path:        path,
		vault:       vault,
		opts:        opts,
		changeCh:    make(chan struct{}, 1),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := fs.load(raw); err != nil {
			return nil, err
		}
		if len(raw) > 16<<20 {
			// The file buffer is garbage now: hand it back to the OS right away instead of
			// letting it count against a container memory limit until the next GC cycles.
			debug.FreeOSMemory()
		}
	case errors.Is(err, os.ErrNotExist):
		if opts.ReadOnly {
			return nil, fmt.Errorf("no Dzięcioł data found at %s (run `dzieciol serve` or `dzieciol scan` first)", path)
		}
		fs.isNew = true
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	default:
		return nil, fmt.Errorf("read store %s: %w", path, err)
	}

	fs.savedGen = fs.Generation()
	if !opts.ReadOnly {
		// Temp files left by a crash mid-write (the snapshot itself is replaced atomically).
		if stale, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")); len(stale) > 0 {
			for _, p := range stale {
				_ = os.Remove(p)
			}
		}
	}
	if opts.ReadOnly {
		close(fs.doneCh)
		return fs, nil
	}
	if opts.Retention != nil && !fs.isNew {
		rep, err := fs.Compact(context.Background(), *opts.Retention)
		switch {
		case err != nil:
			log.Printf("[WARN] retention on load: %v", err)
		case !rep.Empty():
			log.Printf("[INFO] retention on load (%s): %s", opts.Retention, rep)
		}
	}
	if fs.isNew || fs.Generation() != fs.savedGen {
		// A new store is persisted immediately so the master key and the wrapped DEKs are
		// paired on disk; a compacted one so the smaller file replaces the old one now.
		if err := fs.Flush(); err != nil {
			return nil, err
		}
		if !fs.isNew {
			debug.FreeOSMemory()
		}
	}
	fs.SetChangeHook(fs.notify)
	go fs.loop()
	return fs, nil
}

// IsNew reports whether the store file did not exist before OpenFileStore.
func (f *FileStore) IsNew() bool { return f.isNew }

// Path returns the snapshot file path.
func (f *FileStore) Path() string { return f.path }

func (f *FileStore) BackendName() string { return "file-encrypted" }

// load decrypts raw (the whole file) in place and streams the decompressed JSON into the
// store, so loading holds the file bytes plus the decoded state and nothing in between.
func (f *FileStore) load(raw []byte) error {
	if len(raw) < len(fileStoreMagic) || !bytes.Equal(raw[:len(fileStoreMagic)], fileStoreMagic) {
		return fmt.Errorf("%s is not a Dzięcioł store file (bad magic)", f.path)
	}
	plain, err := f.vault.OpenBlobInPlace(raw[len(fileStoreMagic):], fileStoreAAD)
	if err != nil {
		return fmt.Errorf("open %s: %w", f.path, err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return fmt.Errorf("decompress store: %w", err)
	}
	keys, active, err := f.ReadState(zr)
	if err != nil {
		return err
	}
	f.lastSize = len(raw)
	if len(keys) > 0 {
		if err := f.vault.LoadWrappedDEKs(keys, active); err != nil {
			return fmt.Errorf("unwrap data keys: %w", err)
		}
	} else {
		// Should not happen, but keep the vault's fresh DEK persisted.
		wrapped, act := f.vault.ExportWrappedDEKs()
		for kid, w := range wrapped {
			_ = f.SaveCryptoKey(context.Background(), kid, w, kid == act)
		}
	}
	return nil
}

func (f *FileStore) notify() {
	select {
	case f.changeCh <- struct{}{}:
	default:
	}
}

func (f *FileStore) loop() {
	defer close(f.doneCh)
	ticker := time.NewTicker(f.opts.Interval)
	defer ticker.Stop()

	var debounce <-chan time.Time
	var debounceTimer *time.Timer
	var firstDirty time.Time

	flush := func() {
		if err := f.Flush(); err != nil {
			log.Printf("[ERROR] persist encrypted store: %v", err)
		}
		firstDirty = time.Time{}
		debounce = nil
	}

	for {
		select {
		case <-f.stopCh:
			return
		case <-f.changeCh:
			now := time.Now()
			if firstDirty.IsZero() {
				firstDirty = now
			}
			wait := f.opts.Debounce
			if deadline := firstDirty.Add(f.opts.MaxDelay); now.Add(wait).After(deadline) {
				wait = time.Until(deadline)
				if wait < 0 {
					wait = 0
				}
			}
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.NewTimer(wait)
			debounce = debounceTimer.C
		case <-debounce:
			flush()
		case <-ticker.C:
			if f.Generation() != f.savedGenSnapshot() {
				flush()
			}
		}
	}
}

func (f *FileStore) savedGenSnapshot() uint64 {
	f.saveMu.Lock()
	defer f.saveMu.Unlock()
	return f.savedGen
}

// Ping reports a failing snapshot write (disk full, permissions) so /health and the UI show
// that recent changes are not being persisted, instead of only logging it.
func (f *FileStore) Ping(_ context.Context) error {
	f.saveMu.Lock()
	defer f.saveMu.Unlock()
	if f.saveErr != nil {
		return fmt.Errorf("persisting the store to disk fails - changes are not saved (check free space and permissions on %s): %w",
			filepath.Dir(f.path), f.saveErr)
	}
	return nil
}

// Flush writes the current state to disk if it changed since the last save.
func (f *FileStore) Flush() error {
	if f.opts.ReadOnly {
		return nil
	}
	f.saveMu.Lock()
	defer f.saveMu.Unlock()
	err := f.flushLocked()
	f.saveErr = err
	return err
}

// flushLocked streams the state through gzip into one buffer laid out as the final file
// (magic | nonce room | compressed JSON), seals that buffer in place and writes it. Peak
// extra memory is the compressed file size.
func (f *FileStore) flushLocked() error {
	if f.Generation() == f.savedGen && !f.isNewUnsaved() {
		return nil
	}
	var buf bytes.Buffer
	buf.Grow(f.lastSize + f.lastSize/8 + 4096)
	buf.Write(fileStoreMagic)
	buf.Write(make([]byte, crypto.BlobNonceSize))
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	gen, err := f.WriteState(zw)
	if err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	buf.Grow(crypto.BlobTagSize)
	out, err := f.vault.SealBlobInPlace(buf.Bytes(), len(fileStoreMagic), fileStoreAAD)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(f.path, out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", f.path, err)
	}
	f.lastSize = len(out)
	f.savedGen = gen
	f.wroteOnce = true
	return nil
}

func (f *FileStore) isNewUnsaved() bool { return f.isNew && !f.wroteOnce }

// Close stops the background writer and performs a final flush.
func (f *FileStore) Close() {
	f.closeOnce.Do(func() {
		if f.opts.ReadOnly {
			return
		}
		close(f.stopCh)
		<-f.doneCh
		if err := f.Flush(); err != nil {
			log.Printf("[ERROR] final flush of encrypted store: %v", err)
		}
	})
}

// writeFileAtomic writes data to a temp file in the same directory, fsyncs it and renames it
// over path, so a crash never leaves a half-written store behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	if runtime.GOOS != "windows" {
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			d.Close()
		}
	}
	return nil
}
