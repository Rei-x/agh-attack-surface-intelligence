package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	stateFileName = "agent.json"
	outboxDirName = "outbox"
)

// state is the agent identity, stored 0600 in the data directory. The credential is the
// only secret the agent holds; the one-time enrollment token is never stored.
type state struct {
	ServerURL  string    `json:"server_url"`
	AgentID    string    `json:"agent_id"`
	Name       string    `json:"name"`
	Site       string    `json:"site,omitempty"`
	Credential string    `json:"credential"`
	InstanceID string    `json:"instance_id"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func loadState(dir string) (*state, error) {
	raw, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if errors.Is(err, os.ErrNotExist) {
		return &state{}, nil
	}
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", stateFileName, err)
	}
	return &st, nil
}

// writeFileAtomic writes data with mode 0600 via temp file + fsync + rename.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func saveState(dir string, st *state) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, stateFileName), raw)
}

// outbox is a durable FIFO of results waiting for upload. Every chunk result and segment
// finish is written here (fsync) before any network call, so a lost connection or a crash
// never loses scan results: they are uploaded, in order, once the server is reachable.
type outbox struct {
	dir    string
	mu     sync.Mutex
	seq    uint64
	notify chan struct{}
}

type outboxRecord struct {
	Kind      string          `json:"kind"` // chunk | finish
	RunID     string          `json:"run_id"`
	CreatedAt time.Time       `json:"created_at"`
	Body      json.RawMessage `json:"body"`
}

func openOutbox(dataDir string) (*outbox, error) {
	dir := filepath.Join(dataDir, outboxDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	o := &outbox{dir: dir, notify: make(chan struct{}, 1)}
	for _, n := range o.list() {
		var s uint64
		if _, err := fmt.Sscanf(n, "%020d", &s); err == nil && s > o.seq {
			o.seq = s
		}
	}
	return o, nil
}

func (o *outbox) put(kind, runID string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	rec, err := json.Marshal(outboxRecord{Kind: kind, RunID: runID, CreatedAt: time.Now().UTC(), Body: raw})
	if err != nil {
		return err
	}
	o.mu.Lock()
	o.seq++
	name := fmt.Sprintf("%020d-%s.json", o.seq, kind)
	err = writeFileAtomic(filepath.Join(o.dir, name), rec)
	o.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case o.notify <- struct{}{}:
	default:
	}
	return nil
}

// list returns pending record file names, oldest first.
func (o *outbox) list() []string {
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func (o *outbox) read(name string) (*outboxRecord, error) {
	raw, err := os.ReadFile(filepath.Join(o.dir, name))
	if err != nil {
		return nil, err
	}
	var rec outboxRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (o *outbox) remove(name string) { _ = os.Remove(filepath.Join(o.dir, name)) }

// quarantine moves a record the server rejects as malformed out of the queue (kept for
// inspection) so it cannot block every later upload.
func (o *outbox) quarantine(name string) {
	bad := filepath.Join(o.dir, "rejected")
	_ = os.MkdirAll(bad, 0o700)
	_ = os.Rename(filepath.Join(o.dir, name), filepath.Join(bad, name))
}

func (o *outbox) pending() int { return len(o.list()) }
