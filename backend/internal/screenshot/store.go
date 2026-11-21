package screenshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// DefaultKeep is how many distinct screenshots are kept per service.
const DefaultKeep = 5

// ChangeDistance is the perceptual hash distance (of 64 bits) from which a new screenshot
// counts as a visibly different page rather than noise (clock, carousel, counters).
const ChangeDistance = 12

// ErrNotFound is returned for unknown image ids.
var ErrNotFound = errors.New("screenshot not found")

const indexAAD = "screenshot:index:v1"

// Key identifies one service.
type Key struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (k Key) norm() Key {
	if k.Protocol == "" {
		k.Protocol = "tcp"
	}
	k.Protocol = strings.ToLower(k.Protocol)
	return k
}

func (k Key) String() string {
	k = k.norm()
	return k.IP + "|" + strconv.Itoa(k.Port) + "|" + k.Protocol
}

func parseKey(s string) (Key, bool) {
	parts := strings.Split(s, "|")
	if len(parts) != 3 {
		return Key{}, false
	}
	p, err := strconv.Atoi(parts[1])
	if err != nil {
		return Key{}, false
	}
	return Key{IP: parts[0], Port: p, Protocol: parts[2]}, true
}

// Entry is one stored screenshot of a service. ID and Thumb are opaque blob ids
// (keyed hashes of the content: equal images share one blob, ids reveal nothing).
type Entry struct {
	ID         string    `json:"id"`
	Thumb      string    `json:"thumb"`
	Width      int       `json:"width"`
	Height     int       `json:"height"`
	Bytes      int       `json:"bytes"`
	PHash      string    `json:"phash"`
	URL        string    `json:"url"`
	Title      string    `json:"title,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`  // first capture of this exact picture
	CapturedAt time.Time `json:"captured_at"` // latest capture of it
	ScanRunID  string    `json:"scan_run_id,omitempty"`
}

// Service is the history of one service, newest first.
type Service struct {
	Key     Key     `json:"key"`
	Entries []Entry `json:"entries"`
}

// PutResult tells what storing a capture did.
type PutResult struct {
	Entry    Entry
	Previous *Entry // the picture it replaced as newest (nil: first capture or unchanged)
	New      bool   // a picture not identical to the newest one
	Changed  bool   // perceptually different from Previous (worth a change event)
	Distance int
}

// Store keeps screenshots encrypted at rest (AES-256-GCM under a KEK-derived key, like the
// file store snapshot), deduplicated by content and pruned to the last Keep per service.
// Layout: <dir>/index.enc (sealed JSON index) and <dir>/blobs/<id[:2]>/<id> (sealed JPEGs).
type Store struct {
	dir   string
	vault *crypto.Vault
	keep  int

	mu    sync.RWMutex
	index map[string][]Entry
}

// OpenStore opens (or creates) a screenshot store in dir.
func OpenStore(dir string, vault *crypto.Vault, keep int) (*Store, error) {
	if vault == nil {
		return nil, errors.New("screenshot store needs the vault")
	}
	if keep <= 0 {
		keep = DefaultKeep
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, vault: vault, keep: keep, index: make(map[string][]Entry)}
	raw, err := os.ReadFile(s.indexPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		plain, err := vault.OpenBlob(raw, indexAAD)
		if err != nil {
			return nil, fmt.Errorf("screenshot index: %w", err)
		}
		var doc struct {
			Services map[string][]Entry `json:"services"`
		}
		if err := json.Unmarshal(plain, &doc); err != nil {
			return nil, fmt.Errorf("screenshot index: %w", err)
		}
		if doc.Services != nil {
			s.index = doc.Services
		}
	}
	return s, nil
}

func (s *Store) indexPath() string { return filepath.Join(s.dir, "index.enc") }

func (s *Store) blobPath(id string) string {
	return filepath.Join(s.dir, "blobs", id[:2], id)
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

// blobID is a keyed hash of the content, so equal pictures dedupe and the id does not let
// anyone confirm a guessed image.
func (s *Store) blobID(b []byte) string {
	sum := sha256.Sum256(b)
	return s.vault.BlindIndex("screenshot:" + hex.EncodeToString(sum[:]))
}

func (s *Store) writeBlob(id string, data []byte) error {
	p := s.blobPath(id)
	if _, err := os.Stat(p); err == nil {
		return nil // content-addressed: already there
	}
	sealed, err := s.vault.SealBlob(data, "screenshot:"+id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return writeAtomic(p, sealed)
}

// Read returns the decrypted JPEG of a stored blob.
func (s *Store) Read(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrNotFound
	}
	raw, err := os.ReadFile(s.blobPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.vault.OpenBlob(raw, "screenshot:"+id)
}

// Put stores one capture for a service and persists the index.
func (s *Store) Put(k Key, shot *domain.Screenshot, scanRunID string) (PutResult, error) {
	res, err := s.PutBatch([]Item{{Key: k, Shot: shot}}, scanRunID)
	if err != nil {
		return PutResult{}, err
	}
	if len(res) == 0 || res[0].Err != nil {
		if len(res) > 0 {
			return PutResult{}, res[0].Err
		}
		return PutResult{}, errors.New("not stored")
	}
	return res[0].PutResult, nil
}

// Item is one capture to store.
type Item struct {
	Key  Key
	Shot *domain.Screenshot
}

// ItemResult is the outcome of one Item.
type ItemResult struct {
	PutResult
	Key Key
	Err error
}

// PutBatch stores several captures and writes the index once.
func (s *Store) PutBatch(items []Item, scanRunID string) ([]ItemResult, error) {
	out := make([]ItemResult, 0, len(items))
	s.mu.Lock()
	defer s.mu.Unlock()
	var orphans []string
	for _, it := range items {
		r := ItemResult{Key: it.Key.norm()}
		r.PutResult, r.Err = s.putLocked(r.Key, it.Shot, scanRunID, &orphans)
		out = append(out, r)
	}
	if err := s.saveLocked(); err != nil {
		return out, err
	}
	s.gcLocked(orphans)
	return out, nil
}

func (s *Store) putLocked(k Key, shot *domain.Screenshot, scanRunID string, orphans *[]string) (PutResult, error) {
	if shot == nil {
		return PutResult{}, errors.New("no screenshot")
	}
	if k.IP == "" || k.Port <= 0 || k.Port > 65535 {
		return PutResult{}, errors.New("bad service key")
	}
	w, h, err := Validate(shot.Image, shot.Thumb)
	if err != nil {
		return PutResult{}, err
	}
	at := shot.CapturedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	id, thumbID := s.blobID(shot.Image), s.blobID(shot.Thumb)
	key := k.String()
	list := s.index[key]
	if len(list) > 0 && list[0].ID == id {
		list[0].CapturedAt, list[0].ScanRunID = at, scanRunID
		if shot.Title != "" {
			list[0].Title = shot.Title
		}
		return PutResult{Entry: list[0]}, nil
	}
	if err := s.writeBlob(id, shot.Image); err != nil {
		return PutResult{}, err
	}
	if err := s.writeBlob(thumbID, shot.Thumb); err != nil {
		return PutResult{}, err
	}
	phash := shot.PHash
	if _, ok := ParseHash(phash); !ok {
		phash = ""
	}
	e := Entry{
		ID: id, Thumb: thumbID, Width: w, Height: h, Bytes: len(shot.Image), PHash: phash,
		URL: truncate(shot.URL, 2048), Title: truncate(shot.Title, 300),
		FirstSeen: at, CapturedAt: at, ScanRunID: scanRunID,
	}
	res := PutResult{Entry: e, New: true}
	if len(list) > 0 {
		prev := list[0]
		res.Previous = &prev
		a, okA := ParseHash(prev.PHash)
		b, okB := ParseHash(phash)
		if okA && okB {
			res.Distance = Distance(a, b)
			res.Changed = res.Distance >= ChangeDistance
		}
	}
	// Drop an older copy of the same picture (page flipped back), then prepend.
	kept := make([]Entry, 0, len(list)+1)
	kept = append(kept, e)
	for _, old := range list {
		if old.ID == id {
			kept[0].FirstSeen = old.FirstSeen
			if old.Thumb != thumbID {
				*orphans = append(*orphans, old.Thumb)
			}
			continue
		}
		kept = append(kept, old)
	}
	if len(kept) > s.keep {
		for _, old := range kept[s.keep:] {
			*orphans = append(*orphans, old.ID, old.Thumb)
		}
		kept = kept[:s.keep]
	}
	s.index[key] = kept
	return res, nil
}

// gcLocked deletes blobs no entry references any more.
func (s *Store) gcLocked(candidates []string) {
	if len(candidates) == 0 {
		return
	}
	used := make(map[string]bool)
	for _, list := range s.index {
		for _, e := range list {
			used[e.ID], used[e.Thumb] = true, true
		}
	}
	for _, id := range candidates {
		if !used[id] && validID(id) {
			_ = os.Remove(s.blobPath(id))
		}
	}
}

func (s *Store) saveLocked() error {
	plain, err := json.Marshal(struct {
		Version  int                `json:"version"`
		Services map[string][]Entry `json:"services"`
	}{1, s.index})
	if err != nil {
		return err
	}
	sealed, err := s.vault.SealBlob(plain, indexAAD)
	if err != nil {
		return err
	}
	return writeAtomic(s.indexPath(), sealed)
}

// History returns the stored screenshots of one service, newest first.
func (s *Store) History(k Key) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Entry(nil), s.index[k.String()]...)
}

// ForIP returns every service of one host that has screenshots.
func (s *Store) ForIP(ip string) []Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Service
	for key, list := range s.index {
		k, ok := parseKey(key)
		if !ok || k.IP != ip || len(list) == 0 {
			continue
		}
		out = append(out, Service{Key: k, Entries: append([]Entry(nil), list...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.Port < out[j].Key.Port })
	return out
}

// Latest returns the newest screenshot of every service, newest capture first.
func (s *Store) Latest() []Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Service, 0, len(s.index))
	for key, list := range s.index {
		k, ok := parseKey(key)
		if !ok || len(list) == 0 {
			continue
		}
		out = append(out, Service{Key: k, Entries: []Entry{list[0]}})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Entries[0].CapturedAt, out[j].Entries[0].CapturedAt
		if !a.Equal(b) {
			return a.After(b)
		}
		return out[i].Key.String() < out[j].Key.String()
	})
	return out
}

// Count is the number of services with at least one screenshot.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.index)
}

// Owns reports whether id is a blob referenced by the index (image endpoints serve only
// those).
func (s *Store) Owns(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, list := range s.index {
		for _, e := range list {
			if e.ID == id || e.Thumb == id {
				return true
			}
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}
