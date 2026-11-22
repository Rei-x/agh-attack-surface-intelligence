// Package vulndb cross-checks identified product versions against known vulnerabilities,
// fully offline at scan time.
//
// The data is a compact snapshot (snapshot.json.gz, embedded in the binary) built by
// `go run ./cmd/vulndb` from three public sources, filtered to the products Dzięcioł
// fingerprints (Catalog):
//
//   - NVD CVE API 2.0: the CPE configurations of every CVE for the catalog's vendor:product
//     pairs, reduced to affected version ranges, plus CVSS (v3.1, v3.0, v4.0, v2 in that
//     order), severity, CWE and a short description;
//   - CISA KEV: the catalog of vulnerabilities known to be exploited in the wild;
//   - FIRST EPSS: the probability of exploitation in the next 30 days and its percentile.
//
// `dzieciol vulndb update` refreshes the snapshot into the data directory; the server picks
// the newest of the embedded and the refreshed snapshot. Nothing is fetched during a scan.
package vulndb

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

//go:embed snapshot.json.gz
var embedded []byte

// CVE is one vulnerability record of the snapshot (short JSON keys keep the file small).
type CVE struct {
	ID          string  `json:"id"`
	CVSS        float64 `json:"s,omitempty"`
	CVSSVersion string  `json:"sv,omitempty"`
	Severity    string  `json:"sev,omitempty"` // CRITICAL, HIGH, MEDIUM, LOW, NONE
	Published   string  `json:"p,omitempty"`   // YYYY-MM-DD
	CWE         string  `json:"cwe,omitempty"`
	Summary     string  `json:"d,omitempty"`
	KEVAdded    string  `json:"k,omitempty"` // YYYY-MM-DD the CVE entered CISA KEV, "" = not in KEV
	Ransomware  bool    `json:"kr,omitempty"`
	EPSS        float64 `json:"e,omitempty"`
	EPSSPct     float64 `json:"ep,omitempty"`
	// Requires is a protocol the vulnerable code needs enabled ("http2", "http3", "" = none
	// known), tagged from the description and the explicit table (preconditions.go).
	Requires string `json:"rq,omitempty"`
}

// Affected lists a CVE's affected version ranges for one product.
type Affected struct {
	CVE    string  `json:"c"`
	Ranges []Range `json:"r"`
}

// Sources records where and when each part of the snapshot came from.
type Sources struct {
	NVD         string `json:"nvd"`
	NVDFetched  string `json:"nvd_fetched"`
	KEV         string `json:"kev"`
	KEVVersion  string `json:"kev_version"`
	KEVCount    int    `json:"kev_count"`
	EPSS        string `json:"epss"`
	EPSSModel   string `json:"epss_model"`
	EPSSDate    string `json:"epss_date"`
	ProductsCPE int    `json:"products_cpe"`
}

// Snapshot is the serialised database.
type Snapshot struct {
	Schema      int                   `json:"schema"`
	GeneratedAt string                `json:"generated_at"` // RFC 3339
	Sources     Sources               `json:"sources"`
	CVEs        []CVE                 `json:"cves"`
	Products    map[string][]Affected `json:"products"` // catalog key -> affected CVEs

	byID map[string]*CVE
}

// SchemaVersion is the snapshot format version this build reads.
const SchemaVersion = 1

// DB is a loaded snapshot with its indexes and a per (product, version) match cache.
type DB struct {
	snap   *Snapshot
	origin string // "embedded" or the file path

	mu    sync.RWMutex
	cache map[string][]Hit
}

// Hit is a CVE matched to an observed version.
type Hit struct {
	CVE      *CVE
	Possible bool   // incomplete version: may or may not be affected
	Range    string // matching range, for evidence
}

// Parse decodes a (gzip-compressed or plain) snapshot.
func Parse(raw []byte) (*Snapshot, error) {
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		if raw, err = io.ReadAll(zr); err != nil {
			return nil, err
		}
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.Schema != SchemaVersion {
		return nil, fmt.Errorf("vulndb: snapshot schema %d, this build reads %d", s.Schema, SchemaVersion)
	}
	s.index()
	return &s, nil
}

func (s *Snapshot) index() {
	s.byID = make(map[string]*CVE, len(s.CVEs))
	for i := range s.CVEs {
		s.byID[s.CVEs[i].ID] = &s.CVEs[i]
	}
}

// Encode serialises a snapshot gzip-compressed (deterministic order).
func (s *Snapshot) Encode() ([]byte, error) {
	sort.Slice(s.CVEs, func(i, j int) bool { return s.CVEs[i].ID < s.CVEs[j].ID })
	for k := range s.Products {
		list := s.Products[k]
		sort.Slice(list, func(i, j int) bool { return list[i].CVE < list[j].CVE })
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// New wraps a parsed snapshot.
func New(s *Snapshot, origin string) *DB {
	if s.byID == nil {
		s.index()
	}
	return &DB{snap: s, origin: origin, cache: map[string][]Hit{}}
}

// Snapshot returns the underlying data (read-only).
func (d *DB) Snapshot() *Snapshot { return d.snap }

// CVE returns one record by id.
func (d *DB) CVE(id string) *CVE { return d.snap.byID[id] }

// Info summarises the loaded snapshot for the UI and the CLI.
type Info struct {
	Origin      string  `json:"origin"`
	GeneratedAt string  `json:"generated_at"`
	CVEs        int     `json:"cves"`
	KEV         int     `json:"kev"`
	Products    int     `json:"products"`
	Sources     Sources `json:"sources"`
}

// Info describes the snapshot.
func (d *DB) Info() Info {
	kev := 0
	for i := range d.snap.CVEs {
		if d.snap.CVEs[i].KEVAdded != "" {
			kev++
		}
	}
	return Info{Origin: d.origin, GeneratedAt: d.snap.GeneratedAt, CVEs: len(d.snap.CVEs), KEV: kev, Products: len(d.snap.Products), Sources: d.snap.Sources}
}

// Lookup returns the CVEs affecting product (catalog key) at version, KEV first, then by
// EPSS and CVSS. Results are cached.
func (d *DB) Lookup(productKey, version string) []Hit {
	nv := normalizeVersion(version)
	if nv == "" {
		return nil
	}
	ck := productKey + "\x00" + nv
	d.mu.RLock()
	hits, ok := d.cache[ck]
	d.mu.RUnlock()
	if ok {
		return hits
	}
	def := defByKey(productKey)
	full := 3
	if def != nil {
		full = def.FullParts
	}
	for _, a := range d.snap.Products[productKey] {
		c := d.snap.byID[a.CVE]
		if c == nil {
			continue
		}
		best, rng := NoMatch, ""
		for _, r := range a.Ranges {
			if m := r.matchVersion(nv, full); m > best {
				best, rng = m, r.String()
				if m == Match {
					break
				}
			}
		}
		if best != NoMatch {
			hits = append(hits, Hit{CVE: c, Possible: best == PossibleMatch, Range: rng})
		}
	}
	sortHits(hits)
	d.mu.Lock()
	if len(d.cache) > 4096 {
		d.cache = map[string][]Hit{}
	}
	d.cache[ck] = hits
	d.mu.Unlock()
	return hits
}

// sortHits orders by: definite before possible, KEV, EPSS, CVSS, newest id.
func sortHits(h []Hit) {
	sort.SliceStable(h, func(i, j int) bool {
		a, b := h[i], h[j]
		if a.Possible != b.Possible {
			return !a.Possible
		}
		if (a.CVE.KEVAdded != "") != (b.CVE.KEVAdded != "") {
			return a.CVE.KEVAdded != ""
		}
		if a.CVE.EPSS != b.CVE.EPSS {
			return a.CVE.EPSS > b.CVE.EPSS
		}
		if a.CVE.CVSS != b.CVE.CVSS {
			return a.CVE.CVSS > b.CVE.CVSS
		}
		return a.CVE.ID > b.CVE.ID
	})
}

// ---- process-wide database -------------------------------------------------------------

var (
	curMu       sync.RWMutex
	cur         *DB
	overlayPath string
	overlayMod  time.Time
	lastCheck   time.Time
)

// SetOverlayPath registers the refreshed snapshot written by `dzieciol vulndb update`
// (<data dir>/vulndb.json.gz). It is used instead of the embedded one when it is newer, and
// re-read when the file changes (checked at most once a minute).
func SetOverlayPath(path string) {
	curMu.Lock()
	overlayPath, overlayMod, lastCheck = path, time.Time{}, time.Time{}
	curMu.Unlock()
}

// Current returns the active database (embedded snapshot unless a newer overlay exists).
func Current() *DB {
	curMu.RLock()
	d, path, check := cur, overlayPath, lastCheck
	curMu.RUnlock()
	if d != nil && (path == "" || time.Since(check) < time.Minute) {
		return d
	}
	curMu.Lock()
	defer curMu.Unlock()
	if cur == nil {
		s, err := Parse(embedded)
		if err != nil {
			// A broken embedded snapshot is a build bug; serve an empty database rather than panic.
			s = &Snapshot{Schema: SchemaVersion, Products: map[string][]Affected{}}
			s.index()
		}
		cur = New(s, "embedded")
	}
	if overlayPath != "" && time.Since(lastCheck) >= time.Minute {
		lastCheck = time.Now()
		if st, err := os.Stat(overlayPath); err == nil && !st.ModTime().Equal(overlayMod) {
			overlayMod = st.ModTime()
			if raw, err := os.ReadFile(overlayPath); err == nil {
				if s, err := Parse(raw); err == nil && s.GeneratedAt >= cur.snap.GeneratedAt {
					cur = New(s, overlayPath)
				}
			}
		}
	}
	return cur
}

// SetCurrent replaces the active database (tests).
func SetCurrent(d *DB) {
	curMu.Lock()
	cur, overlayPath = d, ""
	curMu.Unlock()
}
