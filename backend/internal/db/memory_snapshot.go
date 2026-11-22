package db

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// memorySnapshotVersion is bumped on incompatible changes to memoryState.
const memorySnapshotVersion = 1

// memoryState is the serialisable form of MemoryStore. Every sensitive field inside the
// enc*Row types is ALREADY an AES-256-GCM envelope ciphertext (per-row DEK, AAD-bound),
// so this structure never holds plaintext IPs, hostnames, banners, e-mails or notes.
// FileStore additionally seals the whole serialised state with a KEK-derived key.
type memoryState struct {
	Version      int                                  `json:"version"`
	CryptoKeys   map[string]string                    `json:"crypto_keys"`
	ActiveKID    string                               `json:"active_kid"`
	Roles        map[string]domain.Role               `json:"roles"`
	Users        map[string]encUserRow                `json:"users"`
	Targets      map[string]domain.Target             `json:"targets"`
	Exclusions   map[string]domain.TargetExclusion    `json:"exclusions"`
	Profiles     map[string]domain.ScanProfile        `json:"profiles"`
	ScanRuns     map[string]encScanRunRow             `json:"scan_runs"`
	ScanChunks   map[string][]domain.ScanChunk        `json:"scan_chunks"`
	Hosts        map[string]encHostRow                `json:"hosts"`
	HostByIPHMAC map[string]string                    `json:"host_by_ip_hmac"`
	Services     map[string]encServiceRow             `json:"services"`
	Observations map[string][]encObservationRow       `json:"observations"`
	Overrides    map[string]map[string]encOverrideRow `json:"overrides"`
	Changes      map[string]encChangeRow              `json:"changes"`
	Snapshots    map[string]string                    `json:"snapshots"`
	Signatures   map[string]domain.Signature          `json:"signatures"`
	DDConfig     *encDDConfigRow                      `json:"dd_config,omitempty"`
	DDExports    []domain.DefectDojoExport            `json:"dd_exports"`
	AuditLogs    []domain.AuditLog                    `json:"audit_logs"`
	// Recurring-scan scheduler bookkeeping (last fire/skip per profile), so a restart
	// neither double-fires a missed run nor forgets the schedule anchor.
	ScheduleStates map[string]domain.ScheduleState `json:"schedule_states,omitempty"`
	// Encrypted settings documents (CIDR tag rules, alert webhook): key -> vault ciphertext.
	Settings map[string]string `json:"settings,omitempty"`
	// Per-host summaries of change events removed by retention (no sensitive fields).
	ChangeRollups map[string]domain.ChangeRollup `json:"change_rollups,omitempty"`
	// SnapshotFormat is snapshotFormatSlim when every scan snapshot is slim and compressed;
	// absent (0) in files written before, whose snapshots are migrated on the next compaction.
	SnapshotFormat int `json:"snapshot_format,omitempty"`
}

// snapshotFormatSlim marks stores whose scan snapshots are all SlimSnapshotHosts payloads.
const snapshotFormatSlim = 2

// unlockDirty releases the write lock and records that state may have changed.
// All mutating MemoryStore methods use it instead of m.mu.Unlock().
func (m *MemoryStore) unlockDirty() {
	m.generation++
	hook := m.onChange
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
}

// SetChangeHook registers fn to be called (outside the lock) after every write.
func (m *MemoryStore) SetChangeHook(fn func()) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

// Generation returns a counter incremented on every write.
func (m *MemoryStore) Generation() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.generation
}

// ExportState serialises the full (field-encrypted) store state to JSON together with the
// generation it corresponds to. The file store streams the same encoding with WriteState.
func (m *MemoryStore) ExportState() ([]byte, uint64, error) {
	var buf bytes.Buffer
	gen, err := m.WriteState(&buf)
	if err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), gen, nil
}

// ImportState replaces the store contents with a state produced by ExportState and
// returns the persisted wrapped DEKs (so the caller can load them into the Vault).
func (m *MemoryStore) ImportState(raw []byte) (map[string]string, string, error) {
	return m.ReadState(bytes.NewReader(raw))
}

// stateWriter emits the memoryState JSON object field by field. Large collections are
// written one entry at a time, so persisting the store never builds the whole encoding in
// memory (json.Marshal of the state used to cost as much heap as the state itself).
type stateWriter struct {
	bw    *bufio.Writer
	enc   *json.Encoder
	first bool
	err   error
}

func newStateWriter(w io.Writer) *stateWriter {
	bw := bufio.NewWriterSize(w, 256<<10)
	return &stateWriter{bw: bw, enc: json.NewEncoder(bw), first: true}
}

func (sw *stateWriter) raw(s string) {
	if sw.err == nil {
		_, sw.err = sw.bw.WriteString(s)
	}
}

func (sw *stateWriter) key(name string) {
	if !sw.first {
		sw.raw(",")
	}
	sw.first = false
	sw.raw(`"` + name + `":`) // field names are fixed identifiers, no escaping needed
}

// encode writes one JSON value (Encode appends a newline, which is valid whitespace).
func (sw *stateWriter) encode(v any) {
	if sw.err == nil {
		sw.err = sw.enc.Encode(v)
	}
}

func (sw *stateWriter) value(name string, v any) {
	sw.key(name)
	sw.encode(v)
}

func writeMap[V any](sw *stateWriter, name string, m map[string]V) {
	sw.key(name)
	if m == nil {
		sw.raw("null")
		return
	}
	sw.raw("{")
	first := true
	for k, v := range m {
		if !first {
			sw.raw(",")
		}
		first = false
		sw.encode(k)
		sw.raw(":")
		sw.encode(v)
		if sw.err != nil {
			return
		}
	}
	sw.raw("}")
}

func writeSlice[V any](sw *stateWriter, name string, s []V) {
	sw.key(name)
	if s == nil {
		sw.raw("null")
		return
	}
	sw.raw("[")
	for i := range s {
		if i > 0 {
			sw.raw(",")
		}
		sw.encode(&s[i])
		if sw.err != nil {
			return
		}
	}
	sw.raw("]")
}

// WriteState streams the full (field-encrypted) store state as JSON to w and returns the
// generation it corresponds to. The read lock is held while writing, so writers wait for it.
func (m *MemoryStore) WriteState(w io.Writer) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sw := newStateWriter(w)
	sw.raw("{")
	sw.value("version", memorySnapshotVersion)
	sw.value("crypto_keys", m.cryptoKeys)
	sw.value("active_kid", m.activeKID)
	sw.value("roles", m.roles)
	writeMap(sw, "users", m.users)
	sw.value("targets", m.targets)
	sw.value("exclusions", m.exclusions)
	sw.value("profiles", m.profiles)
	writeMap(sw, "scan_runs", m.scanRuns)
	writeMap(sw, "scan_chunks", m.scanChunks)
	writeMap(sw, "hosts", m.hosts)
	writeMap(sw, "host_by_ip_hmac", m.hostByIPHMAC)
	writeMap(sw, "services", m.services)
	writeMap(sw, "observations", m.observations)
	writeMap(sw, "overrides", m.overrides)
	writeMap(sw, "changes", m.changes)
	writeMap(sw, "snapshots", m.snapshots)
	writeMap(sw, "signatures", m.signatures)
	if m.ddConfig != nil {
		sw.value("dd_config", m.ddConfig)
	}
	writeSlice(sw, "dd_exports", m.ddExports)
	writeSlice(sw, "audit_logs", m.auditLogs)
	if len(m.scheduleStates) > 0 {
		sw.value("schedule_states", m.scheduleStates)
	}
	if len(m.settings) > 0 {
		writeMap(sw, "settings", m.settings)
	}
	if len(m.changeRollups) > 0 {
		writeMap(sw, "change_rollups", m.changeRollups)
	}
	if m.snapshotFormat != 0 {
		sw.value("snapshot_format", m.snapshotFormat)
	}
	sw.raw("}")
	if sw.err != nil {
		return 0, fmt.Errorf("marshal store state: %w", sw.err)
	}
	if err := sw.bw.Flush(); err != nil {
		return 0, fmt.Errorf("marshal store state: %w", err)
	}
	return m.generation, nil
}

// readMap decodes a JSON object (or null) into dst one entry at a time.
func readMap[V any](dec *json.Decoder, dst *map[string]V) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("expected an object, got %v", tok)
	}
	if *dst == nil {
		*dst = make(map[string]V)
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		k, ok := kt.(string)
		if !ok {
			return fmt.Errorf("expected an object key, got %v", kt)
		}
		var v V
		if err := dec.Decode(&v); err != nil {
			return err
		}
		(*dst)[k] = v
	}
	_, err = dec.Token() // '}'
	return err
}

// readSlice decodes a JSON array (or null) into dst one element at a time.
func readSlice[V any](dec *json.Decoder, dst *[]V) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("expected an array, got %v", tok)
	}
	for dec.More() {
		var v V
		if err := dec.Decode(&v); err != nil {
			return err
		}
		*dst = append(*dst, v)
	}
	_, err = dec.Token() // ']'
	return err
}

// decodeState reads a memoryState JSON object without buffering it whole: small fields are
// decoded directly, large collections entry by entry. Unknown fields are skipped.
func decodeState(r io.Reader) (*memoryState, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object, got %v", tok)
	}
	st := &memoryState{}
	small := map[string]any{
		"version": &st.Version, "crypto_keys": &st.CryptoKeys, "active_kid": &st.ActiveKID, "roles": &st.Roles,
		"targets": &st.Targets, "exclusions": &st.Exclusions, "profiles": &st.Profiles, "dd_config": &st.DDConfig,
		"schedule_states": &st.ScheduleStates, "snapshot_format": &st.SnapshotFormat,
	}
	large := map[string]func() error{
		"users":           func() error { return readMap(dec, &st.Users) },
		"scan_runs":       func() error { return readMap(dec, &st.ScanRuns) },
		"scan_chunks":     func() error { return readMap(dec, &st.ScanChunks) },
		"hosts":           func() error { return readMap(dec, &st.Hosts) },
		"host_by_ip_hmac": func() error { return readMap(dec, &st.HostByIPHMAC) },
		"services":        func() error { return readMap(dec, &st.Services) },
		"observations":    func() error { return readMap(dec, &st.Observations) },
		"overrides":       func() error { return readMap(dec, &st.Overrides) },
		"changes":         func() error { return readMap(dec, &st.Changes) },
		"snapshots":       func() error { return readMap(dec, &st.Snapshots) },
		"signatures":      func() error { return readMap(dec, &st.Signatures) },
		"settings":        func() error { return readMap(dec, &st.Settings) },
		"change_rollups":  func() error { return readMap(dec, &st.ChangeRollups) },
		"dd_exports":      func() error { return readSlice(dec, &st.DDExports) },
		"audit_logs":      func() error { return readSlice(dec, &st.AuditLogs) },
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, fmt.Errorf("expected a field name, got %v", kt)
		}
		switch {
		case large[key] != nil:
			err = large[key]()
		case small[key] != nil:
			err = dec.Decode(small[key])
		default:
			var skip json.RawMessage
			err = dec.Decode(&skip)
		}
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", key, err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return st, nil
}

// ReadState replaces the store contents with a state streamed from r (as written by
// WriteState or ExportState) and returns the persisted wrapped DEKs.
func (m *MemoryStore) ReadState(r io.Reader) (map[string]string, string, error) {
	st, err := decodeState(r)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshal store state: %w", err)
	}
	if st.Version != memorySnapshotVersion {
		return nil, "", fmt.Errorf("unsupported store snapshot version %d (this binary supports %d)", st.Version, memorySnapshotVersion)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cryptoKeys = orEmpty(st.CryptoKeys)
	m.activeKID = st.ActiveKID
	m.roles = orEmpty(st.Roles)
	m.users = orEmpty(st.Users)
	m.targets = orEmpty(st.Targets)
	m.exclusions = orEmpty(st.Exclusions)
	m.profiles = orEmpty(st.Profiles)
	m.scanRuns = orEmpty(st.ScanRuns)
	m.scanChunks = orEmpty(st.ScanChunks)
	m.hosts = orEmpty(st.Hosts)
	m.hostByIPHMAC = orEmpty(st.HostByIPHMAC)
	m.services = orEmpty(st.Services)
	m.observations = orEmpty(st.Observations)
	m.overrides = orEmpty(st.Overrides)
	m.changes = orEmpty(st.Changes)
	m.snapshots = orEmpty(st.Snapshots)
	m.signatures = orEmpty(st.Signatures)
	m.ddConfig = st.DDConfig
	m.ddExports = st.DDExports
	m.auditLogs = st.AuditLogs
	m.scheduleStates = st.ScheduleStates
	m.settings = st.Settings
	m.rebuildServiceIndexLocked()
	m.changeRollups = orEmpty(st.ChangeRollups)
	m.snapshotFormat = st.SnapshotFormat
	if len(m.snapshots) == 0 {
		m.snapshotFormat = snapshotFormatSlim // nothing to migrate
	}
	// Rebuild the blind-index lookup if an older snapshot lacked it.
	if len(m.hostByIPHMAC) == 0 && len(m.hosts) > 0 {
		for id, h := range m.hosts {
			m.hostByIPHMAC[h.IPHMAC] = id
		}
	}
	keys := make(map[string]string, len(m.cryptoKeys))
	for k, v := range m.cryptoKeys {
		keys[k] = v
	}
	return keys, m.activeKID, nil
}

func orEmpty[K comparable, V any](in map[K]V) map[K]V {
	if in == nil {
		return make(map[K]V)
	}
	return in
}
