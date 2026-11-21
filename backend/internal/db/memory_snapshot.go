package db

import (
	"encoding/json"
	"fmt"

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
}

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
// generation it corresponds to.
func (m *MemoryStore) ExportState() ([]byte, uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := memoryState{
		Version:      memorySnapshotVersion,
		CryptoKeys:   m.cryptoKeys,
		ActiveKID:    m.activeKID,
		Roles:        m.roles,
		Users:        m.users,
		Targets:      m.targets,
		Exclusions:   m.exclusions,
		Profiles:     m.profiles,
		ScanRuns:     m.scanRuns,
		ScanChunks:   m.scanChunks,
		Hosts:        m.hosts,
		HostByIPHMAC: m.hostByIPHMAC,
		Services:     m.services,
		Observations: m.observations,
		Overrides:    m.overrides,
		Changes:      m.changes,
		Snapshots:    m.snapshots,
		Signatures:   m.signatures,
		DDConfig:     m.ddConfig,
		DDExports:    m.ddExports,
		AuditLogs:    m.auditLogs,
	}
	raw, err := json.Marshal(&st)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal store state: %w", err)
	}
	return raw, m.generation, nil
}

// ImportState replaces the store contents with a state produced by ExportState and
// returns the persisted wrapped DEKs (so the caller can load them into the Vault).
func (m *MemoryStore) ImportState(raw []byte) (map[string]string, string, error) {
	var st memoryState
	if err := json.Unmarshal(raw, &st); err != nil {
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
