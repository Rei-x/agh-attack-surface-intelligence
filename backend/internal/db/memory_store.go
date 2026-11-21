package db

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

type encUserRow struct {
	ID           string
	Username     string
	EmailEnc     string
	PasswordHash string
	RoleID       string
	Active       bool
	CreatedAt    time.Time
}

type encHostRow struct {
	ID                 string
	IPHMAC             string
	IPEnc              string
	HostnameEnc        string
	DomainsEnc         string
	OSGuessEnc         string
	LifecycleState     string
	Environment        string
	Owner              string
	NotesEnc           string
	Tags               []string
	FirstSeen          time.Time
	LastSeen           time.Time
	TotalScansSeen     int
	TotalScansChecked  int
	ConsecutiveMisses  int
	StateTransitions   int
	StabilityScore     int
	Interestingness    int
	InterestingFactors []domain.InterestingnessFactor
	TimeOfDayStats     []domain.TimeSlotStat
}

type encServiceRow struct {
	ID                 string
	HostID             string
	Port               int
	Protocol           string
	State              string
	ServiceName        string
	Product            string
	Version            string
	CPE                string
	BannerEnc          string
	HTTPEnc            string
	Technologies       []domain.DetectedTechnology
	MatchedSignatures  []string
	IsAdminPanel       bool
	IsStagingEnv       bool
	IsIoT              bool
	ClusterKey         string
	Interestingness    int
	InterestingFactors []domain.InterestingnessFactor
	TriageStatus       string
	NotesEnc           string
	Tags               []string
	FirstSeen          time.Time
	LastSeen           time.Time
}

type encObservationRow struct {
	ID          string
	ScanRunID   string
	HostID      string
	ServiceID   string
	Port        int
	Protocol    string
	State       string
	ServiceName string
	Product     string
	Version     string
	BannerEnc   string
	HTTPEnc     string
	ObservedAt  time.Time
}

type encOverrideRow struct {
	EntityType string
	EntityID   string
	Field      string
	ValueEnc   string
	UpdatedBy  string
	UpdatedAt  time.Time
}

type encScanRunRow struct {
	ID                string
	ProfileID         string
	Name              string
	RunType           string
	Status            string
	NotesEnc          string
	TotalIPs          int
	ScannedIPs        int
	TotalChunks       int
	CompletedChunks   int
	ActiveHosts       int
	ServicesFound     int
	ChangesDetected   int
	HostsPerSec       float64
	ETASeconds        int64
	DurationMs        int64
	WindowPausedCount int
	RawNmapXMLEnc     string
	HasRawNmapXML     bool
	TriggeredBy       string
	StartedAt         time.Time
	FinishedAt        *time.Time
}

type encChangeRow struct {
	ID                 string
	ScanRunID          string
	PrevScanRunID      string
	HostID             string
	HostIPEnc          string
	ServiceID          string
	Port               int
	EventType          string
	Severity           string
	Summary            string
	TimeSlot           string
	IsExpectedSchedule bool
	IsTimeAnomaly      bool
	BeforeEnc          string
	AfterEnc           string
	AcknowledgedBy     string
	AcknowledgedAt     *time.Time
	CreatedAt          time.Time
}

type encDDConfigRow struct {
	URL          string
	APITokenEnc  string
	ProductID    int
	EngagementID int
	VerifyTLS    bool
	AutoPushNmap bool
}

// MemoryStore is a full in-memory Store that encrypts every sensitive field at rest
// with *crypto.Vault (AES-256-GCM + AAD + HMAC-SHA256 blind indexes).
type MemoryStore struct {
	mu    sync.RWMutex
	vault *crypto.Vault

	cryptoKeys   map[string]string
	activeKID    string
	roles        map[string]domain.Role
	users        map[string]encUserRow
	targets      map[string]domain.Target
	exclusions   map[string]domain.TargetExclusion
	profiles     map[string]domain.ScanProfile
	scanRuns     map[string]encScanRunRow
	scanChunks   map[string][]domain.ScanChunk
	hosts        map[string]encHostRow
	hostByIPHMAC map[string]string
	services     map[string]encServiceRow
	observations map[string][]encObservationRow // keyed by serviceID
	overrides    map[string]map[string]encOverrideRow
	changes      map[string]encChangeRow
	snapshots    map[string]string // scanRunID -> encrypted JSON
	signatures   map[string]domain.Signature
	ddConfig     *encDDConfigRow
	ddExports    []domain.DefectDojoExport
	auditLogs    []domain.AuditLog

	scheduleStates map[string]domain.ScheduleState // lazily initialized (schedule_state.go)
	// Change tracking for the encrypted file-backed store (see memory_snapshot.go).
	generation uint64
	onChange   func()
}

func NewMemoryStore(vault *crypto.Vault) *MemoryStore {
	wrapped, active := vault.ExportWrappedDEKs()
	return &MemoryStore{
		vault:        vault,
		cryptoKeys:   wrapped,
		activeKID:    active,
		roles:        make(map[string]domain.Role),
		users:        make(map[string]encUserRow),
		targets:      make(map[string]domain.Target),
		exclusions:   make(map[string]domain.TargetExclusion),
		profiles:     make(map[string]domain.ScanProfile),
		scanRuns:     make(map[string]encScanRunRow),
		scanChunks:   make(map[string][]domain.ScanChunk),
		hosts:        make(map[string]encHostRow),
		hostByIPHMAC: make(map[string]string),
		services:     make(map[string]encServiceRow),
		observations: make(map[string][]encObservationRow),
		overrides:    make(map[string]map[string]encOverrideRow),
		changes:      make(map[string]encChangeRow),
		snapshots:    make(map[string]string),
		signatures:   make(map[string]domain.Signature),
	}
}

func (m *MemoryStore) Ping(_ context.Context) error { return nil }
func (m *MemoryStore) Close()                       {}
func (m *MemoryStore) BackendName() string          { return "memory-encrypted" }

func (m *MemoryStore) LoadCryptoKeys(_ context.Context) (map[string]string, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.cryptoKeys))
	for k, v := range m.cryptoKeys {
		out[k] = v
	}
	return out, m.activeKID, nil
}

func (m *MemoryStore) SaveCryptoKey(_ context.Context, kid, wrapped string, active bool) error {
	m.mu.Lock()
	defer m.unlockDirty()
	m.cryptoKeys[kid] = wrapped
	if active {
		m.activeKID = kid
	}
	return nil
}

func (m *MemoryStore) ReEncryptAll(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.unlockDirty()
	count := 0
	reenc := func(ct, aad string) (string, error) {
		n, changed, err := m.vault.ReEncrypt(ct, aad)
		if err != nil {
			return "", err
		}
		if changed {
			count++
		}
		return n, nil
	}

	for id, u := range m.users {
		var err error
		if u.EmailEnc, err = reenc(u.EmailEnc, "users:"+id+":email"); err != nil {
			return count, err
		}
		m.users[id] = u
	}
	for id, h := range m.hosts {
		var err error
		if h.IPEnc, err = reenc(h.IPEnc, "hosts:"+id+":ip"); err != nil {
			return count, err
		}
		if h.HostnameEnc, err = reenc(h.HostnameEnc, "hosts:"+id+":hostname"); err != nil {
			return count, err
		}
		if h.DomainsEnc, err = reenc(h.DomainsEnc, "hosts:"+id+":domains"); err != nil {
			return count, err
		}
		if h.OSGuessEnc, err = reenc(h.OSGuessEnc, "hosts:"+id+":os_guess"); err != nil {
			return count, err
		}
		if h.NotesEnc, err = reenc(h.NotesEnc, "hosts:"+id+":notes"); err != nil {
			return count, err
		}
		m.hosts[id] = h
	}
	for id, s := range m.services {
		var err error
		if s.BannerEnc, err = reenc(s.BannerEnc, "services:"+id+":banner"); err != nil {
			return count, err
		}
		if s.HTTPEnc, err = reenc(s.HTTPEnc, "services:"+id+":http"); err != nil {
			return count, err
		}
		if s.NotesEnc, err = reenc(s.NotesEnc, "services:"+id+":notes"); err != nil {
			return count, err
		}
		m.services[id] = s
	}
	for svcID, obsList := range m.observations {
		for i := range obsList {
			var err error
			if obsList[i].BannerEnc, err = reenc(obsList[i].BannerEnc, "service_observations:"+obsList[i].ID+":banner"); err != nil {
				return count, err
			}
			if obsList[i].HTTPEnc, err = reenc(obsList[i].HTTPEnc, "service_observations:"+obsList[i].ID+":http"); err != nil {
				return count, err
			}
		}
		m.observations[svcID] = obsList
	}
	for ek, fields := range m.overrides {
		for f, row := range fields {
			var err error
			aad := "asset_overrides:" + row.EntityType + ":" + row.EntityID + ":" + row.Field
			if row.ValueEnc, err = reenc(row.ValueEnc, aad); err != nil {
				return count, err
			}
			fields[f] = row
		}
		m.overrides[ek] = fields
	}
	for id, run := range m.scanRuns {
		var err error
		if run.NotesEnc, err = reenc(run.NotesEnc, "scan_runs:"+id+":notes"); err != nil {
			return count, err
		}
		if run.RawNmapXMLEnc, err = reenc(run.RawNmapXMLEnc, "scan_runs:"+id+":raw_nmap_xml"); err != nil {
			return count, err
		}
		m.scanRuns[id] = run
	}
	for id, ev := range m.changes {
		var err error
		if ev.HostIPEnc, err = reenc(ev.HostIPEnc, "change_events:"+id+":host_ip"); err != nil {
			return count, err
		}
		if ev.BeforeEnc, err = reenc(ev.BeforeEnc, "change_events:"+id+":before"); err != nil {
			return count, err
		}
		if ev.AfterEnc, err = reenc(ev.AfterEnc, "change_events:"+id+":after"); err != nil {
			return count, err
		}
		m.changes[id] = ev
	}
	for id, snap := range m.snapshots {
		var err error
		if m.snapshots[id], err = reenc(snap, "scan_snapshots:"+id+":payload"); err != nil {
			return count, err
		}
	}
	if m.ddConfig != nil && m.ddConfig.APITokenEnc != "" {
		var err error
		if m.ddConfig.APITokenEnc, err = reenc(m.ddConfig.APITokenEnc, "defectdojo_config:default:api_token"); err != nil {
			return count, err
		}
	}
	return count, nil
}

func (m *MemoryStore) GetCryptoProofSample(_ context.Context) (*CryptoProofSample, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, h := range m.hosts {
		if h.IPEnc != "" {
			aad := "hosts:" + id + ":ip"
			plain, err := m.vault.Decrypt(h.IPEnc, aad)
			if err != nil {
				return nil, err
			}
			return &CryptoProofSample{
				Table:           "hosts",
				RecordID:        id,
				Column:          "ip_enc",
				AAD:             aad,
				RawCiphertext:   h.IPEnc,
				DecryptedSample: plain,
				BlindIndexCol:   "ip_hmac",
				BlindIndexValue: h.IPHMAC,
			}, nil
		}
	}
	for id, u := range m.users {
		if u.EmailEnc != "" {
			aad := "users:" + id + ":email"
			plain, err := m.vault.Decrypt(u.EmailEnc, aad)
			if err != nil {
				return nil, err
			}
			return &CryptoProofSample{
				Table:           "users",
				RecordID:        id,
				Column:          "email_enc",
				AAD:             aad,
				RawCiphertext:   u.EmailEnc,
				DecryptedSample: plain,
			}, nil
		}
	}
	// Synthetic self-test proof if store has no rows yet
	aad := "crypto_self_test:sample:payload"
	sample := "172.28.0.10"
	ct, err := m.vault.Encrypt(sample, aad)
	if err != nil {
		return nil, err
	}
	return &CryptoProofSample{
		Table:           "crypto_self_test",
		RecordID:        "sample",
		Column:          "payload",
		AAD:             aad,
		RawCiphertext:   ct,
		DecryptedSample: sample,
		BlindIndexCol:   "ip_hmac",
		BlindIndexValue: m.vault.BlindIndex(sample),
	}, nil
}

// RawHostIPCiphertext returns the encrypted ip_enc stored for hostID (used in tests).
func (m *MemoryStore) RawHostIPCiphertext(hostID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hosts[hostID].IPEnc
}

// --- Roles & Users ---

func (m *MemoryStore) ListRoles(_ context.Context) ([]domain.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Role, 0, len(m.roles))
	for _, r := range m.roles {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) GetRole(_ context.Context, id string) (*domain.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.roles[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}

func (m *MemoryStore) GetRoleBySlug(_ context.Context, slug string) (*domain.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.roles {
		if r.Slug == slug {
			cp := r
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) CreateRole(_ context.Context, role *domain.Role) error {
	m.mu.Lock()
	defer m.unlockDirty()
	for _, r := range m.roles {
		if r.Slug == role.Slug {
			return ErrConflict
		}
	}
	if role.ID == "" {
		role.ID = NewID()
	}
	if role.CreatedAt.IsZero() {
		role.CreatedAt = time.Now().UTC()
	}
	m.roles[role.ID] = *role
	return nil
}

func (m *MemoryStore) UpdateRole(_ context.Context, role *domain.Role) error {
	m.mu.Lock()
	defer m.unlockDirty()
	existing, ok := m.roles[role.ID]
	if !ok {
		return ErrNotFound
	}
	existing.Name = role.Name
	existing.Description = role.Description
	existing.Permissions = append([]string(nil), role.Permissions...)
	if role.Slug != "" && !existing.IsSystem {
		existing.Slug = role.Slug
	}
	m.roles[role.ID] = existing
	*role = existing
	return nil
}

func (m *MemoryStore) DeleteRole(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.unlockDirty()
	r, ok := m.roles[id]
	if !ok {
		return ErrNotFound
	}
	if r.IsSystem {
		return fmt.Errorf("cannot delete system role %s", r.Slug)
	}
	delete(m.roles, id)
	return nil
}

func (m *MemoryStore) decryptUserLocked(row encUserRow) (*domain.User, error) {
	email, err := m.vault.Decrypt(row.EmailEnc, "users:"+row.ID+":email")
	if err != nil {
		return nil, err
	}
	role := m.roles[row.RoleID]
	return &domain.User{
		ID:           row.ID,
		Username:     row.Username,
		Email:        email,
		PasswordHash: row.PasswordHash,
		RoleID:       row.RoleID,
		RoleSlug:     role.Slug,
		RoleName:     role.Name,
		Permissions:  append([]string(nil), role.Permissions...),
		Active:       row.Active,
		CreatedAt:    row.CreatedAt,
	}, nil
}

func (m *MemoryStore) ListUsers(_ context.Context) ([]domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.User, 0, len(m.users))
	for _, row := range m.users {
		u, err := m.decryptUserLocked(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) GetUser(_ context.Context, id string) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	row, ok := m.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return m.decryptUserLocked(row)
}

func (m *MemoryStore) GetUserByUsername(_ context.Context, username string) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, row := range m.users {
		if strings.EqualFold(row.Username, username) {
			return m.decryptUserLocked(row)
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) CreateUser(_ context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.unlockDirty()
	for _, row := range m.users {
		if strings.EqualFold(row.Username, user.Username) {
			return ErrConflict
		}
	}
	if user.ID == "" {
		user.ID = NewID()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	emailEnc, err := m.vault.Encrypt(user.Email, "users:"+user.ID+":email")
	if err != nil {
		return err
	}
	m.users[user.ID] = encUserRow{
		ID:           user.ID,
		Username:     user.Username,
		EmailEnc:     emailEnc,
		PasswordHash: user.PasswordHash,
		RoleID:       user.RoleID,
		Active:       user.Active,
		CreatedAt:    user.CreatedAt,
	}
	if role, ok := m.roles[user.RoleID]; ok {
		user.RoleSlug = role.Slug
		user.RoleName = role.Name
		user.Permissions = append([]string(nil), role.Permissions...)
	}
	return nil
}

func (m *MemoryStore) UpdateUser(_ context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.unlockDirty()
	row, ok := m.users[user.ID]
	if !ok {
		return ErrNotFound
	}
	if user.Email != "" {
		enc, err := m.vault.Encrypt(user.Email, "users:"+user.ID+":email")
		if err != nil {
			return err
		}
		row.EmailEnc = enc
	}
	if user.PasswordHash != "" {
		row.PasswordHash = user.PasswordHash
	}
	if user.RoleID != "" {
		row.RoleID = user.RoleID
	}
	row.Active = user.Active
	m.users[user.ID] = row
	return nil
}

func (m *MemoryStore) DeleteUser(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if _, ok := m.users[id]; !ok {
		return ErrNotFound
	}
	delete(m.users, id)
	return nil
}

// --- Targets & Exclusions ---

func (m *MemoryStore) ListTargets(_ context.Context) ([]domain.Target, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Target, 0, len(m.targets))
	for _, t := range m.targets {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) CreateTarget(_ context.Context, t *domain.Target) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if t.ID == "" {
		t.ID = NewID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	m.targets[t.ID] = *t
	return nil
}

func (m *MemoryStore) DeleteTarget(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if _, ok := m.targets[id]; !ok {
		return ErrNotFound
	}
	delete(m.targets, id)
	return nil
}

func (m *MemoryStore) ListExclusions(_ context.Context) ([]domain.TargetExclusion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.TargetExclusion, 0, len(m.exclusions))
	for _, ex := range m.exclusions {
		out = append(out, ex)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) CreateExclusion(_ context.Context, ex *domain.TargetExclusion) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if ex.ID == "" {
		ex.ID = NewID()
	}
	if ex.CreatedAt.IsZero() {
		ex.CreatedAt = time.Now().UTC()
	}
	m.exclusions[ex.ID] = *ex
	return nil
}

func (m *MemoryStore) DeleteExclusion(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if _, ok := m.exclusions[id]; !ok {
		return ErrNotFound
	}
	delete(m.exclusions, id)
	return nil
}

// --- Scan Profiles ---

func (m *MemoryStore) ListProfiles(_ context.Context) ([]domain.ScanProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.ScanProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) GetProfile(_ context.Context, id string) (*domain.ScanProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.profiles[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &p, nil
}

func (m *MemoryStore) CreateProfile(_ context.Context, p *domain.ScanProfile) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if p.ID == "" {
		p.ID = NewID()
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	m.profiles[p.ID] = *p
	return nil
}

func (m *MemoryStore) UpdateProfile(_ context.Context, p *domain.ScanProfile) error {
	m.mu.Lock()
	defer m.unlockDirty()
	existing, ok := m.profiles[p.ID]
	if !ok {
		return ErrNotFound
	}
	p.CreatedAt = existing.CreatedAt
	p.UpdatedAt = time.Now().UTC()
	m.profiles[p.ID] = *p
	return nil
}

func (m *MemoryStore) DeleteProfile(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if _, ok := m.profiles[id]; !ok {
		return ErrNotFound
	}
	delete(m.profiles, id)
	return nil
}

// --- Scan Runs & Chunks ---

func (m *MemoryStore) decryptScanRunLocked(r encScanRunRow) (*domain.ScanRun, error) {
	notes, err := m.vault.Decrypt(r.NotesEnc, "scan_runs:"+r.ID+":notes")
	if err != nil {
		return nil, err
	}
	xmlData, err := m.vault.Decrypt(r.RawNmapXMLEnc, "scan_runs:"+r.ID+":raw_nmap_xml")
	if err != nil {
		return nil, err
	}
	return &domain.ScanRun{
		ID:                r.ID,
		ProfileID:         r.ProfileID,
		Name:              r.Name,
		RunType:           r.RunType,
		Status:            r.Status,
		Notes:             notes,
		TotalIPs:          r.TotalIPs,
		ScannedIPs:        r.ScannedIPs,
		TotalChunks:       r.TotalChunks,
		CompletedChunks:   r.CompletedChunks,
		ActiveHosts:       r.ActiveHosts,
		ServicesFound:     r.ServicesFound,
		ChangesDetected:   r.ChangesDetected,
		HostsPerSec:       r.HostsPerSec,
		ETASeconds:        r.ETASeconds,
		DurationMs:        r.DurationMs,
		WindowPausedCount: r.WindowPausedCount,
		RawNmapXML:        xmlData,
		HasRawNmapXML:     r.HasRawNmapXML || xmlData != "",
		TriggeredBy:       r.TriggeredBy,
		StartedAt:         r.StartedAt,
		FinishedAt:        r.FinishedAt,
	}, nil
}

func (m *MemoryStore) ListScanRuns(_ context.Context, limit int) ([]domain.ScanRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.ScanRun, 0, len(m.scanRuns))
	for _, r := range m.scanRuns {
		dec, err := m.decryptScanRunLocked(r)
		if err != nil {
			return nil, err
		}
		out = append(out, *dec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) GetScanRun(_ context.Context, id string) (*domain.ScanRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.scanRuns[id]
	if !ok {
		return nil, ErrNotFound
	}
	dec, err := m.decryptScanRunLocked(r)
	if err != nil {
		return nil, err
	}
	chunks := m.scanChunks[id]
	if len(chunks) > 0 {
		dec.Chunks = append([]domain.ScanChunk(nil), chunks...)
	}
	return dec, nil
}

func (m *MemoryStore) CreateScanRun(_ context.Context, run *domain.ScanRun) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if run.ID == "" {
		run.ID = NewID()
	}
	if run.StartedAt.IsZero() {
		run.StartedAt = time.Now().UTC()
	}
	notesEnc, err := m.vault.Encrypt(run.Notes, "scan_runs:"+run.ID+":notes")
	if err != nil {
		return err
	}
	xmlEnc, err := m.vault.Encrypt(run.RawNmapXML, "scan_runs:"+run.ID+":raw_nmap_xml")
	if err != nil {
		return err
	}
	m.scanRuns[run.ID] = encScanRunRow{
		ID:                run.ID,
		ProfileID:         run.ProfileID,
		Name:              run.Name,
		RunType:           run.RunType,
		Status:            run.Status,
		NotesEnc:          notesEnc,
		TotalIPs:          run.TotalIPs,
		ScannedIPs:        run.ScannedIPs,
		TotalChunks:       run.TotalChunks,
		CompletedChunks:   run.CompletedChunks,
		ActiveHosts:       run.ActiveHosts,
		ServicesFound:     run.ServicesFound,
		ChangesDetected:   run.ChangesDetected,
		HostsPerSec:       run.HostsPerSec,
		ETASeconds:        run.ETASeconds,
		DurationMs:        run.DurationMs,
		WindowPausedCount: run.WindowPausedCount,
		RawNmapXMLEnc:     xmlEnc,
		HasRawNmapXML:     run.RawNmapXML != "",
		TriggeredBy:       run.TriggeredBy,
		StartedAt:         run.StartedAt,
		FinishedAt:        run.FinishedAt,
	}
	return nil
}

func (m *MemoryStore) UpdateScanRun(_ context.Context, run *domain.ScanRun) error {
	m.mu.Lock()
	defer m.unlockDirty()
	existing, ok := m.scanRuns[run.ID]
	if !ok {
		return ErrNotFound
	}
	notesEnc, err := m.vault.Encrypt(run.Notes, "scan_runs:"+run.ID+":notes")
	if err != nil {
		return err
	}
	xmlEnc := existing.RawNmapXMLEnc
	hasXML := existing.HasRawNmapXML
	if run.RawNmapXML != "" {
		xmlEnc, err = m.vault.Encrypt(run.RawNmapXML, "scan_runs:"+run.ID+":raw_nmap_xml")
		if err != nil {
			return err
		}
		hasXML = true
	}
	m.scanRuns[run.ID] = encScanRunRow{
		ID:                run.ID,
		ProfileID:         run.ProfileID,
		Name:              run.Name,
		RunType:           run.RunType,
		Status:            run.Status,
		NotesEnc:          notesEnc,
		TotalIPs:          run.TotalIPs,
		ScannedIPs:        run.ScannedIPs,
		TotalChunks:       run.TotalChunks,
		CompletedChunks:   run.CompletedChunks,
		ActiveHosts:       run.ActiveHosts,
		ServicesFound:     run.ServicesFound,
		ChangesDetected:   run.ChangesDetected,
		HostsPerSec:       run.HostsPerSec,
		ETASeconds:        run.ETASeconds,
		DurationMs:        run.DurationMs,
		WindowPausedCount: run.WindowPausedCount,
		RawNmapXMLEnc:     xmlEnc,
		HasRawNmapXML:     hasXML,
		TriggeredBy:       run.TriggeredBy,
		StartedAt:         existing.StartedAt,
		FinishedAt:        run.FinishedAt,
	}
	return nil
}

func (m *MemoryStore) UpdateScanRunMeta(_ context.Context, id, name, notes string) (*domain.ScanRun, error) {
	m.mu.Lock()
	defer m.unlockDirty()
	row, ok := m.scanRuns[id]
	if !ok {
		return nil, ErrNotFound
	}
	if name != "" {
		row.Name = name
	}
	enc, err := m.vault.Encrypt(notes, "scan_runs:"+id+":notes")
	if err != nil {
		return nil, err
	}
	row.NotesEnc = enc
	m.scanRuns[id] = row
	return m.decryptScanRunLocked(row)
}

func (m *MemoryStore) DeleteScanRun(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if _, ok := m.scanRuns[id]; !ok {
		return ErrNotFound
	}
	delete(m.scanRuns, id)
	delete(m.scanChunks, id)
	delete(m.snapshots, id)
	return nil
}

func (m *MemoryStore) SaveScanChunks(_ context.Context, scanRunID string, chunks []domain.ScanChunk) error {
	m.mu.Lock()
	defer m.unlockDirty()
	cp := make([]domain.ScanChunk, len(chunks))
	for i, c := range chunks {
		if c.ID == "" {
			c.ID = NewID()
		}
		c.ScanRunID = scanRunID
		cp[i] = c
	}
	m.scanChunks[scanRunID] = cp
	return nil
}

func (m *MemoryStore) UpdateScanChunk(_ context.Context, chunk *domain.ScanChunk) error {
	m.mu.Lock()
	defer m.unlockDirty()
	list := m.scanChunks[chunk.ScanRunID]
	for i := range list {
		if list[i].ID == chunk.ID || list[i].ChunkIndex == chunk.ChunkIndex {
			list[i] = *chunk
			m.scanChunks[chunk.ScanRunID] = list
			return nil
		}
	}
	m.scanChunks[chunk.ScanRunID] = append(list, *chunk)
	return nil
}

func (m *MemoryStore) GetScanChunks(_ context.Context, scanRunID string) ([]domain.ScanChunk, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]domain.ScanChunk(nil), m.scanChunks[scanRunID]...), nil
}

// --- Hosts, Services, Observations & Overrides ---

func overrideKey(entityType, entityID string) string {
	return entityType + ":" + entityID
}

func (m *MemoryStore) getOverridesLocked(entityType, entityID string) (map[string]any, error) {
	fields := m.overrides[overrideKey(entityType, entityID)]
	if len(fields) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(fields))
	for f, row := range fields {
		var val any
		aad := "asset_overrides:" + entityType + ":" + entityID + ":" + f
		if err := m.vault.DecryptJSON(row.ValueEnc, aad, &val); err != nil {
			return nil, err
		}
		out[f] = val
	}
	return out, nil
}

func (m *MemoryStore) decryptServiceLocked(row encServiceRow, hostIP string) (*domain.Service, error) {
	banner, err := m.vault.Decrypt(row.BannerEnc, "services:"+row.ID+":banner")
	if err != nil {
		return nil, err
	}
	notes, err := m.vault.Decrypt(row.NotesEnc, "services:"+row.ID+":notes")
	if err != nil {
		return nil, err
	}
	var httpFP *domain.HTTPFingerprint
	if row.HTTPEnc != "" {
		var fp domain.HTTPFingerprint
		if err := m.vault.DecryptJSON(row.HTTPEnc, "services:"+row.ID+":http", &fp); err != nil {
			return nil, err
		}
		httpFP = &fp
	}
	svc := &domain.Service{
		ID:                 row.ID,
		HostID:             row.HostID,
		HostIP:             hostIP,
		Port:               row.Port,
		Protocol:           row.Protocol,
		State:              row.State,
		ServiceName:        row.ServiceName,
		Product:            row.Product,
		Version:            row.Version,
		CPE:                row.CPE,
		Banner:             banner,
		HTTP:               httpFP,
		Technologies:       append([]domain.DetectedTechnology(nil), row.Technologies...),
		MatchedSignatures:  append([]string(nil), row.MatchedSignatures...),
		IsAdminPanel:       row.IsAdminPanel,
		IsStagingEnv:       row.IsStagingEnv,
		IsIoT:              row.IsIoT,
		ClusterKey:         row.ClusterKey,
		Interestingness:    row.Interestingness,
		InterestingFactors: append([]domain.InterestingnessFactor(nil), row.InterestingFactors...),
		TriageStatus:       row.TriageStatus,
		Notes:              notes,
		Tags:               append([]string(nil), row.Tags...),
		FirstSeen:          row.FirstSeen,
		LastSeen:           row.LastSeen,
	}
	if svc.Technologies == nil {
		svc.Technologies = []domain.DetectedTechnology{}
	}
	if svc.MatchedSignatures == nil {
		svc.MatchedSignatures = []string{}
	}
	if svc.Tags == nil {
		svc.Tags = []string{}
	}
	ov, err := m.getOverridesLocked("service", svc.ID)
	if err != nil {
		return nil, err
	}
	MergeServiceWithOverrides(svc, ov)
	return svc, nil
}

func (m *MemoryStore) decryptHostLocked(row encHostRow, withServices bool) (*domain.Host, error) {
	ip, err := m.vault.Decrypt(row.IPEnc, "hosts:"+row.ID+":ip")
	if err != nil {
		return nil, err
	}
	hostname, err := m.vault.Decrypt(row.HostnameEnc, "hosts:"+row.ID+":hostname")
	if err != nil {
		return nil, err
	}
	var domains []string
	if row.DomainsEnc != "" {
		if err := m.vault.DecryptJSON(row.DomainsEnc, "hosts:"+row.ID+":domains", &domains); err != nil {
			return nil, err
		}
	}
	osGuess, err := m.vault.Decrypt(row.OSGuessEnc, "hosts:"+row.ID+":os_guess")
	if err != nil {
		return nil, err
	}
	notes, err := m.vault.Decrypt(row.NotesEnc, "hosts:"+row.ID+":notes")
	if err != nil {
		return nil, err
	}

	h := &domain.Host{
		ID:                 row.ID,
		IP:                 ip,
		Hostname:           hostname,
		Domains:            domains,
		OSGuess:            osGuess,
		LifecycleState:     row.LifecycleState,
		Environment:        row.Environment,
		Owner:              row.Owner,
		Notes:              notes,
		Tags:               append([]string(nil), row.Tags...),
		FirstSeen:          row.FirstSeen,
		LastSeen:           row.LastSeen,
		TotalScansSeen:     row.TotalScansSeen,
		TotalScansChecked:  row.TotalScansChecked,
		ConsecutiveMisses:  row.ConsecutiveMisses,
		StateTransitions:   row.StateTransitions,
		StabilityScore:     row.StabilityScore,
		Interestingness:    row.Interestingness,
		InterestingFactors: append([]domain.InterestingnessFactor(nil), row.InterestingFactors...),
		TimeOfDayStats:     append([]domain.TimeSlotStat(nil), row.TimeOfDayStats...),
	}
	if h.Tags == nil {
		h.Tags = []string{}
	}

	if withServices {
		svcs := make([]domain.Service, 0)
		for _, srow := range m.services {
			if srow.HostID == h.ID {
				s, err := m.decryptServiceLocked(srow, ip)
				if err != nil {
					return nil, err
				}
				svcs = append(svcs, *s)
			}
		}
		sort.Slice(svcs, func(i, j int) bool { return svcs[i].Port < svcs[j].Port })
		h.Services = svcs
		h.ServiceCount = len(svcs)
	}

	ov, err := m.getOverridesLocked("host", h.ID)
	if err != nil {
		return nil, err
	}
	MergeHostWithOverrides(h, ov)
	return h, nil
}

func (m *MemoryStore) ListHosts(_ context.Context, filter HostFilter) ([]domain.Host, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	matched := make([]domain.Host, 0, len(m.hosts))
	for _, row := range m.hosts {
		h, err := m.decryptHostLocked(row, true)
		if err != nil {
			return nil, 0, err
		}
		if matchesHostFilter(h, filter) {
			matched = append(matched, *h)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Interestingness != matched[j].Interestingness {
			return matched[i].Interestingness > matched[j].Interestingness
		}
		return matched[i].IP < matched[j].IP
	})
	total := len(matched)
	if filter.Limit > 0 {
		page := filter.Page
		if page < 1 {
			page = 1
		}
		start := (page - 1) * filter.Limit
		if start >= total {
			return []domain.Host{}, total, nil
		}
		end := start + filter.Limit
		if end > total {
			end = total
		}
		matched = matched[start:end]
	}
	return matched, total, nil
}

func (m *MemoryStore) GetHost(_ context.Context, id string) (*domain.Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	row, ok := m.hosts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return m.decryptHostLocked(row, true)
}

func (m *MemoryStore) GetHostByIP(_ context.Context, ip string) (*domain.Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hmacIdx := m.vault.BlindIndex(ip)
	id, ok := m.hostByIPHMAC[hmacIdx]
	if !ok {
		return nil, ErrNotFound
	}
	return m.decryptHostLocked(m.hosts[id], true)
}

func (m *MemoryStore) UpsertObservedHost(_ context.Context, host *domain.Host) (*domain.Host, error) {
	m.mu.Lock()
	defer m.unlockDirty()
	hmacIdx := m.vault.BlindIndex(host.IP)
	id, exists := m.hostByIPHMAC[hmacIdx]
	if !exists {
		if host.ID == "" {
			host.ID = NewID()
		}
		id = host.ID
	} else {
		host.ID = id
	}

	ipEnc, err := m.vault.Encrypt(host.IP, "hosts:"+id+":ip")
	if err != nil {
		return nil, err
	}
	hostnameEnc, err := m.vault.Encrypt(host.Hostname, "hosts:"+id+":hostname")
	if err != nil {
		return nil, err
	}
	domainsEnc, err := m.vault.EncryptJSON(host.Domains, "hosts:"+id+":domains")
	if err != nil {
		return nil, err
	}
	osEnc, err := m.vault.Encrypt(host.OSGuess, "hosts:"+id+":os_guess")
	if err != nil {
		return nil, err
	}
	notesEnc, err := m.vault.Encrypt(host.Notes, "hosts:"+id+":notes")
	if err != nil {
		return nil, err
	}

	m.hosts[id] = encHostRow{
		ID:                 id,
		IPHMAC:             hmacIdx,
		IPEnc:              ipEnc,
		HostnameEnc:        hostnameEnc,
		DomainsEnc:         domainsEnc,
		OSGuessEnc:         osEnc,
		LifecycleState:     host.LifecycleState,
		Environment:        host.Environment,
		Owner:              host.Owner,
		NotesEnc:           notesEnc,
		Tags:               append([]string(nil), host.Tags...),
		FirstSeen:          host.FirstSeen,
		LastSeen:           host.LastSeen,
		TotalScansSeen:     host.TotalScansSeen,
		TotalScansChecked:  host.TotalScansChecked,
		ConsecutiveMisses:  host.ConsecutiveMisses,
		StateTransitions:   host.StateTransitions,
		StabilityScore:     host.StabilityScore,
		Interestingness:    host.Interestingness,
		InterestingFactors: append([]domain.InterestingnessFactor(nil), host.InterestingFactors...),
		TimeOfDayStats:     append([]domain.TimeSlotStat(nil), host.TimeOfDayStats...),
	}
	m.hostByIPHMAC[hmacIdx] = id
	return m.decryptHostLocked(m.hosts[id], true)
}

func (m *MemoryStore) DeleteHost(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.unlockDirty()
	row, ok := m.hosts[id]
	if !ok {
		return ErrNotFound
	}
	delete(m.hosts, id)
	delete(m.hostByIPHMAC, row.IPHMAC)
	delete(m.overrides, overrideKey("host", id))
	for sid, s := range m.services {
		if s.HostID == id {
			delete(m.services, sid)
			delete(m.observations, sid)
			delete(m.overrides, overrideKey("service", sid))
		}
	}
	return nil
}

func (m *MemoryStore) ListServices(_ context.Context, filter ServiceFilter) ([]domain.Service, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Service, 0, len(m.services))
	for _, srow := range m.services {
		ip := ""
		if hrow, ok := m.hosts[srow.HostID]; ok {
			ip, _ = m.vault.Decrypt(hrow.IPEnc, "hosts:"+hrow.ID+":ip")
		}
		s, err := m.decryptServiceLocked(srow, ip)
		if err != nil {
			return nil, err
		}
		if matchesServiceFilter(s, filter) {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interestingness != out[j].Interestingness {
			return out[i].Interestingness > out[j].Interestingness
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}

func (m *MemoryStore) GetService(_ context.Context, id string) (*domain.Service, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	srow, ok := m.services[id]
	if !ok {
		return nil, ErrNotFound
	}
	ip := ""
	if hrow, ok := m.hosts[srow.HostID]; ok {
		ip, _ = m.vault.Decrypt(hrow.IPEnc, "hosts:"+hrow.ID+":ip")
	}
	return m.decryptServiceLocked(srow, ip)
}

func (m *MemoryStore) ListServicesByHost(ctx context.Context, hostID string) ([]domain.Service, error) {
	return m.ListServices(ctx, ServiceFilter{HostID: hostID})
}

func (m *MemoryStore) UpsertObservedService(_ context.Context, svc *domain.Service) (*domain.Service, error) {
	m.mu.Lock()
	defer m.unlockDirty()
	proto := svc.Protocol
	if proto == "" {
		proto = "tcp"
	}
	id := svc.ID
	for existingID, existing := range m.services {
		if existing.HostID == svc.HostID && existing.Port == svc.Port && existing.Protocol == proto {
			id = existingID
			if svc.FirstSeen.IsZero() {
				svc.FirstSeen = existing.FirstSeen
			}
			break
		}
	}
	if id == "" {
		id = NewID()
	}
	svc.ID = id
	svc.Protocol = proto

	bannerEnc, err := m.vault.Encrypt(svc.Banner, "services:"+id+":banner")
	if err != nil {
		return nil, err
	}
	httpEnc, err := m.vault.EncryptJSON(svc.HTTP, "services:"+id+":http")
	if err != nil {
		return nil, err
	}
	notesEnc, err := m.vault.Encrypt(svc.Notes, "services:"+id+":notes")
	if err != nil {
		return nil, err
	}
	triage := svc.TriageStatus
	if triage == "" {
		triage = "new"
	}

	m.services[id] = encServiceRow{
		ID:                 id,
		HostID:             svc.HostID,
		Port:               svc.Port,
		Protocol:           proto,
		State:              svc.State,
		ServiceName:        svc.ServiceName,
		Product:            svc.Product,
		Version:            svc.Version,
		CPE:                svc.CPE,
		BannerEnc:          bannerEnc,
		HTTPEnc:            httpEnc,
		Technologies:       append([]domain.DetectedTechnology(nil), svc.Technologies...),
		MatchedSignatures:  append([]string(nil), svc.MatchedSignatures...),
		IsAdminPanel:       svc.IsAdminPanel,
		IsStagingEnv:       svc.IsStagingEnv,
		IsIoT:              svc.IsIoT,
		ClusterKey:         svc.ClusterKey,
		Interestingness:    svc.Interestingness,
		InterestingFactors: append([]domain.InterestingnessFactor(nil), svc.InterestingFactors...),
		TriageStatus:       triage,
		NotesEnc:           notesEnc,
		Tags:               append([]string(nil), svc.Tags...),
		FirstSeen:          svc.FirstSeen,
		LastSeen:           svc.LastSeen,
	}
	ip := svc.HostIP
	if ip == "" {
		if hrow, ok := m.hosts[svc.HostID]; ok {
			ip, _ = m.vault.Decrypt(hrow.IPEnc, "hosts:"+hrow.ID+":ip")
		}
	}
	return m.decryptServiceLocked(m.services[id], ip)
}

func (m *MemoryStore) AddObservation(_ context.Context, obs *ServiceObservation) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if obs.ID == "" {
		obs.ID = NewID()
	}
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now().UTC()
	}
	bannerEnc, err := m.vault.Encrypt(obs.Banner, "service_observations:"+obs.ID+":banner")
	if err != nil {
		return err
	}
	httpEnc, err := m.vault.EncryptJSON(obs.HTTP, "service_observations:"+obs.ID+":http")
	if err != nil {
		return err
	}
	m.observations[obs.ServiceID] = append(m.observations[obs.ServiceID], encObservationRow{
		ID:          obs.ID,
		ScanRunID:   obs.ScanRunID,
		HostID:      obs.HostID,
		ServiceID:   obs.ServiceID,
		Port:        obs.Port,
		Protocol:    obs.Protocol,
		State:       obs.State,
		ServiceName: obs.ServiceName,
		Product:     obs.Product,
		Version:     obs.Version,
		BannerEnc:   bannerEnc,
		HTTPEnc:     httpEnc,
		ObservedAt:  obs.ObservedAt,
	})
	return nil
}

func (m *MemoryStore) ListServiceObservations(_ context.Context, serviceID string, limit int) ([]ServiceObservation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rows := m.observations[serviceID]
	out := make([]ServiceObservation, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		banner, err := m.vault.Decrypt(r.BannerEnc, "service_observations:"+r.ID+":banner")
		if err != nil {
			return nil, err
		}
		var fp *domain.HTTPFingerprint
		if r.HTTPEnc != "" {
			var tmp domain.HTTPFingerprint
			if err := m.vault.DecryptJSON(r.HTTPEnc, "service_observations:"+r.ID+":http", &tmp); err != nil {
				return nil, err
			}
			fp = &tmp
		}
		out = append(out, ServiceObservation{
			ID:          r.ID,
			ScanRunID:   r.ScanRunID,
			HostID:      r.HostID,
			ServiceID:   r.ServiceID,
			Port:        r.Port,
			Protocol:    r.Protocol,
			State:       r.State,
			ServiceName: r.ServiceName,
			Product:     r.Product,
			Version:     r.Version,
			Banner:      banner,
			HTTP:        fp,
			ObservedAt:  r.ObservedAt,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryStore) GetOverrides(_ context.Context, entityType, entityID string) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getOverridesLocked(entityType, entityID)
}

func (m *MemoryStore) PatchOverrides(_ context.Context, entityType, entityID string, patch map[string]any, unlockFields []string, updatedBy string) error {
	m.mu.Lock()
	defer m.unlockDirty()
	k := overrideKey(entityType, entityID)
	fields := m.overrides[k]
	if fields == nil {
		fields = make(map[string]encOverrideRow)
	}
	for _, uf := range unlockFields {
		delete(fields, uf)
	}
	now := time.Now().UTC()
	for field, val := range patch {
		aad := "asset_overrides:" + entityType + ":" + entityID + ":" + field
		enc, err := m.vault.EncryptJSON(val, aad)
		if err != nil {
			return err
		}
		fields[field] = encOverrideRow{
			EntityType: entityType,
			EntityID:   entityID,
			Field:      field,
			ValueEnc:   enc,
			UpdatedBy:  updatedBy,
			UpdatedAt:  now,
		}
	}
	m.overrides[k] = fields
	return nil
}

// --- Changes & Snapshots ---

func (m *MemoryStore) AddChangeEvent(_ context.Context, ev *domain.ChangeEvent) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if ev.ID == "" {
		ev.ID = NewID()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	ipEnc, err := m.vault.Encrypt(ev.HostIP, "change_events:"+ev.ID+":host_ip")
	if err != nil {
		return err
	}
	beforeEnc, err := m.vault.EncryptJSON(ev.Before, "change_events:"+ev.ID+":before")
	if err != nil {
		return err
	}
	afterEnc, err := m.vault.EncryptJSON(ev.After, "change_events:"+ev.ID+":after")
	if err != nil {
		return err
	}
	m.changes[ev.ID] = encChangeRow{
		ID:                 ev.ID,
		ScanRunID:          ev.ScanRunID,
		PrevScanRunID:      ev.PrevScanRunID,
		HostID:             ev.HostID,
		HostIPEnc:          ipEnc,
		ServiceID:          ev.ServiceID,
		Port:               ev.Port,
		EventType:          ev.EventType,
		Severity:           ev.Severity,
		Summary:            ev.Summary,
		TimeSlot:           ev.TimeSlot,
		IsExpectedSchedule: ev.IsExpectedSchedule,
		IsTimeAnomaly:      ev.IsTimeAnomaly,
		BeforeEnc:          beforeEnc,
		AfterEnc:           afterEnc,
		AcknowledgedBy:     ev.AcknowledgedBy,
		AcknowledgedAt:     ev.AcknowledgedAt,
		CreatedAt:          ev.CreatedAt,
	}
	return nil
}

func (m *MemoryStore) decryptChangeLocked(r encChangeRow) (*domain.ChangeEvent, error) {
	ip, err := m.vault.Decrypt(r.HostIPEnc, "change_events:"+r.ID+":host_ip")
	if err != nil {
		return nil, err
	}
	var before, after map[string]any
	if r.BeforeEnc != "" {
		if err := m.vault.DecryptJSON(r.BeforeEnc, "change_events:"+r.ID+":before", &before); err != nil {
			return nil, err
		}
	}
	if r.AfterEnc != "" {
		if err := m.vault.DecryptJSON(r.AfterEnc, "change_events:"+r.ID+":after", &after); err != nil {
			return nil, err
		}
	}
	return &domain.ChangeEvent{
		ID:                 r.ID,
		ScanRunID:          r.ScanRunID,
		PrevScanRunID:      r.PrevScanRunID,
		HostID:             r.HostID,
		HostIP:             ip,
		ServiceID:          r.ServiceID,
		Port:               r.Port,
		EventType:          r.EventType,
		Severity:           r.Severity,
		Summary:            r.Summary,
		TimeSlot:           r.TimeSlot,
		IsExpectedSchedule: r.IsExpectedSchedule,
		IsTimeAnomaly:      r.IsTimeAnomaly,
		Before:             before,
		After:              after,
		AcknowledgedBy:     r.AcknowledgedBy,
		AcknowledgedAt:     r.AcknowledgedAt,
		CreatedAt:          r.CreatedAt,
	}, nil
}

func (m *MemoryStore) ListChangeEvents(_ context.Context, filter ChangeFilter) ([]domain.ChangeEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.ChangeEvent, 0, len(m.changes))
	for _, r := range m.changes {
		if filter.ScanRunID != "" && r.ScanRunID != filter.ScanRunID {
			continue
		}
		if filter.Severity != "" && !strings.EqualFold(r.Severity, filter.Severity) {
			continue
		}
		if filter.EventType != "" && !strings.EqualFold(r.EventType, filter.EventType) {
			continue
		}
		if filter.AnomalyOnly && !r.IsTimeAnomaly {
			continue
		}
		dec, err := m.decryptChangeLocked(r)
		if err != nil {
			return nil, err
		}
		out = append(out, *dec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (m *MemoryStore) AcknowledgeChange(_ context.Context, id, username string) (*domain.ChangeEvent, error) {
	m.mu.Lock()
	defer m.unlockDirty()
	r, ok := m.changes[id]
	if !ok {
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	r.AcknowledgedBy = username
	r.AcknowledgedAt = &now
	m.changes[id] = r
	return m.decryptChangeLocked(r)
}

func (m *MemoryStore) SaveScanSnapshot(_ context.Context, scanRunID string, hosts []domain.Host) error {
	m.mu.Lock()
	defer m.unlockDirty()
	enc, err := m.vault.EncryptJSON(hosts, "scan_snapshots:"+scanRunID+":payload")
	if err != nil {
		return err
	}
	m.snapshots[scanRunID] = enc
	return nil
}

func (m *MemoryStore) GetScanSnapshot(_ context.Context, scanRunID string) ([]domain.Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	enc, ok := m.snapshots[scanRunID]
	if !ok {
		return nil, ErrNotFound
	}
	var hosts []domain.Host
	if err := m.vault.DecryptJSON(enc, "scan_snapshots:"+scanRunID+":payload", &hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

// --- Signatures ---

func (m *MemoryStore) ListSignatures(_ context.Context) ([]domain.Signature, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Signature, 0, len(m.signatures))
	for _, s := range m.signatures {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) GetSignature(_ context.Context, id string) (*domain.Signature, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.signatures[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &s, nil
}

func (m *MemoryStore) CreateSignature(_ context.Context, sig *domain.Signature) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if sig.ID == "" {
		sig.ID = NewID()
	}
	now := time.Now().UTC()
	if sig.CreatedAt.IsZero() {
		sig.CreatedAt = now
	}
	sig.UpdatedAt = now
	m.signatures[sig.ID] = *sig
	return nil
}

func (m *MemoryStore) UpdateSignature(_ context.Context, sig *domain.Signature) error {
	m.mu.Lock()
	defer m.unlockDirty()
	existing, ok := m.signatures[sig.ID]
	if !ok {
		return ErrNotFound
	}
	sig.CreatedAt = existing.CreatedAt
	sig.UpdatedAt = time.Now().UTC()
	m.signatures[sig.ID] = *sig
	return nil
}

func (m *MemoryStore) DeleteSignature(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if _, ok := m.signatures[id]; !ok {
		return ErrNotFound
	}
	delete(m.signatures, id)
	return nil
}

// --- DefectDojo ---

func (m *MemoryStore) GetDefectDojoConfig(_ context.Context) (*domain.DefectDojoConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.ddConfig == nil {
		return &domain.DefectDojoConfig{VerifyTLS: true}, nil
	}
	tok, err := m.vault.Decrypt(m.ddConfig.APITokenEnc, "defectdojo_config:default:api_token")
	if err != nil {
		return nil, err
	}
	return &domain.DefectDojoConfig{
		URL:          m.ddConfig.URL,
		APIToken:     tok,
		HasAPIToken:  tok != "",
		ProductID:    m.ddConfig.ProductID,
		EngagementID: m.ddConfig.EngagementID,
		VerifyTLS:    m.ddConfig.VerifyTLS,
		AutoPushNmap: m.ddConfig.AutoPushNmap,
	}, nil
}

func (m *MemoryStore) SaveDefectDojoConfig(_ context.Context, cfg *domain.DefectDojoConfig) error {
	m.mu.Lock()
	defer m.unlockDirty()
	var tokEnc string
	if cfg.APIToken != "" {
		var err error
		tokEnc, err = m.vault.Encrypt(cfg.APIToken, "defectdojo_config:default:api_token")
		if err != nil {
			return err
		}
	} else if m.ddConfig != nil {
		tokEnc = m.ddConfig.APITokenEnc
	}
	m.ddConfig = &encDDConfigRow{
		URL:          cfg.URL,
		APITokenEnc:  tokEnc,
		ProductID:    cfg.ProductID,
		EngagementID: cfg.EngagementID,
		VerifyTLS:    cfg.VerifyTLS,
		AutoPushNmap: cfg.AutoPushNmap,
	}
	return nil
}

func (m *MemoryStore) AddDefectDojoExport(_ context.Context, exp *domain.DefectDojoExport) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if exp.ID == "" {
		exp.ID = NewID()
	}
	if exp.CreatedAt.IsZero() {
		exp.CreatedAt = time.Now().UTC()
	}
	m.ddExports = append(m.ddExports, *exp)
	return nil
}

func (m *MemoryStore) ListDefectDojoExports(_ context.Context, limit int) ([]domain.DefectDojoExport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.DefectDojoExport, 0, len(m.ddExports))
	for i := len(m.ddExports) - 1; i >= 0; i-- {
		out = append(out, m.ddExports[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// --- Audit Logs ---

func (m *MemoryStore) AddAuditLog(_ context.Context, entry *domain.AuditLog) error {
	m.mu.Lock()
	defer m.unlockDirty()
	if entry.ID == "" {
		entry.ID = NewID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	cp := *entry
	if entry.Details != nil {
		b, _ := json.Marshal(entry.Details)
		_ = json.Unmarshal(b, &cp.Details)
	}
	m.auditLogs = append(m.auditLogs, cp)
	return nil
}

func (m *MemoryStore) ListAuditLogs(_ context.Context, limit int) ([]domain.AuditLog, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.AuditLog, 0, len(m.auditLogs))
	for i := len(m.auditLogs) - 1; i >= 0; i-- {
		out = append(out, m.auditLogs[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}
