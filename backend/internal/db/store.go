package db

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

// NewID generates a random UUID v4 string without external dependencies.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// HostFilter controls GET /api/v1/hosts and export filtering.
type HostFilter struct {
	Query    string
	State    string
	Tag      string
	MinScore int
	Env      string
	HasAdmin bool
	ScanID   string
	Page     int
	Limit    int
}

// ServiceFilter controls GET /api/v1/services filtering.
type ServiceFilter struct {
	HostID   string
	Query    string
	Port     int
	Tag      string
	MinScore int
	HasAdmin bool
	State    string
}

// ChangeFilter controls GET /api/v1/changes filtering.
type ChangeFilter struct {
	ScanRunID   string
	Severity    string
	EventType   string
	AnomalyOnly bool
	Limit       int
}

// ServiceObservation is a single immutable raw observation (Evidence Receipt) tied to a scan run.
type ServiceObservation struct {
	ID          string                  `json:"id"`
	ScanRunID   string                  `json:"scan_run_id"`
	HostID      string                  `json:"host_id"`
	ServiceID   string                  `json:"service_id"`
	Port        int                     `json:"port"`
	Protocol    string                  `json:"protocol"`
	State       string                  `json:"state"`
	ServiceName string                  `json:"service_name"`
	Product     string                  `json:"product,omitempty"`
	Version     string                  `json:"version,omitempty"`
	Banner      string                  `json:"banner,omitempty"`
	HTTP        *domain.HTTPFingerprint `json:"http,omitempty"`
	ObservedAt  time.Time               `json:"observed_at"`
}

// CryptoProofSample demonstrates raw ciphertext stored in the DB alongside its decrypted representation.
type CryptoProofSample struct {
	Table           string `json:"table"`
	RecordID        string `json:"record_id"`
	Column          string `json:"column"`
	AAD             string `json:"aad"`
	RawCiphertext   string `json:"raw_ciphertext"`
	DecryptedSample string `json:"decrypted_sample"`
	BlindIndexCol   string `json:"blind_index_column,omitempty"`
	BlindIndexValue string `json:"blind_index_value,omitempty"`
}

// Store is the unified persistence contract implemented by PostgresStore and MemoryStore.
type Store interface {
	Ping(ctx context.Context) error
	Close()
	BackendName() string

	// Crypto key persistence & rotation
	LoadCryptoKeys(ctx context.Context) (map[string]string, string, error)
	SaveCryptoKey(ctx context.Context, kid, wrapped string, active bool) error
	ReEncryptAll(ctx context.Context) (int, error)
	GetCryptoProofSample(ctx context.Context) (*CryptoProofSample, error)

	// Roles & Users (Dynamic RBAC)
	ListRoles(ctx context.Context) ([]domain.Role, error)
	GetRole(ctx context.Context, id string) (*domain.Role, error)
	GetRoleBySlug(ctx context.Context, slug string) (*domain.Role, error)
	CreateRole(ctx context.Context, role *domain.Role) error
	UpdateRole(ctx context.Context, role *domain.Role) error
	DeleteRole(ctx context.Context, id string) error

	ListUsers(ctx context.Context) ([]domain.User, error)
	GetUser(ctx context.Context, id string) (*domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	CreateUser(ctx context.Context, user *domain.User) error
	UpdateUser(ctx context.Context, user *domain.User) error
	DeleteUser(ctx context.Context, id string) error

	// Targets & Exclusions
	ListTargets(ctx context.Context) ([]domain.Target, error)
	CreateTarget(ctx context.Context, t *domain.Target) error
	DeleteTarget(ctx context.Context, id string) error

	ListExclusions(ctx context.Context) ([]domain.TargetExclusion, error)
	CreateExclusion(ctx context.Context, ex *domain.TargetExclusion) error
	DeleteExclusion(ctx context.Context, id string) error

	// Scan Profiles
	ListProfiles(ctx context.Context) ([]domain.ScanProfile, error)
	GetProfile(ctx context.Context, id string) (*domain.ScanProfile, error)
	CreateProfile(ctx context.Context, p *domain.ScanProfile) error
	UpdateProfile(ctx context.Context, p *domain.ScanProfile) error
	DeleteProfile(ctx context.Context, id string) error

	// Scan Runs & Coverage Ledger Chunks
	ListScanRuns(ctx context.Context, limit int) ([]domain.ScanRun, error)
	GetScanRun(ctx context.Context, id string) (*domain.ScanRun, error)
	CreateScanRun(ctx context.Context, run *domain.ScanRun) error
	UpdateScanRun(ctx context.Context, run *domain.ScanRun) error
	UpdateScanRunMeta(ctx context.Context, id, name, notes string) (*domain.ScanRun, error)
	DeleteScanRun(ctx context.Context, id string) error
	SaveScanChunks(ctx context.Context, scanRunID string, chunks []domain.ScanChunk) error
	UpdateScanChunk(ctx context.Context, chunk *domain.ScanChunk) error
	GetScanChunks(ctx context.Context, scanRunID string) ([]domain.ScanChunk, error)

	// Hosts, Services & Observations (with automatic override merging on reads)
	ListHosts(ctx context.Context, filter HostFilter) ([]domain.Host, int, error)
	GetHost(ctx context.Context, id string) (*domain.Host, error)
	GetHostByIP(ctx context.Context, ip string) (*domain.Host, error)
	UpsertObservedHost(ctx context.Context, host *domain.Host) (*domain.Host, error)
	DeleteHost(ctx context.Context, id string) error

	ListServices(ctx context.Context, filter ServiceFilter) ([]domain.Service, error)
	GetService(ctx context.Context, id string) (*domain.Service, error)
	ListServicesByHost(ctx context.Context, hostID string) ([]domain.Service, error)
	UpsertObservedService(ctx context.Context, svc *domain.Service) (*domain.Service, error)

	AddObservation(ctx context.Context, obs *ServiceObservation) error
	ListServiceObservations(ctx context.Context, serviceID string, limit int) ([]ServiceObservation, error)

	// Preserved Analyst Overrides
	GetOverrides(ctx context.Context, entityType, entityID string) (map[string]any, error)
	PatchOverrides(ctx context.Context, entityType, entityID string, patch map[string]any, unlockFields []string, updatedBy string) error

	// Changes & Scan Snapshots
	AddChangeEvent(ctx context.Context, ev *domain.ChangeEvent) error
	ListChangeEvents(ctx context.Context, filter ChangeFilter) ([]domain.ChangeEvent, error)
	AcknowledgeChange(ctx context.Context, id, username string) (*domain.ChangeEvent, error)
	SaveScanSnapshot(ctx context.Context, scanRunID string, hosts []domain.Host) error
	GetScanSnapshot(ctx context.Context, scanRunID string) ([]domain.Host, error)

	// Signatures
	ListSignatures(ctx context.Context) ([]domain.Signature, error)
	GetSignature(ctx context.Context, id string) (*domain.Signature, error)
	CreateSignature(ctx context.Context, sig *domain.Signature) error
	UpdateSignature(ctx context.Context, sig *domain.Signature) error
	DeleteSignature(ctx context.Context, id string) error

	// DefectDojo Integration
	GetDefectDojoConfig(ctx context.Context) (*domain.DefectDojoConfig, error)
	SaveDefectDojoConfig(ctx context.Context, cfg *domain.DefectDojoConfig) error
	AddDefectDojoExport(ctx context.Context, exp *domain.DefectDojoExport) error
	ListDefectDojoExports(ctx context.Context, limit int) ([]domain.DefectDojoExport, error)

	// Audit Logs
	AddAuditLog(ctx context.Context, entry *domain.AuditLog) error
	ListAuditLogs(ctx context.Context, limit int) ([]domain.AuditLog, error)
}
