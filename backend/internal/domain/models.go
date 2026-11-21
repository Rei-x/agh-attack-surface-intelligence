package domain

import "time"

// Lifecycle states for hosts (hysteresis state machine).
const (
	HostStateNew          = "NEW"
	HostStateActive       = "ACTIVE"
	HostStateIntermittent = "INTERMITTENT"
	HostStateMissing      = "MISSING"
	HostStateInactive     = "INACTIVE"
	HostStateReactivated  = "REACTIVATED"
)

// Scan run statuses.
const (
	ScanStatusQueued       = "QUEUED"
	ScanStatusCalibrating  = "CALIBRATING"
	ScanStatusRunning      = "RUNNING"
	ScanStatusPausedWindow = "PAUSED_WINDOW"
	ScanStatusPausedUser   = "PAUSED_USER"
	ScanStatusCompleted    = "COMPLETED"
	ScanStatusFailed       = "FAILED"
	ScanStatusStopped      = "STOPPED"
)

// Scan run types.
const (
	ScanTypeActive     = "ACTIVE"
	ScanTypeManual     = "MANUAL"
	ScanTypeImportCSV  = "IMPORT_CSV"
	ScanTypeImportJSON = "IMPORT_JSON"
	ScanTypeImportNmap = "IMPORT_NMAP" // raw nmap XML (-oX) upload
	ScanTypePassive    = "PASSIVE"
)

// Chunk statuses (Coverage Ledger).
const (
	ChunkStatusPending = "PENDING"
	ChunkStatusRunning = "RUNNING"
	ChunkStatusDone    = "DONE"
	ChunkStatusPaused  = "PAUSED"
	ChunkStatusFailed  = "FAILED"
)

// Time-of-day slots.
const (
	SlotNight     = "00-06"
	SlotMorning   = "06-12"
	SlotAfternoon = "12-18"
	SlotEvening   = "18-24"
)

func TimeSlotFor(t time.Time) string {
	h := t.Hour()
	switch {
	case h < 6:
		return SlotNight
	case h < 12:
		return SlotMorning
	case h < 18:
		return SlotAfternoon
	default:
		return SlotEvening
	}
}

// RBAC Permission slugs.
const (
	PermDashboardRead    = "dashboard:read"
	PermAssetsRead       = "assets:read"
	PermAssetsWrite      = "assets:write"
	PermAssetsDelete     = "assets:delete"
	PermScansRead        = "scans:read"
	PermScansWrite       = "scans:write"
	PermScansDelete      = "scans:delete"
	PermScansRun         = "scans:run"
	PermSignaturesRead   = "signatures:read"
	PermSignaturesWrite  = "signatures:write"
	PermSignaturesDelete = "signatures:delete"
	PermImportWrite      = "import:write"
	PermExportRead       = "export:read"
	PermDefectDojoPush   = "defectdojo:push"
	PermAdminUsers       = "admin:users"
	PermAdminRoles       = "admin:roles"
	PermAdminSettings    = "admin:settings"
	PermAdminAudit       = "admin:audit"
)

var AllPermissions = []string{
	PermDashboardRead,
	PermAssetsRead,
	PermAssetsWrite,
	PermAssetsDelete,
	PermScansRead,
	PermScansWrite,
	PermScansDelete,
	PermScansRun,
	PermSignaturesRead,
	PermSignaturesWrite,
	PermSignaturesDelete,
	PermImportWrite,
	PermExportRead,
	PermDefectDojoPush,
	PermAdminUsers,
	PermAdminRoles,
	PermAdminSettings,
	PermAdminAudit,
}

type Role struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	RoleID       string    `json:"role_id"`
	RoleSlug     string    `json:"role_slug"`
	RoleName     string    `json:"role_name"`
	Permissions  []string  `json:"permissions"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
}

type Target struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"` // IP, CIDR, range, or domain
	Kind      string    `json:"kind"`  // ip, cidr, range, domain
	Label     string    `json:"label"`
	Tags      []string  `json:"tags"`
	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type TargetExclusion struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"`
	Reason    string    `json:"reason"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type ScanProfile struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Description           string    `json:"description"`
	Targets               []string  `json:"targets"`
	AllowedPorts          string    `json:"allowed_ports"` // e.g. "22,80,443,8080,8443"
	MaxRatePPS            int       `json:"max_rate_pps"`
	HTTPRPS               int       `json:"http_rps"`
	Concurrency           int       `json:"concurrency"`
	ChunkTargetSec        int       `json:"chunk_target_sec"`
	ScheduleCron          string    `json:"schedule_cron"` // optional cron expression
	WindowEnabled         bool      `json:"window_enabled"`
	WindowStart           string    `json:"window_start"` // HH:MM e.g. "22:00"
	WindowEnd             string    `json:"window_end"`   // HH:MM e.g. "06:00"
	Timezone              string    `json:"timezone"`     // e.g. "Europe/Warsaw"
	MissingThreshold      int       `json:"missing_threshold"`
	GracePeriodHours      int       `json:"grace_period_hours"`
	RetryUnstableCount    int       `json:"retry_unstable_count"`
	EnableHTTPFingerprint bool      `json:"enable_http_fingerprint"`
	UserAgent             string    `json:"user_agent"`
	Enabled               bool      `json:"enabled"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type ScanChunk struct {
	ID          string     `json:"id"`
	ScanRunID   string     `json:"scan_run_id"`
	ChunkIndex  int        `json:"chunk_index"`
	Targets     []string   `json:"targets"`
	IPCount     int        `json:"ip_count"`
	Status      string     `json:"status"`
	ActiveHosts int        `json:"active_hosts"`
	Services    int        `json:"services_found"`
	DurationMs  int64      `json:"duration_ms"`
	Error       string     `json:"error,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	// NmapCommands lists the exact command lines executed for this chunk (discovery,
	// unstable re-probes, service detection) or a description of the pure-Go fallback.
	NmapCommands []string `json:"nmap_commands,omitempty"`
	// MaxRatePPS is this chunk's share of the profile's global --max-rate budget.
	MaxRatePPS int `json:"max_rate_pps,omitempty"`
	// Worker is the 1-based chunk worker slot that executed the chunk.
	Worker int `json:"worker,omitempty"`
}

// ScheduleState is the persisted bookkeeping of the recurring-scan scheduler for one profile.
// AnchorAt marks the last consumed cron slot boundary: every slot <= AnchorAt has either fired,
// been skipped, or been collapsed into a single catch-up run.
type ScheduleState struct {
	ProfileID      string     `json:"profile_id"`
	Cron           string     `json:"cron"`
	AnchorAt       *time.Time `json:"anchor_at,omitempty"`
	LastFireAt     *time.Time `json:"last_fire_at,omitempty"`
	LastRunID      string     `json:"last_run_id,omitempty"`
	LastSkipAt     *time.Time `json:"last_skip_at,omitempty"`
	LastSkipReason string     `json:"last_skip_reason,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type ScanRun struct {
	ID                string      `json:"id"`
	ProfileID         string      `json:"profile_id,omitempty"`
	Name              string      `json:"name"`
	RunType           string      `json:"run_type"`
	Status            string      `json:"status"`
	Notes             string      `json:"notes"`
	TotalIPs          int         `json:"total_ips"`
	ScannedIPs        int         `json:"scanned_ips"`
	TotalChunks       int         `json:"total_chunks"`
	CompletedChunks   int         `json:"completed_chunks"`
	ActiveHosts       int         `json:"active_hosts"`
	ServicesFound     int         `json:"services_found"`
	ChangesDetected   int         `json:"changes_detected"`
	HostsPerSec       float64     `json:"hosts_per_sec"`
	ETASeconds        int64       `json:"eta_seconds"`
	DurationMs        int64       `json:"duration_ms"`
	WindowPausedCount int         `json:"window_paused_count"`
	RawNmapXML        string      `json:"-"` // stored encrypted at rest
	HasRawNmapXML     bool        `json:"has_raw_nmap_xml"`
	TriggeredBy       string      `json:"triggered_by"`
	StartedAt         time.Time   `json:"started_at"`
	FinishedAt        *time.Time  `json:"finished_at,omitempty"`
	Chunks            []ScanChunk `json:"chunks,omitempty"`
}

// Fingerprinting & Evidence structures.
type RedirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

type CookieInfo struct {
	Name     string   `json:"name"`
	Value    string   `json:"value,omitempty"` // encrypted at rest
	Path     string   `json:"path,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	HttpOnly bool     `json:"http_only"`
	Secure   bool     `json:"secure"`
	SameSite string   `json:"same_site,omitempty"`
	Flags    []string `json:"flags,omitempty"` // e.g. "missing_httponly", "missing_secure"
}

type TLSInfo struct {
	Version      string    `json:"version"`
	CipherSuite  string    `json:"cipher_suite,omitempty"`
	SubjectCN    string    `json:"subject_cn"`
	Issuer       string    `json:"issuer"`
	SANs         []string  `json:"sans,omitempty"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DaysToExpiry int       `json:"days_to_expiry"`
	IsSelfSigned bool      `json:"is_self_signed"`
	IsExpired    bool      `json:"is_expired"`
	SHA256       string    `json:"sha256"`
	JARM         string    `json:"jarm,omitempty"` // 62-char JARM TLS server fingerprint (Salesforce algorithm)
}

type SafePathHit struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
	// LoginForm: the response is an HTML page with a password field.
	LoginForm bool `json:"login_form,omitempty"`
	// AuthChallenge is the WWW-Authenticate header of a 401 (e.g. Basic realm="Tomcat Manager Application").
	AuthChallenge string `json:"auth_challenge,omitempty"`
}

type HTTPFingerprint struct {
	URL                string            `json:"url"`
	Scheme             string            `json:"scheme"`
	StatusCode         int               `json:"status_code"`
	Title              string            `json:"title"`
	ServerHeader       string            `json:"server_header,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	MissingSecHeaders  []string          `json:"missing_sec_headers,omitempty"`
	InterestingHeaders []string          `json:"interesting_headers,omitempty"`
	Cookies            []CookieInfo      `json:"cookies,omitempty"`
	RedirectChain      []RedirectHop     `json:"redirect_chain,omitempty"`
	TLS                *TLSInfo          `json:"tls,omitempty"`
	FaviconMMH3        string            `json:"favicon_mmh3,omitempty"`
	FaviconSHA256      string            `json:"favicon_sha256,omitempty"`
	MetaGenerator      string            `json:"meta_generator,omitempty"`
	FooterVersion      string            `json:"footer_version,omitempty"`
	BodySnippet        string            `json:"body_snippet,omitempty"`
	LoginForm          bool              `json:"login_form,omitempty"` // final page has a password field
	SafePathHits       []SafePathHit     `json:"safe_path_hits,omitempty"`
	// CatchAll is set when a random, non-existent path answers like a real page (SPA fallback,
	// custom 200/403 error page, redirect-everything-to-login). Path hits that look the same as
	// that soft-404 baseline are dropped, so they can't fake WordPress/phpMyAdmin/... detections.
	CatchAll       bool  `json:"catch_all,omitempty"`
	ResponseTimeMs int64 `json:"response_time_ms"`
}

type TechEvidence struct {
	SignalType string  `json:"signal_type"` // header, cookie, favicon, html, path, tls, banner, signature
	Detail     string  `json:"detail"`
	Weight     float64 `json:"weight"`
}

type DetectedTechnology struct {
	Name       string         `json:"name"`
	Category   string         `json:"category"` // cms, framework, server, iot, admin_panel, staging, custom
	Version    string         `json:"version,omitempty"`
	Confidence int            `json:"confidence"` // 0..100 (Noisy-OR fused)
	Evidence   []TechEvidence `json:"evidence"`
	// Explanation shows the fusion arithmetic, e.g.
	// "header 0.80 ⊕ html 0.80 → 1-(0.20·0.20) = 96%".
	Explanation string `json:"explanation,omitempty"`
}

type InterestingnessFactor struct {
	Reason string `json:"reason"`
	Points int    `json:"points"`
}

type TimeSlotStat struct {
	Slot  string  `json:"slot"` // 00-06, 06-12, 12-18, 18-24
	Seen  int     `json:"seen"`
	Total int     `json:"total"`
	Ratio float64 `json:"ratio"`

	// Beta-Bernoulli availability posterior for this time-of-day slot (see
	// intelligence/liveness.go). Alpha/Beta include the prior and are
	// exponentially forgotten; StreakMisses are misses of the current,
	// still-unexplained outage (folded into Beta once the host answers again).
	Alpha        float64   `json:"alpha,omitempty"`
	Beta         float64   `json:"beta,omitempty"`
	PUp          float64   `json:"p_up,omitempty"` // posterior mean availability in this slot
	StreakMisses int       `json:"streak_misses,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// LivenessEstimate explains the Bayesian "is this host gone?" decision.
type LivenessEstimate struct {
	PAlive       float64 `json:"p_alive"`       // P(host still exists | history, current outage)
	PUpSlot      float64 `json:"p_up_slot"`     // P(host answers in the current slot) = p_alive * E[availability]
	Slot         string  `json:"slot"`          // slot the estimate refers to
	StreakMisses int     `json:"streak_misses"` // misses in the current outage (all slots)
	Threshold    float64 `json:"threshold"`     // INACTIVE when p_alive < threshold (plus min guards)
	Reason       string  `json:"reason"`
	Model        string  `json:"model"`
}

type Host struct {
	ID                 string                  `json:"id"`
	IP                 string                  `json:"ip"`
	Hostname           string                  `json:"hostname,omitempty"`
	Domains            []string                `json:"domains,omitempty"`
	OSGuess            string                  `json:"os_guess,omitempty"`
	LifecycleState     string                  `json:"lifecycle_state"`
	Environment        string                  `json:"environment,omitempty"` // prod, staging, dev, test, unknown
	Owner              string                  `json:"owner,omitempty"`
	Notes              string                  `json:"notes,omitempty"`
	Tags               []string                `json:"tags"`
	FirstSeen          time.Time               `json:"first_seen"`
	LastSeen           time.Time               `json:"last_seen"`
	TotalScansSeen     int                     `json:"total_scans_seen"`
	TotalScansChecked  int                     `json:"total_scans_checked"`
	ConsecutiveMisses  int                     `json:"consecutive_misses"`
	StateTransitions   int                     `json:"state_transitions"`
	StabilityScore     int                     `json:"stability_score"` // 0..100
	Interestingness    int                     `json:"interestingness"` // 0..100
	InterestingFactors []InterestingnessFactor `json:"interesting_factors,omitempty"`
	TimeOfDayStats     []TimeSlotStat          `json:"time_of_day_stats,omitempty"`
	Liveness           *LivenessEstimate       `json:"liveness,omitempty"` // derived from TimeOfDayStats
	LockedFields       []string                `json:"locked_fields,omitempty"`
	ScannerObserved    map[string]any          `json:"scanner_observed,omitempty"` // shown when analyst overrode a field
	Services           []Service               `json:"services,omitempty"`
	ServiceCount       int                     `json:"service_count"`
	// Analyst risk decision on the whole host (accepted_risk / false_positive). Only set
	// from the "triage" override, so it is preserved across scans.
	TriageStatus string      `json:"triage_status,omitempty"`
	Triage       *TriageInfo `json:"triage,omitempty"`
}

type Service struct {
	ID                 string                  `json:"id"`
	HostID             string                  `json:"host_id"`
	HostIP             string                  `json:"host_ip,omitempty"`
	Port               int                     `json:"port"`
	Protocol           string                  `json:"protocol"`
	State              string                  `json:"state"` // open, closed, filtered
	ServiceName        string                  `json:"service_name"`
	Product            string                  `json:"product,omitempty"`
	Version            string                  `json:"version,omitempty"`
	ProductSource      string                  `json:"product_source,omitempty"` // nmap, cpe, banner, http-server-header, http-page
	VersionSource      string                  `json:"version_source,omitempty"`
	CPE                string                  `json:"cpe,omitempty"`
	Banner             string                  `json:"banner,omitempty"`
	HTTP               *HTTPFingerprint        `json:"http,omitempty"`
	Technologies       []DetectedTechnology    `json:"technologies"`
	MatchedSignatures  []string                `json:"matched_signatures"`
	IsAdminPanel       bool                    `json:"is_admin_panel"`
	IsStagingEnv       bool                    `json:"is_staging_env"`
	IsIoT              bool                    `json:"is_iot"`
	ClusterKey         string                  `json:"cluster_key,omitempty"`
	Interestingness    int                     `json:"interestingness"`
	InterestingFactors []InterestingnessFactor `json:"interesting_factors,omitempty"`
	TriageStatus       string                  `json:"triage_status"` // new, triaged, accepted_risk, false_positive
	Triage             *TriageInfo             `json:"triage,omitempty"`
	Notes              string                  `json:"notes,omitempty"`
	Tags               []string                `json:"tags"`
	LockedFields       []string                `json:"locked_fields,omitempty"`
	ScannerObserved    map[string]any          `json:"scanner_observed,omitempty"`
	FirstSeen          time.Time               `json:"first_seen"`
	LastSeen           time.Time               `json:"last_seen"`
}

// Raw observation emitted by scanner OR unified importer before diff/merge.
type ObservedService struct {
	Port        int              `json:"port"`
	Protocol    string           `json:"protocol"`
	State       string           `json:"state"`
	ServiceName string           `json:"service_name"`
	Product     string           `json:"product,omitempty"`
	Version     string           `json:"version,omitempty"`
	CPE         string           `json:"cpe,omitempty"`
	Banner      string           `json:"banner,omitempty"`
	HTTP        *HTTPFingerprint `json:"http,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
	Notes       string           `json:"notes,omitempty"`
}

type ObservedHost struct {
	IP          string            `json:"ip"`
	Hostname    string            `json:"hostname,omitempty"`
	Domains     []string          `json:"domains,omitempty"`
	OSGuess     string            `json:"os_guess,omitempty"`
	IsAlive     bool              `json:"is_alive"`
	Environment string            `json:"environment,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Notes       string            `json:"notes,omitempty"`
	ObservedAt  time.Time         `json:"observed_at"`
	Services    []ObservedService `json:"services"`
}

type ChangeEvent struct {
	ID                 string         `json:"id"`
	ScanRunID          string         `json:"scan_run_id"`
	PrevScanRunID      string         `json:"prev_scan_run_id,omitempty"`
	HostID             string         `json:"host_id"`
	HostIP             string         `json:"host_ip"`
	ServiceID          string         `json:"service_id,omitempty"`
	Port               int            `json:"port,omitempty"`
	EventType          string         `json:"event_type"`
	Severity           string         `json:"severity"` // info, low, medium, high
	Summary            string         `json:"summary"`
	TimeSlot           string         `json:"time_slot"`
	IsExpectedSchedule bool           `json:"is_expected_schedule"`
	IsTimeAnomaly      bool           `json:"is_time_anomaly"`
	Before             map[string]any `json:"before,omitempty"`
	After              map[string]any `json:"after,omitempty"`
	AcknowledgedBy     string         `json:"acknowledged_by,omitempty"`
	AcknowledgedAt     *time.Time     `json:"acknowledged_at,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
}

// Custom detection signature.
type SignatureMatcher struct {
	Type         string `json:"type"` // header, cookie, favicon_mmh3, favicon_sha256, html_body, footer_version, safe_path, tls_cert, jarm, banner, port
	Key          string `json:"key,omitempty"`
	Pattern      string `json:"pattern"`
	Regex        bool   `json:"regex"`
	StatusCodes  []int  `json:"status_codes,omitempty"`
	VersionGroup int    `json:"version_group,omitempty"`
}

type Signature struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Description      string             `json:"description"`
	Category         string             `json:"category"`   // cms, framework, server, iot, admin_panel, staging, interesting_header, interesting_cookie, custom
	MatchMode        string             `json:"match_mode"` // any, all
	Matchers         []SignatureMatcher `json:"matchers"`
	ConfidenceWeight float64            `json:"confidence_weight"` // 0.1 .. 0.98
	InterestingPts   int                `json:"interesting_points"`
	Tags             []string           `json:"tags"`
	IsBuiltin        bool               `json:"is_builtin"`
	Enabled          bool               `json:"enabled"`
	CreatedBy        string             `json:"created_by"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

type AuditLog struct {
	ID         string         `json:"id"`
	UserID     string         `json:"user_id,omitempty"`
	Username   string         `json:"username"`
	RoleSlug   string         `json:"role_slug"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	ResourceID string         `json:"resource_id,omitempty"`
	Status     string         `json:"status"` // success, denied, error
	Details    map[string]any `json:"details,omitempty"`
	IPAddress  string         `json:"ip_address,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

type DefectDojoConfig struct {
	URL          string `json:"url"`
	APIToken     string `json:"api_token,omitempty"`
	HasAPIToken  bool   `json:"has_api_token"`
	ProductID    int    `json:"product_id"`
	EngagementID int    `json:"engagement_id"`
	VerifyTLS    bool   `json:"verify_tls"`
	AutoPushNmap bool   `json:"auto_push_nmap"`
}

type DefectDojoExport struct {
	ID           string    `json:"id"`
	ExportType   string    `json:"export_type"` // nmap_xml, finding
	SourceID     string    `json:"source_id"`
	Title        string    `json:"title"`
	ExternalID   string    `json:"external_id,omitempty"`
	ExternalURL  string    `json:"external_url,omitempty"`
	Status       string    `json:"status"` // success, failed
	ErrorMessage string    `json:"error_message,omitempty"`
	ExportedBy   string    `json:"exported_by"`
	CreatedAt    time.Time `json:"created_at"`
}

// Live event pushed over SSE.
type LiveEvent struct {
	Type      string         `json:"type"`
	ScanRunID string         `json:"scan_run_id,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
	Payload   map[string]any `json:"payload"`
}

// TargetEstimate returned by POST /api/v1/targets/estimate.
type TargetEstimate struct {
	TotalIPs             int   `json:"total_ips"`
	ExcludedIPs          int   `json:"excluded_ips"`
	EffectiveIPs         int   `json:"effective_ips"`
	RecommendedChunkSize int   `json:"recommended_chunk_size"`
	ChunkCount           int   `json:"chunk_count"`
	EstimatedSeconds     int64 `json:"estimated_seconds"`
	FitsInWindow         bool  `json:"fits_in_window"`
	EstimatedWindows     int   `json:"estimated_windows"`
}

// ServiceCluster for grouping similar services.
type ServiceCluster struct {
	ClusterKey  string   `json:"cluster_key"`
	GroupBy     string   `json:"group_by"` // favicon, tech_stack, http_title, tls_issuer, service_product
	Label       string   `json:"label"`
	Count       int      `json:"count"`
	HostIPs     []string `json:"host_ips"`
	ServiceIDs  []string `json:"service_ids"`
	MaxScore    int      `json:"max_interestingness"`
	SampleTechs []string `json:"sample_techs"`
}

// Graph structures for Interactive Attack Surface Graph.
type GraphNode struct {
	ID              string         `json:"id"`
	Kind            string         `json:"kind"` // scope, host, service, technology, signature
	Label           string         `json:"label"`
	State           string         `json:"state,omitempty"`
	Interestingness int            `json:"interestingness,omitempty"`
	Meta            map[string]any `json:"meta,omitempty"`
}

type GraphEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

// Triage statuses shared by services and hosts.
const (
	TriageNew           = "new"
	TriageTriaged       = "triaged"
	TriageAcceptedRisk  = "accepted_risk"
	TriageFalsePositive = "false_positive"
)

// TriageInfo is an analyst risk decision (accepted risk / false positive) with a mandatory
// reason, author and optional expiry. It is stored as the encrypted "triage" override, so
// it survives every later scan. Once ExpiresAt passes the decision stops applying (Expired
// is set on read) and the finding counts as active again.
type TriageInfo struct {
	Status    string     `json:"status"`
	Reason    string     `json:"reason"`
	By        string     `json:"by"`
	At        time.Time  `json:"at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Expired   bool       `json:"expired"`
}

// IsSuppressing reports whether the decision currently hides the finding (accepted risk or
// false positive that has not expired).
func (t *TriageInfo) IsSuppressing(now time.Time) bool {
	if t == nil {
		return false
	}
	if t.Status != TriageAcceptedRisk && t.Status != TriageFalsePositive {
		return false
	}
	return t.ExpiresAt == nil || now.Before(*t.ExpiresAt)
}

// TagRule maps a CIDR to tags / owner / environment applied automatically on ingest
// (ownership by network range, e.g. 10.66.0.0/22 -> wydzial-wi, owner admin@wi.agh.edu.pl).
type TagRule struct {
	ID          string    `json:"id"`
	CIDR        string    `json:"cidr"`
	Tags        []string  `json:"tags"`
	Owner       string    `json:"owner,omitempty"`
	Environment string    `json:"environment,omitempty"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// WebhookConfig is the single outbound alert webhook (Slack / Discord / Teams compatible).
// The URL is a secret (it embeds the channel token) and is stored encrypted at rest; API
// responses only expose URLMasked.
type WebhookConfig struct {
	URL                string     `json:"url,omitempty"`
	HasURL             bool       `json:"has_url"`
	URLMasked          string     `json:"url_masked,omitempty"`
	Enabled            bool       `json:"enabled"`
	MinSeverity        string     `json:"min_severity"` // info, low, medium, high
	NotifyStateChanges bool       `json:"notify_state_changes"`
	LastStatus         string     `json:"last_status,omitempty"`
	LastError          string     `json:"last_error,omitempty"`
	LastSentAt         *time.Time `json:"last_sent_at,omitempty"`
}

// HostTimelineEntry is one row of the host incident-response timeline.
type HostTimelineEntry struct {
	Kind      string         `json:"kind"` // change, observation, first_seen
	At        time.Time      `json:"at"`
	Until     *time.Time     `json:"until,omitempty"`
	Count     int            `json:"count,omitempty"`
	EventType string         `json:"event_type,omitempty"`
	Severity  string         `json:"severity,omitempty"`
	Summary   string         `json:"summary"`
	ServiceID string         `json:"service_id,omitempty"`
	Port      int            `json:"port,omitempty"`
	Protocol  string         `json:"protocol,omitempty"`
	ScanRunID string         `json:"scan_run_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}
