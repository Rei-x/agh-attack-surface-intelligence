package domain

import "time"

// Zone policies ("exposure policy as code"): a network zone (one or more CIDRs) declares
// what may run there, and the inventory is checked against it after every ingest. A host
// follows the most specific enabled zone that contains its IP.

// Policy rule categories a zone can forbid.
const (
	PolicyCatAdminPanel = "admin_panel"     // management or login UI reachable
	PolicyCatCleartext  = "cleartext_admin" // telnet, ftp, r-services
	PolicyCatDatabase   = "database"        // database listener reachable
	PolicyCatIoTBMC     = "iot_bmc"         // embedded devices and server BMCs (iDRAC, iLO, IPMI)
	PolicyCatEOL        = "eol"             // end-of-life software version
	PolicyCatStaging    = "staging"         // staging, dev or test environment
)

// Policy rule identifiers used in violations (besides "forbidden:<category>").
const (
	PolicyRuleNoServices = "no_services"
	PolicyRulePort       = "port_not_allowed"
	PolicyRuleTLS        = "tls_required"
	PolicyRuleMaxRisk    = "max_risk"
	PolicyRuleForbidden  = "forbidden:" // prefix, followed by a category
)

// Change event types emitted by the policy engine.
const (
	EventPolicyViolation = "POLICY_VIOLATION"
	EventPolicyResolved  = "POLICY_RESOLVED"
)

// PolicyRules is what a zone allows.
type PolicyRules struct {
	NoServices   bool     `json:"no_services"`             // any open service is a violation
	AllowedPorts []int    `json:"allowed_ports,omitempty"` // empty means any port
	Forbidden    []string `json:"forbidden,omitempty"`     // PolicyCat* values
	RequireTLS   bool     `json:"require_tls"`             // web services must use HTTPS
	MaxRisk      int      `json:"max_risk,omitempty"`      // 0 = off; service score above this is a violation
}

// PolicyZone is one network zone with its rules.
type PolicyZone struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	CIDRs       []string    `json:"cidrs"`
	Preset      string      `json:"preset,omitempty"` // preset the rules started from (informational)
	Owner       string      `json:"owner,omitempty"`  // fallback owner when the host has none
	Enabled     bool        `json:"enabled"`
	Rules       PolicyRules `json:"rules"`
	CreatedBy   string      `json:"created_by,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// PolicyViolation is one service breaking the policy of its zone. One record per
// (zone, service); Reasons lists every rule it breaks. It resolves on its own when the
// service closes, the host goes inactive, the rules change, or an analyst accepts the risk.
type PolicyViolation struct {
	ID          string     `json:"id"` // stable: derived from zone and service
	ZoneID      string     `json:"zone_id"`
	ZoneName    string     `json:"zone_name"`
	Rule        string     `json:"rule"`  // primary (most severe) rule
	Rules       []string   `json:"rules"` // every rule broken
	Severity    string     `json:"severity"`
	Summary     string     `json:"summary"`
	Evidence    []string   `json:"evidence"`
	HostID      string     `json:"host_id"`
	HostIP      string     `json:"host_ip"`
	Hostname    string     `json:"hostname,omitempty"`
	ServiceID   string     `json:"service_id,omitempty"`
	Port        int        `json:"port,omitempty"`
	Protocol    string     `json:"protocol,omitempty"`
	ServiceName string     `json:"service_name,omitempty"`
	Owner       string     `json:"owner,omitempty"`
	Status      string     `json:"status"` // open, resolved
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// Policy violation statuses.
const (
	PolicyStatusOpen     = "open"
	PolicyStatusResolved = "resolved"
)

// PolicyHit is the compact read-time annotation of a service with open violations.
type PolicyHit struct {
	ZoneID   string   `json:"zone_id"`
	ZoneName string   `json:"zone_name"`
	Rules    []string `json:"rules"`
	Severity string   `json:"severity"`
	Summary  string   `json:"summary"`
}
