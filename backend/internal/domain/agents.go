package domain

import "time"

// Remote scanning agents (dzieciol agent): a lightweight scanner inside another network segment
// that connects OUT to this server, pulls scan jobs and uploads results (internal/agenthub).
const (
	AgentStatusOnline   = "online"
	AgentStatusOffline  = "offline"
	AgentStatusDisabled = "disabled"
)

// AgentCapabilities are reported by the agent itself at enrollment and on every heartbeat.
type AgentCapabilities struct {
	Nmap        bool   `json:"nmap"`
	NmapVersion string `json:"nmap_version,omitempty"`
	Privileged  bool   `json:"privileged"`
	OS          string `json:"os,omitempty"`
	Arch        string `json:"arch,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	// Screenshots: a headless Chromium was found, so web services are captured as pictures.
	Screenshots bool `json:"screenshots,omitempty"`
	// AllowCIDRs is the agent's LOCAL allowlist (--allow-cidr): it refuses any target outside
	// it, whatever the server asks. Empty = no local restriction.
	AllowCIDRs []string `json:"allow_cidrs,omitempty"`
}

// Agent is one enrolled remote scanner. CredentialHash is the SHA-256 of the agent's secret;
// the secret is handed to the agent once at enrollment and never stored.
type Agent struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Site           string            `json:"site"`
	Version        string            `json:"version"`
	Status         string            `json:"status"`
	RemoteIP       string            `json:"remote_ip"`
	Capabilities   AgentCapabilities `json:"capabilities"`
	CurrentRunID   string            `json:"current_run_id,omitempty"`
	LastSeenAt     *time.Time        `json:"last_seen_at,omitempty"`
	EnrolledAt     time.Time         `json:"enrolled_at"`
	EnrolledBy     string            `json:"enrolled_by,omitempty"`
	Disabled       bool              `json:"disabled"`
	CredentialHash string            `json:"credential_hash,omitempty"` // stripped by the API
}

// AgentEnrollToken is a one-time enrollment token created by an administrator. Only its
// SHA-256 hash is stored; the token itself is returned once by the create call.
type AgentEnrollToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Site      string     `json:"site"`
	TokenHash string     `json:"token_hash,omitempty"` // stripped by the API
	Prefix    string     `json:"prefix"`               // first characters, to recognise a token
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	AgentID   string     `json:"agent_id,omitempty"`
}
