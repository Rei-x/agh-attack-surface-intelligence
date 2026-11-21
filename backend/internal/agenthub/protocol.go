// Package agenthub is the server side of remote scanning agents (`dzieciol agent`).
//
// Model (same as runZero Explorers, Nessus linked scanners, Rapid7 engines in
// engine-to-console mode, Qualys appliances): the agent sits inside a network segment, opens
// OUTBOUND HTTPS to this server only, enrolls once with a one-time token, then pulls jobs,
// heartbeats and uploads results. The server never connects to the agent.
//
// Protocol (all JSON, Authorization: Bearer <agent credential>, except enroll):
//
//	POST /api/v1/agent/enroll            one-time token -> agent id + long-lived credential
//	POST /api/v1/agent/heartbeat         liveness + capabilities -> control (pause/stop) per run
//	POST /api/v1/agent/jobs/next?wait=25 long-poll for a job (204 = nothing to do)
//	POST /api/v1/agent/jobs/{id}/start   chunk ledger planned by the agent (first segment only)
//	POST /api/v1/agent/jobs/{id}/progress ledger + counters + live events (SSE relay)
//	POST /api/v1/agent/jobs/{id}/chunks  one finished chunk's observations (idempotent by chunk id)
//	POST /api/v1/agent/jobs/{id}/finish  segment end: outcome + raw nmap XML (idempotent by segment id)
//
// Results go through ingest.Pipeline.ProcessObservations exactly like local scans.
package agenthub

import (
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// InstanceHeader identifies one agent installation (one data directory). A job's lease is
// held by an instance, so a copied credential running elsewhere cannot steal a running job.
const InstanceHeader = "X-Dzieciol-Agent-Instance"

// CredentialPrefix marks agent credentials ("agt.<agent-id>.<secret>"). User JWTs never start
// with it, so the two token kinds can never be confused.
const CredentialPrefix = "agt."

// Control actions returned to the agent for a run it is executing.
const (
	ControlPause = "pause"
	ControlStop  = "stop"
)

// Finish outcomes reported by the agent at the end of a segment.
const (
	OutcomeCompleted    = "completed"
	OutcomePausedWindow = "paused_window"
	OutcomePausedUser   = "paused_user"
	OutcomeStopped      = "stopped"
	OutcomeInterrupted  = "interrupted" // agent shut down (systemctl stop/restart): resume later
	OutcomeFailed       = "failed"
	OutcomeRefused      = "refused" // local safety policy (--allow-cidr) rejected the job
)

// EnrollRequest is sent once by a new agent to exchange an enrollment token for a credential.
type EnrollRequest struct {
	Token        string                   `json:"token"`
	Name         string                   `json:"name"`
	Version      string                   `json:"version"`
	InstanceID   string                   `json:"instance_id"`
	Capabilities domain.AgentCapabilities `json:"capabilities"`
}

// EnrollResponse returns the agent identity and its long-lived credential.
type EnrollResponse struct {
	AgentID      string `json:"agent_id"`
	Name         string `json:"name"`
	Site         string `json:"site"`
	Credential   string `json:"credential"`
	HeartbeatSec int    `json:"heartbeat_sec"`
}

// HeartbeatRequest is the periodic liveness report of an agent.
type HeartbeatRequest struct {
	Version      string                   `json:"version"`
	Capabilities domain.AgentCapabilities `json:"capabilities"`
	CurrentRunID string                   `json:"current_run_id,omitempty"`
}

// HeartbeatResponse carries the server clock and pending pause/stop controls.
type HeartbeatResponse struct {
	ServerTime   time.Time         `json:"server_time"`
	HeartbeatSec int               `json:"heartbeat_sec"`
	Control      map[string]string `json:"control,omitempty"` // run id -> pause|stop
}

// RunCounters are the run fields an agent needs to continue a run from its checkpoint.
type RunCounters struct {
	TotalIPs          int       `json:"total_ips"`
	TotalChunks       int       `json:"total_chunks"`
	ScannedIPs        int       `json:"scanned_ips"`
	CompletedChunks   int       `json:"completed_chunks"`
	ActiveHosts       int       `json:"active_hosts"`
	ServicesFound     int       `json:"services_found"`
	DurationMs        int64     `json:"duration_ms"`
	WindowPausedCount int       `json:"window_paused_count"`
	StartedAt         time.Time `json:"started_at"`
}

// JobSpec is one scan job handed to an agent. Chunks is the server's coverage ledger: empty
// for a fresh run (the agent plans it with its own DNS view), otherwise DONE/FAILED chunks are
// already ingested and everything else must be (re)scanned.
type JobSpec struct {
	RunID         string                   `json:"run_id"`
	RunName       string                   `json:"run_name"`
	Profile       domain.ScanProfile       `json:"profile"`
	Exclusions    []domain.TargetExclusion `json:"exclusions"`
	Chunks        []domain.ScanChunk       `json:"chunks,omitempty"`
	Run           RunCounters              `json:"run"`
	UnstableHosts []string                 `json:"unstable_hosts,omitempty"`
}

// StartRequest reports the agent's chunk plan when it starts (or resumes) a job.
type StartRequest struct {
	TotalIPs   int                `json:"total_ips"`
	ETASeconds int64              `json:"eta_seconds"`
	Chunks     []domain.ScanChunk `json:"chunks"`
}

// Timing carries the agent-measured clock values of a run.
type Timing struct {
	DurationMs        int64   `json:"duration_ms"`
	HostsPerSec       float64 `json:"hosts_per_sec"`
	ETASeconds        int64   `json:"eta_seconds"`
	WindowPausedCount int     `json:"window_paused_count"`
}

// ProgressRequest streams timing, chunk states and live events of a running job.
type ProgressRequest struct {
	Timing Timing             `json:"timing"`
	Chunks []domain.ScanChunk `json:"chunks,omitempty"`
	Events []domain.LiveEvent `json:"events,omitempty"`
}

// ControlResponse answers progress/chunk/finish calls; Control tells the agent to pause or
// stop the run (user action in the UI).
type ControlResponse struct {
	OK        bool   `json:"ok"`
	Duplicate bool   `json:"duplicate,omitempty"`
	Control   string `json:"control,omitempty"`
	Error     string `json:"error,omitempty"`
	Dropped   int    `json:"dropped,omitempty"` // observations outside the chunk, ignored
}

// ChunkUpload carries one finished (DONE or FAILED) chunk and its observations. The chunk id
// is the idempotency key: a retried upload of an already ingested chunk is acknowledged and
// ignored.
type ChunkUpload struct {
	Chunk        domain.ScanChunk      `json:"chunk"`
	Observations []domain.ObservedHost `json:"observations"`
}

// FinishRequest ends one execution segment. SegmentID is the idempotency key.
type FinishRequest struct {
	SegmentID  string             `json:"segment_id"`
	Outcome    string             `json:"outcome"`
	Error      string             `json:"error,omitempty"`
	RawNmapXML string             `json:"raw_nmap_xml,omitempty"`
	Timing     Timing             `json:"timing"`
	Chunks     []domain.ScanChunk `json:"chunks,omitempty"`
	Events     []domain.LiveEvent `json:"events,omitempty"`
}
