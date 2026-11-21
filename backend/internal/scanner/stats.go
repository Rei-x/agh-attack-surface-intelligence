package scanner

import (
	"sync/atomic"
	"time"
)

// StageTimings is a per-run breakdown of where scanner wall time went. Durations are summed
// over all workers (so they can exceed run wall time when stages overlap); counters describe
// the work each stage did.
type StageTimings struct {
	DiscoveryMs   int64 `json:"discovery_ms"`
	ReprobeMs     int64 `json:"reprobe_ms"`
	ServiceMs     int64 `json:"service_ms"`
	FingerprintMs int64 `json:"fingerprint_ms"`

	DiscoveryIPs int64 `json:"discovery_ips"`
	LiveHosts    int64 `json:"live_hosts"`
	OpenPorts    int64 `json:"open_ports"`
	HTTPServices int64 `json:"http_services"`
	HTTPRequests int64 `json:"http_requests"`
}

// stageStats is the concurrency-safe accumulator behind StageTimings.
type stageStats struct {
	discoveryNs, reprobeNs, serviceNs, fingerprintNs atomic.Int64
	discoveryIPs, liveHosts, openPorts, httpServices atomic.Int64
	httpRequests                                     atomic.Int64
}

func (s *stageStats) snapshot() StageTimings {
	if s == nil {
		return StageTimings{}
	}
	return StageTimings{
		DiscoveryMs:   s.discoveryNs.Load() / int64(time.Millisecond),
		ReprobeMs:     s.reprobeNs.Load() / int64(time.Millisecond),
		ServiceMs:     s.serviceNs.Load() / int64(time.Millisecond),
		FingerprintMs: s.fingerprintNs.Load() / int64(time.Millisecond),
		DiscoveryIPs:  s.discoveryIPs.Load(),
		LiveHosts:     s.liveHosts.Load(),
		OpenPorts:     s.openPorts.Load(),
		HTTPServices:  s.httpServices.Load(),
		HTTPRequests:  s.httpRequests.Load(),
	}
}

// chunkStageMs is the per-chunk stage breakdown reported in scan.chunk events.
type chunkStageMs struct {
	Discovery   int64 `json:"discovery"`
	Reprobe     int64 `json:"reprobe"`
	Service     int64 `json:"service"`
	Fingerprint int64 `json:"fingerprint"`
}
