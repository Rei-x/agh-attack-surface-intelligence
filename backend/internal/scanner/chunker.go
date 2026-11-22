package scanner

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const (
	MinChunkSize          = 32
	MaxChunkSize          = 512
	DefaultChunkTargetSec = 30
)

// EstimateRequest configures scope size, rate, and window estimation.
type EstimateRequest struct {
	Targets               []string
	Exclusions            []domain.TargetExclusion
	Ports                 string
	MaxRatePPS            int
	Concurrency           int
	ChunkTargetSec        int
	Window                *WindowGuard
	Now                   time.Time
	Resolver              Resolver
	EnableHTTPFingerprint bool
}

// CalibrationResult summarizes a micro-probe measurement used for adaptive chunk sizing.
type CalibrationResult struct {
	SampledIPs   int           `json:"sampled_ips"`
	AliveIPs     int           `json:"alive_ips"`
	AvgLatencyMs int64         `json:"avg_latency_ms"`
	HostsPerSec  float64       `json:"hosts_per_sec"`
	ChunkSize    int           `json:"chunk_size"`
	Elapsed      time.Duration `json:"elapsed"`
}

// EstimateTargets expands targets, applies exclusions, estimates throughput & ETA,
// recommends an adaptive chunk size (32..512), and checks fit against the time window.
func EstimateTargets(ctx context.Context, req EstimateRequest) (*domain.TargetEstimate, *TargetResolution, error) {
	resolution, err := ParseAndNormalizeTargets(ctx, req.Targets, req.Exclusions, req.Resolver)
	if err != nil {
		return nil, nil, err
	}

	portSpec := EffectivePorts(req.Ports, len(resolution.IPs))
	ports, err := ParsePorts(portSpec)
	if err != nil {
		return nil, nil, err
	}

	maxRate := req.MaxRatePPS
	if maxRate <= 0 && IsAutoPorts(req.Ports) && len(resolution.IPs) <= AutoFullRangeMaxIPs {
		maxRate = AutoFullRangeRatePPS
	}
	if maxRate <= 0 {
		maxRate = 300
	}
	concurrency := req.Concurrency
	if concurrency <= 0 {
		concurrency = 32
	}
	chunkTargetSec := req.ChunkTargetSec
	if chunkTargetSec <= 0 {
		chunkTargetSec = DefaultChunkTargetSec
	}

	effectiveIPs := len(resolution.IPs)
	hostsPerSec := estimateThroughput(maxRate, concurrency, len(ports), req.EnableHTTPFingerprint)
	chunkSize := RecommendChunkSize(effectiveIPs, hostsPerSec, chunkTargetSec)

	chunkCount := 0
	if effectiveIPs > 0 {
		chunkCount = int(math.Ceil(float64(effectiveIPs) / float64(chunkSize)))
	}

	estSec := int64(0)
	if effectiveIPs > 0 && hostsPerSec > 0 {
		estSec = int64(math.Ceil(float64(effectiveIPs) / hostsPerSec))
		if estSec < 1 {
			estSec = 1
		}
	}
	// Small scopes with long port lists (auto: all 65535 ports for 1-4 IPs): the sweep sends
	// one probe per (IP, port), plus about 20 s of version detection and HTTP fingerprinting.
	// (Large scopes keep the calibrated model above.)
	if effectiveIPs > 0 && effectiveIPs <= AutoTopPortsMaxIPs {
		if floor := int64(math.Ceil(float64(effectiveIPs)*float64(len(ports))/float64(maxRate))) + 20; estSec < floor {
			estSec = floor
		}
	}

	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	fits := true
	estWindows := 1
	if req.Window != nil && req.Window.Enabled {
		fits = req.Window.FitsInWindow(now, estSec)
		estWindows = req.Window.EstimatedWindows(estSec)
	}

	est := &domain.TargetEstimate{
		TotalIPs:             resolution.TotalCount,
		ExcludedIPs:          resolution.ExcludedCount,
		EffectiveIPs:         effectiveIPs,
		RecommendedChunkSize: chunkSize,
		ChunkCount:           chunkCount,
		EstimatedSeconds:     estSec,
		FitsInWindow:         fits,
		EstimatedWindows:     estWindows,
		PortCount:            len(ports),
		PortsLabel:           portSpec,
		MaxRatePPS:           maxRate,
	}
	if IsAutoPorts(req.Ports) {
		est.PortsLabel = AutoPortsLabel(effectiveIPs)
	}
	return est, resolution, nil
}

// estimateThroughput computes realistic hosts/sec accounting for host discovery + port scan + HTTP fingerprinting.
func estimateThroughput(maxRatePPS, concurrency, portCount int, httpFP bool) float64 {
	// Stage 1: ~2 probes per IP for host discovery.
	// Stage 2: ~10% assumed active hosts * portCount * 2 packets.
	// Stage 3: HTTP fingerprint adds slight overhead per active host.
	effectivePacketsPerHost := 2.0 + 0.12*float64(portCount)*2.0
	if httpFP {
		effectivePacketsPerHost += 1.5
	}
	rateBound := float64(maxRatePPS) / effectivePacketsPerHost
	concBound := float64(concurrency) * 1.5

	hps := math.Min(rateBound, concBound)
	if hps < 2.0 {
		hps = 2.0
	}
	return hps
}

// Calibrate runs a fast micro-probe on up to 8 sample IPs to measure real-world
// throughput and compute an adaptive chunk size in [32..512].
func Calibrate(ctx context.Context, ips []string, chunkTargetSec int, concurrency int, probeFn func(ctx context.Context, ip string) (bool, time.Duration)) CalibrationResult {
	if chunkTargetSec <= 0 {
		chunkTargetSec = DefaultChunkTargetSec
	}
	if concurrency <= 0 {
		concurrency = 16
	}
	if len(ips) == 0 || probeFn == nil {
		return CalibrationResult{
			HostsPerSec: 10,
			ChunkSize:   RecommendChunkSize(len(ips), 10, chunkTargetSec),
		}
	}

	sampleCount := len(ips)
	if sampleCount > 8 {
		sampleCount = 8
	}

	// Pick evenly spread indices across the scope for representative sampling.
	samples := make([]string, 0, sampleCount)
	step := float64(len(ips)) / float64(sampleCount)
	for i := 0; i < sampleCount; i++ {
		idx := int(math.Floor(float64(i) * step))
		if idx >= len(ips) {
			idx = len(ips) - 1
		}
		samples = append(samples, ips[idx])
	}

	start := time.Now()
	alive := 0
	var totalLat time.Duration
	for _, ip := range samples {
		if ctx.Err() != nil {
			break
		}
		ok, lat := probeFn(ctx, ip)
		if ok {
			alive++
		}
		totalLat += lat
	}
	elapsed := time.Since(start)
	if elapsed <= 0 {
		elapsed = time.Millisecond
	}

	avgLat := totalLat / time.Duration(sampleCount)
	if avgLat <= 0 {
		avgLat = 20 * time.Millisecond
	}
	// Extrapolate parallel hosts/sec from average single-probe latency and concurrency.
	hps := float64(concurrency) / avgLat.Seconds()
	if hps < 2.0 {
		hps = 2.0
	}
	if hps > 500.0 {
		hps = 500.0
	}

	return CalibrationResult{
		SampledIPs:   sampleCount,
		AliveIPs:     alive,
		AvgLatencyMs: avgLat.Milliseconds(),
		HostsPerSec:  math.Round(hps*10) / 10,
		ChunkSize:    RecommendChunkSize(len(ips), hps, chunkTargetSec),
		Elapsed:      elapsed,
	}
}

// RecommendChunkSize chooses an adaptive chunk size bounded to [32..512] targeting chunkTargetSec.
func RecommendChunkSize(totalIPs int, hostsPerSec float64, chunkTargetSec int) int {
	if totalIPs <= 0 {
		return MinChunkSize
	}
	if chunkTargetSec <= 0 {
		chunkTargetSec = DefaultChunkTargetSec
	}
	if hostsPerSec <= 0 {
		hostsPerSec = 10
	}

	raw := int(math.Round(hostsPerSec * float64(chunkTargetSec)))
	// Snap to multiples of 32 for clean ledger chunks.
	snapped := ((raw + 16) / 32) * 32
	if snapped < MinChunkSize {
		snapped = MinChunkSize
	}
	if snapped > MaxChunkSize {
		snapped = MaxChunkSize
	}
	if totalIPs < snapped {
		// Still report a clean chunk size, capped to totalIPs when very small scope.
		if totalIPs < MinChunkSize {
			return totalIPs
		}
		return snapped
	}
	return snapped
}

// BuildChunks partitions normalized IPs into deterministic ScanChunk records (Coverage Ledger).
func BuildChunks(scanRunID string, ips []string, chunkSize int) []domain.ScanChunk {
	if len(ips) == 0 {
		return nil
	}
	if chunkSize <= 0 {
		chunkSize = MinChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}

	numChunks := (len(ips) + chunkSize - 1) / chunkSize
	chunks := make([]domain.ScanChunk, 0, numChunks)
	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(ips) {
			end = len(ips)
		}
		slice := make([]string, end-start)
		copy(slice, ips[start:end])

		chunks = append(chunks, domain.ScanChunk{
			ID:         fmt.Sprintf("%s-chunk-%04d", scanRunID, i),
			ScanRunID:  scanRunID,
			ChunkIndex: i,
			Targets:    slice,
			IPCount:    len(slice),
			Status:     domain.ChunkStatusPending,
		})
	}
	return chunks
}
