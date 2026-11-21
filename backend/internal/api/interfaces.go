package api

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

// EstimateRequest is accepted by POST /api/v1/targets/estimate.
type EstimateRequest struct {
	Targets        []string `json:"targets"`
	Exclusions     []string `json:"exclusions"`
	Ports          string   `json:"ports"`
	MaxRatePPS     int      `json:"max_rate_pps"`
	Concurrency    int      `json:"concurrency"`
	ChunkTargetSec int      `json:"chunk_target_sec"`
	WindowEnabled  bool     `json:"window_enabled"`
	WindowStart    string   `json:"window_start"`
	WindowEnd      string   `json:"window_end"`
	Timezone       string   `json:"timezone"`
}

// ScanRunner is the clean dependency boundary for active scanning orchestration.
// Production wires cmd/server.LiveScanRunner (scanner.Engine), wrapped by
// AgentAwareRunner so profiles bound to a remote agent are dispatched to it;
// StubScanRunner is the fallback used by tests when no runner is injected.
type ScanRunner interface {
	EstimateTargets(ctx context.Context, req EstimateRequest) (domain.TargetEstimate, error)
	StartScan(ctx context.Context, run *domain.ScanRun, profile *domain.ScanProfile, exclusions []domain.TargetExclusion) error
	PauseScan(ctx context.Context, scanRunID string) error
	ResumeScan(ctx context.Context, scanRunID string) error
	StopScan(ctx context.Context, scanRunID string) error
	NmapAvailable() bool
}

// StubScanRunner is a safe default ScanRunner used when no external scanner engine is injected.
// It never sends packets: scans complete immediately with no observations.
type StubScanRunner struct {
	store    db.Store
	pipeline *ingest.Pipeline
	hub      *SSEHub

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

// NewStubScanRunner returns a StubScanRunner that records scan runs in store.
func NewStubScanRunner(store db.Store, pipeline *ingest.Pipeline, hub *SSEHub) *StubScanRunner {
	return &StubScanRunner{
		store:    store,
		pipeline: pipeline,
		hub:      hub,
		cancels:  make(map[string]context.CancelFunc),
	}
}

func (s *StubScanRunner) NmapAvailable() bool { return false }

func (s *StubScanRunner) EstimateTargets(_ context.Context, req EstimateRequest) (domain.TargetEstimate, error) {
	total := 0
	for _, t := range req.Targets {
		total += countTargetIPs(t)
	}
	excluded := 0
	for _, ex := range req.Exclusions {
		c := countTargetIPs(ex)
		if c > total {
			c = total
		}
		excluded += c
	}
	effective := total - excluded
	if effective < 0 {
		effective = 0
	}

	rate := req.MaxRatePPS
	if rate <= 0 {
		rate = 500
	}
	ports := 4
	if strings.TrimSpace(req.Ports) != "" {
		ports = len(strings.Split(req.Ports, ","))
	}
	ipsPerSec := float64(rate) / float64(maxInt(ports*2, 1))
	if ipsPerSec < 5 {
		ipsPerSec = 5
	}
	estSec := int64(math.Ceil(float64(effective) / ipsPerSec))

	chunkTargetSec := req.ChunkTargetSec
	if chunkTargetSec <= 0 {
		chunkTargetSec = 60
	}
	chunkSize := int(math.Round(ipsPerSec * float64(chunkTargetSec)))
	if chunkSize < 32 {
		chunkSize = 32
	}
	if chunkSize > 512 {
		chunkSize = 512
	}
	chunkCount := 0
	if effective > 0 {
		chunkCount = int(math.Ceil(float64(effective) / float64(chunkSize)))
	}

	windowSec := int64(8 * 3600)
	if req.WindowEnabled && req.WindowStart != "" && req.WindowEnd != "" {
		if d := estimateWindowDurationSec(req.WindowStart, req.WindowEnd); d > 0 {
			windowSec = d
		}
	}
	fits := !req.WindowEnabled || estSec <= windowSec
	estWindows := 1
	if windowSec > 0 && estSec > windowSec {
		estWindows = int(math.Ceil(float64(estSec) / float64(windowSec)))
	}

	return domain.TargetEstimate{
		TotalIPs:             total,
		ExcludedIPs:          excluded,
		EffectiveIPs:         effective,
		RecommendedChunkSize: chunkSize,
		ChunkCount:           chunkCount,
		EstimatedSeconds:     estSec,
		FitsInWindow:         fits,
		EstimatedWindows:     estWindows,
	}, nil
}

func (s *StubScanRunner) StartScan(ctx context.Context, run *domain.ScanRun, profile *domain.ScanProfile, _ []domain.TargetExclusion) error {
	est, _ := s.EstimateTargets(ctx, EstimateRequest{
		Targets:        profile.Targets,
		Ports:          profile.AllowedPorts,
		MaxRatePPS:     profile.MaxRatePPS,
		ChunkTargetSec: profile.ChunkTargetSec,
	})
	run.TotalIPs = est.EffectiveIPs
	run.TotalChunks = maxInt(est.ChunkCount, 1)
	run.Status = domain.ScanStatusRunning
	_ = s.store.UpdateScanRun(ctx, run)

	chunk := domain.ScanChunk{
		ID:         db.NewID(),
		ScanRunID:  run.ID,
		ChunkIndex: 0,
		Targets:    profile.Targets,
		IPCount:    est.EffectiveIPs,
		Status:     domain.ChunkStatusDone,
	}
	now := time.Now().UTC()
	chunk.StartedAt = &now
	chunk.FinishedAt = &now
	_ = s.store.SaveScanChunks(ctx, run.ID, []domain.ScanChunk{chunk})

	run.CompletedChunks = 1
	run.ScannedIPs = est.EffectiveIPs
	run.Status = domain.ScanStatusCompleted
	run.FinishedAt = &now
	_ = s.store.UpdateScanRun(ctx, run)

	if s.hub != nil {
		s.hub.Publish(domain.LiveEvent{
			Type:      "scan.completed",
			ScanRunID: run.ID,
			Timestamp: now,
			Payload:   map[string]any{"status": run.Status, "scanned_ips": run.ScannedIPs},
		})
	}
	return nil
}

func (s *StubScanRunner) PauseScan(ctx context.Context, scanRunID string) error {
	run, err := s.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		return err
	}
	run.Status = domain.ScanStatusPausedUser
	return s.store.UpdateScanRun(ctx, run)
}

func (s *StubScanRunner) ResumeScan(ctx context.Context, scanRunID string) error {
	run, err := s.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		return err
	}
	run.Status = domain.ScanStatusRunning
	return s.store.UpdateScanRun(ctx, run)
}

func (s *StubScanRunner) StopScan(ctx context.Context, scanRunID string) error {
	s.mu.Lock()
	if cancel, ok := s.cancels[scanRunID]; ok {
		cancel()
		delete(s.cancels, scanRunID)
	}
	s.mu.Unlock()
	run, err := s.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	run.Status = domain.ScanStatusStopped
	run.FinishedAt = &now
	return s.store.UpdateScanRun(ctx, run)
}

func countTargetIPs(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if strings.Contains(raw, "/") {
		_, ipnet, err := net.ParseCIDR(raw)
		if err != nil {
			return 0
		}
		ones, bits := ipnet.Mask.Size()
		if bits == 32 && ones <= 32 {
			shift := bits - ones
			if shift >= 24 {
				return 1 << 24
			}
			return 1 << shift
		}
		return 1
	}
	if strings.Contains(raw, "-") {
		parts := strings.SplitN(raw, "-", 2)
		ip1 := net.ParseIP(strings.TrimSpace(parts[0])).To4()
		ip2 := net.ParseIP(strings.TrimSpace(parts[1])).To4()
		if ip1 != nil && ip2 != nil {
			a := binary.BigEndian.Uint32(ip1)
			b := binary.BigEndian.Uint32(ip2)
			if b >= a {
				return int(b-a) + 1
			}
		}
		return 1
	}
	return 1
}

func estimateWindowDurationSec(startHHMM, endHHMM string) int64 {
	s, err1 := parseHHMM(startHHMM)
	e, err2 := parseHHMM(endHHMM)
	if err1 != nil || err2 != nil {
		return 0
	}
	if e > s {
		return int64(e-s) * 60
	}
	return int64((24*60-s)+e) * 60
}

func parseHHMM(s string) (int, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, errors.New("invalid HH:MM")
	}
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
