package scanner

import (
	"context"
	"sync"
	"time"
)

// ThrottleEvent is emitted whenever the Target Noise Governor slows scanning down.
type ThrottleEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Host       string    `json:"host"`
	Reason     string    `json:"reason"` // timeout_burst, http_429, rst_burst
	OldRate    float64   `json:"old_rate"`
	NewRate    float64   `json:"new_rate"`
	ErrorCount int       `json:"error_count"`
}

// GovernorStats exposes current rate limiting and backoff telemetry.
type GovernorStats struct {
	CurrentRate     float64 `json:"current_rate"`
	InitialRate     float64 `json:"initial_rate"`
	ThrottleCount   int     `json:"throttle_count"`
	TimeoutCount    int     `json:"timeout_count"`
	HTTP429Count    int     `json:"http_429_count"`
	RSTCount        int     `json:"rst_count"`
	IsThrottled     bool    `json:"is_throttled"`
}

// GovernorConfig configures the global/per-host token buckets and Target Noise Governor.
type GovernorConfig struct {
	GlobalRatePerSec  float64
	GlobalBurst       int
	PerHostRatePerSec float64
	PerHostBurst      int
	MinRatePerSec     float64
	ErrorThreshold    int
	ErrorWindow       time.Duration
	CooldownDuration  time.Duration
	BackoffFactor     float64
	OnThrottle        func(ThrottleEvent)
	Now               func() time.Time
}

type tokenBucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate float64, burst int, now time.Time) *tokenBucket {
	if rate <= 0 {
		rate = 10
	}
	if burst < 1 {
		burst = 1
	}
	return &tokenBucket{
		rate:   rate,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   now,
	}
}

func (b *tokenBucket) refill(now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
}

func (b *tokenBucket) take(now time.Time) (bool, time.Duration) {
	b.refill(now)
	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true, 0
	}
	needed := 1.0 - b.tokens
	waitSec := needed / b.rate
	if waitSec < 0.001 {
		waitSec = 0.001
	}
	return false, time.Duration(waitSec * float64(time.Second))
}

// Governor enforces global and per-host token-bucket rate limits and dynamically backs off
// on timeout, HTTP 429, or TCP RST bursts (Target Noise Governor).
type Governor struct {
	mu               sync.Mutex
	cfg              GovernorConfig
	global           *tokenBucket
	perHost          map[string]*tokenBucket
	initialRate      float64
	errorTimestamps  []time.Time
	errorHosts       []string
	errorReasons     []string
	distress         float64
	lastBackoff      time.Time
	successStreak    int
	throttleCount    int
	timeoutCount     int
	http429Count     int
	rstCount         int
	nowFn            func() time.Time
}

// NewGovernor constructs a thread-safe rate limiter with Target Noise Governor protection.
func NewGovernor(cfg GovernorConfig) *Governor {
	if cfg.GlobalRatePerSec <= 0 {
		cfg.GlobalRatePerSec = 100
	}
	if cfg.GlobalBurst <= 0 {
		cfg.GlobalBurst = int(cfg.GlobalRatePerSec)
		if cfg.GlobalBurst < 4 {
			cfg.GlobalBurst = 4
		}
	}
	if cfg.PerHostRatePerSec <= 0 {
		cfg.PerHostRatePerSec = 10
	}
	if cfg.PerHostBurst <= 0 {
		cfg.PerHostBurst = 4
	}
	if cfg.MinRatePerSec <= 0 {
		cfg.MinRatePerSec = 5
	}
	if cfg.MinRatePerSec > cfg.GlobalRatePerSec {
		cfg.MinRatePerSec = cfg.GlobalRatePerSec
	}
	if cfg.ErrorThreshold <= 0 {
		cfg.ErrorThreshold = 5
	}
	if cfg.ErrorWindow <= 0 {
		cfg.ErrorWindow = 10 * time.Second
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = 5 * time.Second
	}
	if cfg.BackoffFactor <= 0 || cfg.BackoffFactor >= 1 {
		cfg.BackoffFactor = 0.5
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	now := nowFn()
	return &Governor{
		cfg:         cfg,
		global:      newTokenBucket(cfg.GlobalRatePerSec, cfg.GlobalBurst, now),
		perHost:     make(map[string]*tokenBucket),
		initialRate: cfg.GlobalRatePerSec,
		distress:    1,
		nowFn:       nowFn,
	}
}

// Allow checks whether an immediate token is available globally and for the host.
func (g *Governor) Allow(host string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.nowFn()
	g.global.refill(now)
	if g.global.tokens < 1.0 {
		return false
	}
	hb := g.hostBucketLocked(host, now)
	hb.refill(now)
	if hb.tokens < 1.0 {
		return false
	}
	g.global.tokens -= 1.0
	hb.tokens -= 1.0
	return true
}

// Wait blocks until both global and per-host token buckets grant permission or ctx expires.
func (g *Governor) Wait(ctx context.Context, host string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		g.mu.Lock()
		now := g.nowFn()
		okG, waitG := g.global.take(now)
		var okH bool
		var waitH time.Duration
		if okG {
			hb := g.hostBucketLocked(host, now)
			okH, waitH = hb.take(now)
			if !okH {
				// Refund global token since host bucket was not ready.
				g.global.tokens += 1.0
			}
		}
		g.mu.Unlock()

		if okG && okH {
			return nil
		}
		wait := waitG
		if waitH > wait {
			wait = waitH
		}
		if wait <= 0 {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// RecordTimeout logs a network timeout and triggers backoff when burst threshold is reached.
func (g *Governor) RecordTimeout(host string) {
	g.recordNoise(host, "timeout_burst", 1)
}

// RecordRST logs a TCP RST burst event and triggers backoff when threshold is reached.
func (g *Governor) RecordRST(host string) {
	g.recordNoise(host, "rst_burst", 1)
}

// RecordHTTPStatus inspects HTTP responses; 429 Too Many Requests triggers immediate backoff weight.
func (g *Governor) RecordHTTPStatus(host string, statusCode int) {
	if statusCode == 429 {
		// 429 is an explicit target signal: count with high weight to back off promptly.
		g.recordNoise(host, "http_429", 2)
		return
	}
	if statusCode == 503 {
		g.recordNoise(host, "http_503", 1)
		return
	}
	if statusCode >= 200 && statusCode < 400 {
		g.RecordSuccess(host)
	}
}

// RecordSuccess enables gentle additive recovery (AIMD) after sustained healthy probes.
func (g *Governor) RecordSuccess(host string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.global.rate >= g.initialRate && g.distress >= 1 {
		return
	}
	now := g.nowFn()
	if now.Sub(g.lastBackoff) < g.cfg.CooldownDuration {
		return
	}
	g.successStreak++
	if g.successStreak >= 10 {
		g.successStreak = 0
		newRate := g.global.rate * 1.15
		if newRate > g.initialRate {
			newRate = g.initialRate
		}
		g.global.rate = newRate
		if g.distress = g.distress * 1.15; g.distress > 1 {
			g.distress = 1
		}
	}
}

func (g *Governor) recordNoise(host, reason string, weight int) {
	var evt *ThrottleEvent
	var cb func(ThrottleEvent)

	g.mu.Lock()
	now := g.nowFn()
	g.successStreak = 0
	switch reason {
	case "timeout_burst":
		g.timeoutCount++
	case "http_429":
		g.http429Count++
	case "rst_burst":
		g.rstCount++
	}

	for i := 0; i < weight; i++ {
		g.errorTimestamps = append(g.errorTimestamps, now)
		g.errorHosts = append(g.errorHosts, host)
		g.errorReasons = append(g.errorReasons, reason)
	}

	// Prune events outside the sliding window.
	cutoff := now.Add(-g.cfg.ErrorWindow)
	k := 0
	for i, ts := range g.errorTimestamps {
		if !ts.Before(cutoff) {
			g.errorTimestamps[k], g.errorHosts[k], g.errorReasons[k] = ts, g.errorHosts[i], g.errorReasons[i]
			k++
		}
	}
	g.errorTimestamps, g.errorHosts, g.errorReasons = g.errorTimestamps[:k], g.errorHosts[:k], g.errorReasons[:k]

	if len(g.errorTimestamps) >= g.cfg.ErrorThreshold {
		// Timeouts are a weak signal: one slow or silent host (a tarpit, a service that
		// never answers HTTP) times out on every request. They slow the whole scan only
		// when they come from several hosts at once (network or target-wide distress);
		// otherwise only the offending host's bucket is backed off. Explicit signals
		// (HTTP 429/503, reset bursts) back off globally even from a single host.
		explicit := false
		distinct := map[string]bool{}
		for i := range g.errorHosts {
			distinct[g.errorHosts[i]] = true
			if g.errorReasons[i] != "timeout_burst" {
				explicit = true
			}
		}
		minHosts := 3
		if g.cfg.ErrorThreshold < minHosts {
			minHosts = g.cfg.ErrorThreshold
		}
		errCount := len(g.errorTimestamps)
		if explicit || len(distinct) >= minHosts {
			oldRate := g.global.rate
			newRate := oldRate * g.cfg.BackoffFactor
			if newRate < g.cfg.MinRatePerSec {
				newRate = g.cfg.MinRatePerSec
			}
			g.global.rate = newRate
			g.lastBackoff = now
			g.throttleCount++
			if explicit {
				g.distress *= g.cfg.BackoffFactor
				if g.distress < minDistressFactor {
					g.distress = minDistressFactor
				}
			}
			g.clearErrorsLocked("")

			if hb, ok := g.perHost[host]; ok {
				hb.rate *= g.cfg.BackoffFactor
				if hb.rate < 1.0 {
					hb.rate = 1.0
				}
			}
			e := ThrottleEvent{Timestamp: now, Host: host, Reason: reason, OldRate: oldRate, NewRate: newRate, ErrorCount: errCount}
			evt = &e
			cb = g.cfg.OnThrottle
		} else if hostErrs := countHost(g.errorHosts, host); hostErrs >= g.cfg.ErrorThreshold {
			hb := g.hostBucketLocked(host, now)
			oldRate := hb.rate
			hb.rate *= g.cfg.BackoffFactor
			if hb.rate < 1.0 {
				hb.rate = 1.0
			}
			g.clearErrorsLocked(host)
			e := ThrottleEvent{Timestamp: now, Host: host, Reason: reason + "_host", OldRate: oldRate, NewRate: hb.rate, ErrorCount: hostErrs}
			evt = &e
			cb = g.cfg.OnThrottle
		}
	}
	g.mu.Unlock()

	if evt != nil && cb != nil {
		cb(*evt)
	}
}

// minDistressFactor bounds how far explicit target distress can slow nmap shares.
const minDistressFactor = 0.1

func countHost(hosts []string, host string) int {
	n := 0
	for _, h := range hosts {
		if h == host {
			n++
		}
	}
	return n
}

// clearErrorsLocked drops windowed error events (all of them when host == "").
func (g *Governor) clearErrorsLocked(host string) {
	if host == "" {
		g.errorTimestamps, g.errorHosts, g.errorReasons = g.errorTimestamps[:0], g.errorHosts[:0], g.errorReasons[:0]
		return
	}
	k := 0
	for i := range g.errorHosts {
		if g.errorHosts[i] != host {
			g.errorTimestamps[k], g.errorHosts[k], g.errorReasons[k] = g.errorTimestamps[i], g.errorHosts[i], g.errorReasons[i]
			k++
		}
	}
	g.errorTimestamps, g.errorHosts, g.errorReasons = g.errorTimestamps[:k], g.errorHosts[:k], g.errorReasons[:k]
}

// DistressFactor (0.1..1) reflects only explicit target distress (HTTP 429/503, reset
// bursts). nmap shares are scaled by it: timeouts alone never slow the nmap processes.
func (g *Governor) DistressFactor() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.distress
}

// CurrentRate returns the active global requests/packets per second limit.
func (g *Governor) CurrentRate() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.global.rate
}

// Stats returns a snapshot of rate limiter and backoff metrics.
func (g *Governor) Stats() GovernorStats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return GovernorStats{
		CurrentRate:   g.global.rate,
		InitialRate:   g.initialRate,
		ThrottleCount: g.throttleCount,
		TimeoutCount:  g.timeoutCount,
		HTTP429Count:  g.http429Count,
		RSTCount:      g.rstCount,
		IsThrottled:   g.global.rate < g.initialRate,
	}
}

func (g *Governor) hostBucketLocked(host string, now time.Time) *tokenBucket {
	if host == "" {
		host = "_global_"
	}
	if hb, ok := g.perHost[host]; ok {
		return hb
	}
	// Cap per-host map size to prevent unbounded growth on /16+ scans.
	if len(g.perHost) > 4096 {
		g.perHost = make(map[string]*tokenBucket, 256)
	}
	hb := newTokenBucket(g.cfg.PerHostRatePerSec, g.cfg.PerHostBurst, now)
	g.perHost[host] = hb
	return hb
}
