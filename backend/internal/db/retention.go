package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// RetentionPolicy bounds the history the store keeps, so continuous daily scanning does not
// grow the store (and, for the encrypted file store, the process heap) without limit. The
// current inventory (hosts, services, overrides, triage, signatures, users, settings) is
// never touched; only per-run history is. Zero in a field keeps that history forever.
type RetentionPolicy struct {
	// Days removes change events and service observations older than this many days (the
	// newest observation of every service is always kept as its evidence receipt).
	Days int
	// ObservationsPerService keeps the newest N observations (evidence history) per service.
	ObservationsPerService int
	// ChangesPerHost keeps the newest N change events per host. Removed events are folded
	// into a per-host summary shown on the host timeline.
	ChangesPerHost int
	// SnapshotRuns keeps the inventory snapshot (scan diff, per-run export) of the newest N
	// runs; the newest two runs of every profile keep theirs as well.
	SnapshotRuns int
	// RawXMLRuns keeps the merged raw nmap XML (download, DefectDojo import) of the newest N runs.
	RawXMLRuns int
	// ChunkDetailRuns keeps per-chunk target lists and nmap command lines of the newest N
	// runs. Older runs keep their chunk ledger (status, counts, timing) without them.
	ChunkDetailRuns int
	// AuditEntries keeps the newest N audit log entries.
	AuditEntries int
	// ExportEntries keeps the newest N DefectDojo export log entries.
	ExportEntries int
}

// fullEvidenceObservations is how many of the newest observations per service keep their
// full HTTP fingerprint; older ones keep the slim form (title, status, server, TLS identity),
// which is all the evidence history and the host timeline show.
const fullEvidenceObservations = 3

// DefaultRetention is sized for daily scans of a few /16s: months of change history and a
// month of evidence per service, while the store stays a small multiple of the inventory.
func DefaultRetention() RetentionPolicy {
	return RetentionPolicy{
		Days:                   90,
		ObservationsPerService: 30,
		ChangesPerHost:         200,
		SnapshotRuns:           10,
		RawXMLRuns:             10,
		ChunkDetailRuns:        10,
		AuditEntries:           20000,
		ExportEntries:          1000,
	}
}

// Enabled reports whether the policy limits anything.
func (p RetentionPolicy) Enabled() bool { return p != RetentionPolicy{} }

func (p RetentionPolicy) String() string {
	if !p.Enabled() {
		return "off (all history kept)"
	}
	v := func(n int) string {
		if n <= 0 {
			return "all"
		}
		return strconv.Itoa(n)
	}
	return fmt.Sprintf("days=%s observations/service=%s changes/host=%s snapshots=%s raw_xml=%s chunk_detail=%s audit=%s exports=%s",
		v(p.Days), v(p.ObservationsPerService), v(p.ChangesPerHost), v(p.SnapshotRuns), v(p.RawXMLRuns),
		v(p.ChunkDetailRuns), v(p.AuditEntries), v(p.ExportEntries))
}

// RetentionFromEnv returns DefaultRetention adjusted by the environment:
//
//	DZIECIOL_RETENTION=off                  keep all history (disables every limit below)
//	DZIECIOL_RETENTION_DAYS                 age limit for change events and observations (90)
//	DZIECIOL_RETENTION_OBSERVATIONS         observations kept per service (30)
//	DZIECIOL_RETENTION_CHANGES_PER_HOST     change events kept per host (200)
//	DZIECIOL_RETENTION_SNAPSHOTS            runs that keep their inventory snapshot (10)
//	DZIECIOL_RETENTION_RAW_XML              runs that keep their raw nmap XML (10)
//	DZIECIOL_RETENTION_CHUNK_DETAIL         runs that keep chunk targets and nmap commands (10)
//	DZIECIOL_RETENTION_AUDIT                audit log entries kept (20000)
//	DZIECIOL_RETENTION_EXPORTS              DefectDojo export log entries kept (1000)
//
// 0 keeps that kind of history forever. Invalid values fall back to the default.
func RetentionFromEnv() RetentionPolicy {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DZIECIOL_RETENTION"))) {
	case "off", "false", "no", "0", "disabled", "none":
		return RetentionPolicy{}
	}
	p := DefaultRetention()
	for _, e := range []struct {
		key string
		dst *int
	}{
		{"DZIECIOL_RETENTION_DAYS", &p.Days},
		{"DZIECIOL_RETENTION_OBSERVATIONS", &p.ObservationsPerService},
		{"DZIECIOL_RETENTION_CHANGES_PER_HOST", &p.ChangesPerHost},
		{"DZIECIOL_RETENTION_SNAPSHOTS", &p.SnapshotRuns},
		{"DZIECIOL_RETENTION_RAW_XML", &p.RawXMLRuns},
		{"DZIECIOL_RETENTION_CHUNK_DETAIL", &p.ChunkDetailRuns},
		{"DZIECIOL_RETENTION_AUDIT", &p.AuditEntries},
		{"DZIECIOL_RETENTION_EXPORTS", &p.ExportEntries},
	} {
		raw := strings.TrimSpace(os.Getenv(e.key))
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			log.Printf("[WARN] %s=%q is not a non-negative integer; using %d", e.key, raw, *e.dst)
			continue
		}
		*e.dst = n
	}
	return p
}

// CompactionReport counts what one compaction pass removed or slimmed.
type CompactionReport struct {
	Observations        int // removed
	SlimmedObservations int // full HTTP fingerprint replaced by the slim form
	ChangeEvents        int // removed (folded into per-host summaries)
	Snapshots           int // removed
	MigratedSnapshots   int // legacy full snapshots rewritten in the slim, compressed form
	RawNmapXML          int // runs whose raw XML was dropped
	ChunkDetails        int // runs whose chunk targets and command lines were dropped
	AuditLogs           int
	Exports             int
	TelemetryDocs       int // per-run telemetry of runs that no longer exist
	Duration            time.Duration
}

// Empty reports whether the pass changed nothing.
func (r CompactionReport) Empty() bool {
	return r.Observations == 0 && r.SlimmedObservations == 0 && r.ChangeEvents == 0 && r.Snapshots == 0 &&
		r.MigratedSnapshots == 0 && r.RawNmapXML == 0 && r.ChunkDetails == 0 && r.AuditLogs == 0 &&
		r.Exports == 0 && r.TelemetryDocs == 0
}

func (r CompactionReport) String() string {
	if r.Empty() {
		return "nothing to compact"
	}
	var parts []string
	add := func(n int, what string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, what))
		}
	}
	add(r.Observations, "observations removed")
	add(r.SlimmedObservations, "older observations slimmed")
	add(r.ChangeEvents, "change events folded into host summaries")
	add(r.Snapshots, "scan snapshots removed")
	add(r.MigratedSnapshots, "legacy scan snapshots slimmed")
	add(r.RawNmapXML, "runs' raw nmap XML removed")
	add(r.ChunkDetails, "runs' chunk targets/commands removed")
	add(r.AuditLogs, "audit entries removed")
	add(r.Exports, "DefectDojo export log entries removed")
	add(r.TelemetryDocs, "orphaned run telemetry documents removed")
	return strings.Join(parts, ", ") + fmt.Sprintf(" (%s)", r.Duration.Round(time.Millisecond))
}

// Compactor is implemented by stores that can apply a RetentionPolicy (MemoryStore and
// FileStore in memory, PostgresStore with SQL deletes). Like SettingsStore it is optional:
// callers type-assert it.
type Compactor interface {
	Compact(ctx context.Context, p RetentionPolicy) (CompactionReport, error)
}

// ChangeRollupStore returns the summary of a host's change events removed by retention.
type ChangeRollupStore interface {
	// GetChangeRollup returns nil (and no error) when nothing was removed for the host.
	GetChangeRollup(ctx context.Context, hostID string) (*domain.ChangeRollup, error)
}

var (
	_ Compactor         = (*MemoryStore)(nil)
	_ ChangeRollupStore = (*MemoryStore)(nil)
)

// CompactAndLog runs one compaction pass if store supports it and logs what changed. It also
// runs with retention off: the file store migrates legacy snapshots in the same pass.
func CompactAndLog(ctx context.Context, store Store, p RetentionPolicy, when string) {
	c, ok := store.(Compactor)
	if !ok {
		return
	}
	rep, err := c.Compact(ctx, p)
	if err != nil {
		log.Printf("[WARN] retention (%s): %v", when, err)
		return
	}
	if !rep.Empty() {
		log.Printf("[INFO] retention (%s): %s", when, rep)
	}
}

// foldChange adds one removed change event to a host summary.
func foldChange(r *domain.ChangeRollup, eventType, severity string, at time.Time) {
	r.Count++
	if r.ByType == nil {
		r.ByType = map[string]int{}
	}
	r.ByType[eventType]++
	if severity != "" {
		if r.BySeverity == nil {
			r.BySeverity = map[string]int{}
		}
		r.BySeverity[severity]++
	}
	if r.From.IsZero() || at.Before(r.From) {
		r.From = at
	}
	if at.After(r.To) {
		r.To = at
	}
}

func isTerminalRun(status string) bool {
	switch status {
	case domain.ScanStatusCompleted, domain.ScanStatusFailed, domain.ScanStatusStopped:
		return true
	}
	return false
}
