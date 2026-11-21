package ingest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// IngestRequest drives the unified ingestion pipeline for MANUAL, IMPORT_CSV,
// IMPORT_JSON, PASSIVE, and ACTIVE scanner observations.
type IngestRequest struct {
	ScanRunID        string // optional: reuse existing ScanRun (e.g. active scan)
	ProfileID        string
	RunType          string // domain.ScanType*
	ScanName         string
	Notes            string
	TriggeredBy      string
	RawNmapXML       string
	Observations     []domain.ObservedHost
	ScopeIPs         []string // optional: full scanned IP list to detect missing/disappeared hosts
	MarkMissingHosts bool
	MissingThreshold int
	GracePeriodHours int
}

// IngestResult summarizes what the unified pipeline persisted and detected.
type IngestResult struct {
	ScanRun         *domain.ScanRun      `json:"scan_run"`
	HostsProcessed  int                  `json:"hosts_processed"`
	ServicesUpserted int                 `json:"services_upserted"`
	ChangesDetected int                  `json:"changes_detected"`
	Changes         []domain.ChangeEvent `json:"changes,omitempty"`
}

// Pipeline processes observations from every source through one consistent workflow:
// Signature & Intelligence analysis -> Diffing & Change Events -> Host Lifecycle & Time-of-Day ->
// Encrypted Persistence (never overwriting analyst overrides) -> Snapshot -> Live SSE.
type Pipeline struct {
	store    db.Store
	analyzer Analyzer
	emit     func(domain.LiveEvent)
	notifier atomic.Value // notifierBox
}

// ChangeNotifier receives the change events produced by one pipeline run (e.g. the
// outbound alert webhook). Implementations must not block for long.
type ChangeNotifier interface {
	NotifyChanges(ctx context.Context, run *domain.ScanRun, changes []domain.ChangeEvent)
}

type notifierBox struct{ n ChangeNotifier }

// SetNotifier registers the notifier called after every ingest that produced changes.
func (p *Pipeline) SetNotifier(n ChangeNotifier) {
	p.notifier.Store(notifierBox{n: n})
}

func NewPipeline(store db.Store, analyzer Analyzer, emit func(domain.LiveEvent)) *Pipeline {
	if analyzer == nil {
		analyzer = NewDefaultAnalyzer()
	}
	return &Pipeline{
		store:    store,
		analyzer: analyzer,
		emit:     emit,
	}
}

// Analyzer returns the active Analyzer implementation.
func (p *Pipeline) Analyzer() Analyzer {
	return p.analyzer
}

// ProcessObservations runs the complete unified pipeline.
func (p *Pipeline) ProcessObservations(ctx context.Context, req IngestRequest) (*IngestResult, error) {
	now := time.Now().UTC()
	runType := req.RunType
	if runType == "" {
		runType = domain.ScanTypeManual
	}
	scanName := strings.TrimSpace(req.ScanName)
	if scanName == "" {
		scanName = fmt.Sprintf("%s %s", runType, now.Format("2006-01-02 15:04"))
	}

	var run *domain.ScanRun
	var err error
	if req.ScanRunID != "" {
		run, err = p.store.GetScanRun(ctx, req.ScanRunID)
		if err != nil {
			return nil, fmt.Errorf("load scan run %s: %w", req.ScanRunID, err)
		}
	} else {
		run = &domain.ScanRun{
			ID:          db.NewID(),
			ProfileID:   req.ProfileID,
			Name:        scanName,
			RunType:     runType,
			Status:      domain.ScanStatusRunning,
			Notes:       req.Notes,
			TotalIPs:    len(req.Observations),
			TotalChunks: 1,
			RawNmapXML:  req.RawNmapXML,
			TriggeredBy: req.TriggeredBy,
			StartedAt:   now,
		}
		if err := p.store.CreateScanRun(ctx, run); err != nil {
			return nil, fmt.Errorf("create scan run: %w", err)
		}
	}

	// Find previous completed scan run ID for change attribution
	prevScanRunID := ""
	if prevRuns, err := p.store.ListScanRuns(ctx, 10); err == nil {
		for _, pr := range prevRuns {
			if pr.ID != run.ID && pr.Status == domain.ScanStatusCompleted {
				prevScanRunID = pr.ID
				break
			}
		}
	}

	customSigs, _ := p.store.ListSignatures(ctx)
	tagRules := LoadTagRules(ctx, p.store)
	missingThresh := req.MissingThreshold
	if missingThresh <= 0 {
		missingThresh = 2
	}
	graceHours := req.GracePeriodHours
	if graceHours <= 0 {
		graceHours = 24
	}

	seenIPs := make(map[string]bool, len(req.Observations))
	var changes []domain.ChangeEvent
	servicesUpserted := 0
	activeHostsCount := 0

	recordChange := func(ev domain.ChangeEvent) {
		ev.ID = db.NewID()
		ev.ScanRunID = run.ID
		ev.PrevScanRunID = prevScanRunID
		if ev.TimeSlot == "" {
			ev.TimeSlot = domain.TimeSlotFor(now)
		}
		ev.CreatedAt = now
		if err := p.store.AddChangeEvent(ctx, &ev); err == nil {
			changes = append(changes, ev)
			if p.emit != nil {
				p.emit(domain.LiveEvent{
					Type:      "change.detected",
					ScanRunID: run.ID,
					Timestamp: now,
					Payload: map[string]any{
						"change_id":  ev.ID,
						"event_type": ev.EventType,
						"severity":   ev.Severity,
						"host_ip":    ev.HostIP,
						"summary":    ev.Summary,
					},
				})
			}
		}
	}

	for _, obs := range req.Observations {
		ip := strings.TrimSpace(obs.IP)
		if ip == "" {
			continue
		}
		obsAt := obs.ObservedAt
		if obsAt.IsZero() {
			obsAt = now
		}
		seenIPs[ip] = true
		isAlive := obs.IsAlive || len(obs.Services) > 0

		prevHost, err := p.store.GetHostByIP(ctx, ip)
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			return nil, fmt.Errorf("lookup host %s: %w", ip, err)
		}
		// A dead IP that was never seen before is not an asset: do not create a host record
		// (otherwise scanning a mostly empty /16 would create ~65k phantom NEW hosts).
		if !isAlive && prevHost == nil {
			continue
		}

		trans := p.analyzer.EvaluateLifecycle(prevHost, isAlive, obsAt, missingThresh, graceHours)

		host := &domain.Host{
			IP:                ip,
			Hostname:          obs.Hostname,
			Domains:           obs.Domains,
			OSGuess:           obs.OSGuess,
			LifecycleState:    trans.NewState,
			Environment:       obs.Environment,
			Notes:             obs.Notes,
			Tags:              append([]string(nil), obs.Tags...),
			FirstSeen:         obsAt,
			LastSeen:          obsAt,
			TotalScansSeen:    trans.TotalScansSeen,
			TotalScansChecked: trans.TotalScansChecked,
			ConsecutiveMisses: trans.ConsecutiveMisses,
			StateTransitions:  trans.StateTransitions,
			StabilityScore:    trans.StabilityScore,
			TimeOfDayStats:    trans.TimeOfDayStats,
		}
		if prevHost != nil {
			host.ID = prevHost.ID
			host.FirstSeen = prevHost.FirstSeen
			if !isAlive {
				host.LastSeen = prevHost.LastSeen
			}
			if host.Hostname == "" {
				host.Hostname = prevHost.Hostname
			}
			if len(host.Domains) == 0 {
				host.Domains = prevHost.Domains
			}
			if host.OSGuess == "" {
				host.OSGuess = prevHost.OSGuess
			}
			if host.Environment == "" {
				host.Environment = prevHost.Environment
			}
			if host.Notes == "" {
				host.Notes = prevHost.Notes
			}
			host.Tags = appendUnique(prevHost.Tags, obs.Tags...)
		}
		if host.Environment == "" {
			host.Environment = "unknown"
		}
		// Ownership by CIDR: tags / owner / environment from the configured tag rules.
		ApplyTagRules(host, tagRules)

		savedHost, err := p.store.UpsertObservedHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("upsert host %s: %w", ip, err)
		}

		if prevHost == nil {
			recordChange(domain.ChangeEvent{
				HostID:    savedHost.ID,
				HostIP:    ip,
				EventType: "NEW_HOST",
				Severity:  "medium",
				Summary:   fmt.Sprintf("New host discovered: %s (%d services)", ip, len(obs.Services)),
				TimeSlot:  domain.TimeSlotFor(obsAt),
				After:     map[string]any{"ip": ip, "hostname": savedHost.Hostname, "state": savedHost.LifecycleState},
			})
		} else if trans.Changed || trans.IsTimeAnomaly {
			sev := "info"
			evType := "HOST_STATE_CHANGED"
			if trans.NewState == domain.HostStateReactivated {
				sev = "medium"
				evType = "HOST_REACTIVATED"
			} else if trans.IsTimeAnomaly {
				sev = "medium"
				evType = "TIME_ANOMALY"
			} else if trans.IsExpectedSchedule {
				evType = "EXPECTED_OFF_HOURS"
			}
			recordChange(domain.ChangeEvent{
				HostID:             savedHost.ID,
				HostIP:             ip,
				EventType:          evType,
				Severity:           sev,
				Summary:            nonEmpty(trans.Summary, fmt.Sprintf("Host %s state %s -> %s", ip, prevHost.LifecycleState, trans.NewState)),
				TimeSlot:           domain.TimeSlotFor(obsAt),
				IsExpectedSchedule: trans.IsExpectedSchedule,
				IsTimeAnomaly:      trans.IsTimeAnomaly,
				Before:             map[string]any{"lifecycle_state": prevHost.LifecycleState},
				After:              map[string]any{"lifecycle_state": trans.NewState},
			})
		}

		if isAlive {
			activeHostsCount++
		}

		// Map existing services by port/proto for diffing
		prevSvcMap := make(map[string]domain.Service)
		if prevHost != nil {
			for _, ps := range prevHost.Services {
				prevSvcMap[svcKey(ps.Port, ps.Protocol)] = ps
			}
		}

		seenSvcKeys := make(map[string]bool)
		var hostServices []domain.Service

		for i := range obs.Services {
			osvc := &obs.Services[i]
			proto := strings.ToLower(strings.TrimSpace(osvc.Protocol))
			if proto == "" {
				proto = "tcp"
			}
			state := strings.ToLower(strings.TrimSpace(osvc.State))
			if state == "" {
				state = "open"
			}
			k := svcKey(osvc.Port, proto)
			seenSvcKeys[k] = true

			analysis := p.analyzer.AnalyzeService(osvc, customSigs)
			prevSvc, existed := prevSvcMap[k]

			svcModel := &domain.Service{
				HostID:             savedHost.ID,
				HostIP:             ip,
				Port:               osvc.Port,
				Protocol:           proto,
				State:              state,
				ServiceName:        nonEmpty(osvc.ServiceName, inferServiceName(osvc.Port)),
				Product:            osvc.Product,
				Version:            osvc.Version,
				CPE:                osvc.CPE,
				Banner:             osvc.Banner,
				HTTP:               osvc.HTTP,
				Technologies:       analysis.Technologies,
				MatchedSignatures:  analysis.MatchedSignatures,
				IsAdminPanel:       analysis.IsAdminPanel,
				IsStagingEnv:       analysis.IsStagingEnv,
				IsIoT:              analysis.IsIoT,
				ClusterKey:         analysis.ClusterKey,
				Interestingness:    analysis.Interestingness,
				InterestingFactors: analysis.InterestingFactors,
				TriageStatus:       "new",
				Notes:              osvc.Notes,
				Tags:               analysis.Tags,
				FirstSeen:          obsAt,
				LastSeen:           obsAt,
			}
			if existed {
				svcModel.ID = prevSvc.ID
				svcModel.FirstSeen = prevSvc.FirstSeen
				svcModel.TriageStatus = observedTriageStatus(&prevSvc)
			}

			savedSvc, err := p.store.UpsertObservedService(ctx, svcModel)
			if err != nil {
				return nil, fmt.Errorf("upsert service %s:%d: %w", ip, osvc.Port, err)
			}
			servicesUpserted++
			hostServices = append(hostServices, *savedSvc)

			// Persist immutable raw Evidence Receipt
			_ = p.store.AddObservation(ctx, &db.ServiceObservation{
				ScanRunID:   run.ID,
				HostID:      savedHost.ID,
				ServiceID:   savedSvc.ID,
				Port:        osvc.Port,
				Protocol:    proto,
				State:       state,
				ServiceName: svcModel.ServiceName,
				Product:     osvc.Product,
				Version:     osvc.Version,
				Banner:      osvc.Banner,
				HTTP:        osvc.HTTP,
				ObservedAt:  obsAt,
			})

			// Emit service-level diff events
			if !existed {
				sev := "low"
				evType := "NEW_SERVICE"
				summary := fmt.Sprintf("New service %d/%s (%s) on %s", osvc.Port, proto, svcModel.ServiceName, ip)
				if analysis.IsAdminPanel {
					sev = "high"
					evType = "ADMIN_PANEL_EXPOSED"
				} else if label, risky := RiskyExposure(osvc.Port, svcModel.ServiceName); risky && state == "open" {
					// Remote-access / file-sharing / database ports newly reachable are the
					// exposures a SOC wants paged about (they go out via the alert webhook).
					sev = "high"
					summary = fmt.Sprintf("New %s exposure %d/%s (%s) on %s", label, osvc.Port, proto, svcModel.ServiceName, ip)
				} else if analysis.IsStagingEnv {
					sev = "medium"
				}
				recordChange(domain.ChangeEvent{
					HostID:    savedHost.ID,
					HostIP:    ip,
					ServiceID: savedSvc.ID,
					Port:      osvc.Port,
					EventType: evType,
					Severity:  sev,
					Summary:   summary,
					TimeSlot:  domain.TimeSlotFor(obsAt),
					After: map[string]any{
						"port":    osvc.Port,
						"service": svcModel.ServiceName,
						"product": osvc.Product,
						"version": osvc.Version,
						"title":   httpTitle(osvc.HTTP),
					},
				})
			} else {
				diffBefore, diffAfter, diffSummary, sev := diffService(&prevSvc, svcModel)
				if len(diffAfter) > 0 {
					recordChange(domain.ChangeEvent{
						HostID:    savedHost.ID,
						HostIP:    ip,
						ServiceID: savedSvc.ID,
						Port:      osvc.Port,
						EventType: "SERVICE_CHANGED",
						Severity:  sev,
						Summary:   fmt.Sprintf("Service %s:%d changed: %s", ip, osvc.Port, diffSummary),
						TimeSlot:  domain.TimeSlotFor(obsAt),
						Before:    diffBefore,
						After:     diffAfter,
					})
				}
			}
		}

		// Detect closed services on an alive host when full service list was observed
		if isAlive && prevHost != nil && len(obs.Services) > 0 {
			for k, ps := range prevSvcMap {
				if !seenSvcKeys[k] && ps.State == "open" {
					ps.State = "closed"
					_, _ = p.store.UpsertObservedService(ctx, &ps)
					recordChange(domain.ChangeEvent{
						HostID:    savedHost.ID,
						HostIP:    ip,
						ServiceID: ps.ID,
						Port:      ps.Port,
						EventType: "SERVICE_CLOSED",
						Severity:  "low",
						Summary:   fmt.Sprintf("Service %d/%s (%s) no longer open on %s", ps.Port, ps.Protocol, ps.ServiceName, ip),
						TimeSlot:  domain.TimeSlotFor(obsAt),
						Before:    map[string]any{"state": "open", "service": ps.ServiceName},
						After:     map[string]any{"state": "closed"},
					})
				}
			}
		}

		// Recompute host interestingness & infer environment from staging services
		hostScore, hostFactors := p.analyzer.ScoreHost(host, hostServices)
		host.Interestingness = hostScore
		host.InterestingFactors = hostFactors
		if host.Environment == "unknown" {
			for _, hs := range hostServices {
				if hs.IsStagingEnv {
					host.Environment = "staging"
					break
				}
			}
		}
		_, _ = p.store.UpsertObservedHost(ctx, host)
	}

	// Mark missing hosts in scope if requested (e.g., completed active scan)
	if req.MarkMissingHosts {
		scopeSet := make(map[string]bool, len(req.ScopeIPs))
		for _, ip := range req.ScopeIPs {
			scopeSet[strings.TrimSpace(ip)] = true
		}
		allHosts, _, _ := p.store.ListHosts(ctx, db.HostFilter{})
		for i := range allHosts {
			h := &allHosts[i]
			if seenIPs[h.IP] {
				continue
			}
			if len(scopeSet) > 0 && !scopeSet[h.IP] {
				continue
			}
			trans := p.analyzer.EvaluateLifecycle(h, false, now, missingThresh, graceHours)
			h.LifecycleState = trans.NewState
			h.TotalScansChecked = trans.TotalScansChecked
			h.ConsecutiveMisses = trans.ConsecutiveMisses
			h.StateTransitions = trans.StateTransitions
			h.StabilityScore = trans.StabilityScore
			h.TimeOfDayStats = trans.TimeOfDayStats
			_, _ = p.store.UpsertObservedHost(ctx, h)

			if trans.Changed || trans.IsTimeAnomaly {
				evType := "HOST_MISSING"
				sev := "low"
				if trans.NewState == domain.HostStateInactive {
					evType = "HOST_INACTIVE"
					sev = "medium"
				} else if trans.IsExpectedSchedule {
					evType = "EXPECTED_OFF_HOURS"
					sev = "info"
				} else if trans.IsTimeAnomaly {
					evType = "TIME_ANOMALY"
					sev = "medium"
				}
				recordChange(domain.ChangeEvent{
					HostID:             h.ID,
					HostIP:             h.IP,
					EventType:          evType,
					Severity:           sev,
					Summary:            nonEmpty(trans.Summary, fmt.Sprintf("Host %s not responding (%s)", h.IP, trans.NewState)),
					TimeSlot:           domain.TimeSlotFor(now),
					IsExpectedSchedule: trans.IsExpectedSchedule,
					IsTimeAnomaly:      trans.IsTimeAnomaly,
					After:              map[string]any{"lifecycle_state": trans.NewState, "consecutive_misses": trans.ConsecutiveMisses},
				})
			}
		}
	}

	// Save encrypted snapshot of current inventory for scan-to-scan diffing
	allHostsNow, _, _ := p.store.ListHosts(ctx, db.HostFilter{})
	_ = p.store.SaveScanSnapshot(ctx, run.ID, allHostsNow)

	// Finalize ScanRun metrics (only auto-complete if we created it for ingest; active runner controls its own status if still running)
	finished := time.Now().UTC()
	if req.ScanRunID == "" {
		run.Status = domain.ScanStatusCompleted
		run.ScannedIPs = len(seenIPs)
		run.CompletedChunks = run.TotalChunks
		run.FinishedAt = &finished
		run.DurationMs = finished.Sub(run.StartedAt).Milliseconds()
	}
	// Host/service counters belong to whoever owns the run: for imports the pipeline created
	// the run and sets them; for live scans the engine already accumulates them per chunk, and
	// adding servicesUpserted here double-counted every service.
	if req.ScanRunID == "" {
		run.ActiveHosts = activeHostsCount
		run.ServicesFound = servicesUpserted
	}
	run.ChangesDetected += len(changes)
	if req.RawNmapXML != "" {
		run.RawNmapXML = req.RawNmapXML
		run.HasRawNmapXML = true
	}
	_ = p.store.UpdateScanRun(ctx, run)

	if p.emit != nil && req.ScanRunID == "" {
		p.emit(domain.LiveEvent{
			Type:      "scan.completed",
			ScanRunID: run.ID,
			Timestamp: finished,
			Payload: map[string]any{
				"run_type":         run.RunType,
				"active_hosts":     run.ActiveHosts,
				"services_found":   run.ServicesFound,
				"changes_detected": run.ChangesDetected,
			},
		})
	}

	if box, ok := p.notifier.Load().(notifierBox); ok && box.n != nil && len(changes) > 0 {
		box.n.NotifyChanges(ctx, run, changes)
	}

	return &IngestResult{
		ScanRun:          run,
		HostsProcessed:   len(seenIPs),
		ServicesUpserted: servicesUpserted,
		ChangesDetected:  len(changes),
		Changes:          changes,
	}, nil
}

// observedTriageStatus returns the scanner-side triage status of a (merged) service, so an
// analyst override (triage / triage_status) is never copied into the observed record and
// cannot outlive its own unlock or expiry.
func observedTriageStatus(s *domain.Service) string {
	locked := false
	for _, f := range s.LockedFields {
		if f == "triage" || f == "triage_status" {
			locked = true
			break
		}
	}
	if !locked {
		if s.TriageStatus == domain.TriageAcceptedRisk || s.TriageStatus == domain.TriageFalsePositive {
			return domain.TriageNew
		}
		return nonEmpty(s.TriageStatus, domain.TriageNew)
	}
	if v, ok := s.ScannerObserved["triage_status"].(string); ok && v != "" {
		return v
	}
	return domain.TriageNew
}

// riskyPorts are exposures that warrant an immediate alert when they newly appear.
var riskyPorts = map[int]string{
	21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "SMB", 445: "SMB", 1433: "MSSQL",
	1521: "Oracle DB", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
	27017: "MongoDB",
}

// RiskyExposure reports whether a port/service is a high-risk exposure (remote access,
// file sharing, database, unauthenticated-by-default APIs) and returns a short label.
func RiskyExposure(port int, serviceName string) (string, bool) {
	if l, ok := riskyPorts[port]; ok {
		return l, true
	}
	switch strings.ToLower(serviceName) {
	case "ms-wbt-server", "rdp":
		return "RDP", true
	case "microsoft-ds", "netbios-ssn", "smb":
		return "SMB", true
	case "vnc", "telnet":
		return strings.ToUpper(serviceName), true
	}
	return "", false
}

func svcKey(port int, proto string) string {
	return fmt.Sprintf("%d/%s", port, strings.ToLower(proto))
}

func httpTitle(fp *domain.HTTPFingerprint) string {
	if fp == nil {
		return ""
	}
	return fp.Title
}

func diffService(prev, curr *domain.Service) (map[string]any, map[string]any, string, string) {
	before := map[string]any{}
	after := map[string]any{}
	parts := []string{}
	sev := "low"

	if prev.Product != curr.Product && curr.Product != "" {
		before["product"] = prev.Product
		after["product"] = curr.Product
		parts = append(parts, fmt.Sprintf("product %q -> %q", prev.Product, curr.Product))
	}
	if prev.Version != curr.Version && curr.Version != "" {
		before["version"] = prev.Version
		after["version"] = curr.Version
		parts = append(parts, fmt.Sprintf("version %q -> %q", prev.Version, curr.Version))
	}
	if prev.Banner != curr.Banner && curr.Banner != "" {
		before["banner"] = prev.Banner
		after["banner"] = curr.Banner
		parts = append(parts, "banner updated")
	}
	if !prev.IsAdminPanel && curr.IsAdminPanel {
		before["is_admin_panel"] = false
		after["is_admin_panel"] = true
		parts = append(parts, "admin panel exposed")
		sev = "high"
	}
	if prev.HTTP != nil && curr.HTTP != nil {
		if prev.HTTP.Title != curr.HTTP.Title && curr.HTTP.Title != "" {
			before["http_title"] = prev.HTTP.Title
			after["http_title"] = curr.HTTP.Title
			parts = append(parts, fmt.Sprintf("title %q -> %q", prev.HTTP.Title, curr.HTTP.Title))
			if sev == "low" {
				sev = "medium"
			}
		}
		if prev.HTTP.StatusCode != curr.HTTP.StatusCode && curr.HTTP.StatusCode > 0 {
			before["status_code"] = prev.HTTP.StatusCode
			after["status_code"] = curr.HTTP.StatusCode
			parts = append(parts, fmt.Sprintf("HTTP %d -> %d", prev.HTTP.StatusCode, curr.HTTP.StatusCode))
		}
		if prev.HTTP.FaviconMMH3 != curr.HTTP.FaviconMMH3 && curr.HTTP.FaviconMMH3 != "" {
			before["favicon_mmh3"] = prev.HTTP.FaviconMMH3
			after["favicon_mmh3"] = curr.HTTP.FaviconMMH3
			parts = append(parts, "favicon changed")
		}
		if prev.HTTP.TLS != nil && curr.HTTP.TLS != nil && prev.HTTP.TLS.SHA256 != curr.HTTP.TLS.SHA256 {
			before["tls_sha256"] = prev.HTTP.TLS.SHA256
			after["tls_sha256"] = curr.HTTP.TLS.SHA256
			parts = append(parts, "TLS certificate changed")
			if sev == "low" {
				sev = "medium"
			}
		}
	}
	return before, after, strings.Join(parts, ", "), sev
}

func inferServiceName(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 80, 8080, 8000:
		return "http"
	case 443, 8443:
		return "https"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	default:
		return "tcp"
	}
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
