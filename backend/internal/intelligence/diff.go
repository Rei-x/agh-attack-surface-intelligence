package intelligence

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ScanDiffSummary holds aggregate counts for a scan-to-scan diff report.
type ScanDiffSummary struct {
	NewHosts        int `json:"new_hosts"`
	MissingHosts    int `json:"missing_hosts"`
	NewServices     int `json:"new_services"`
	ClosedServices  int `json:"closed_services"`
	ChangedServices int `json:"changed_services"`
	TimeAnomalies   int `json:"time_anomalies"`
	TotalChanges    int `json:"total_changes"`
}

// ScanDiffReport mirrors GET /api/v1/scans/diff?from=<scanA>&to=<scanB>.
type ScanDiffReport struct {
	NewHosts        []domain.ChangeEvent `json:"new_hosts"`
	MissingHosts    []domain.ChangeEvent `json:"missing_hosts"`
	NewServices     []domain.ChangeEvent `json:"new_services"`
	ClosedServices  []domain.ChangeEvent `json:"closed_services"`
	ChangedServices []domain.ChangeEvent `json:"changed_services"`
	TimeAnomalies   []domain.ChangeEvent `json:"time_anomalies"`
	Summary         ScanDiffSummary      `json:"summary"`
}

// ComputeDiff compares two host snapshots (previous vs current) and produces
// structured ChangeEvents plus a categorized ScanDiffReport.
func ComputeDiff(scanRunID, prevScanRunID string, prevHosts, currHosts []domain.Host, observedAt time.Time) ([]domain.ChangeEvent, ScanDiffReport) {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	slot := domain.TimeSlotFor(observedAt)

	prevByIP := make(map[string]domain.Host, len(prevHosts))
	for _, h := range prevHosts {
		prevByIP[h.IP] = h
	}
	currByIP := make(map[string]domain.Host, len(currHosts))
	for _, h := range currHosts {
		currByIP[h.IP] = h
	}

	var events []domain.ChangeEvent
	report := ScanDiffReport{
		NewHosts:        []domain.ChangeEvent{},
		MissingHosts:    []domain.ChangeEvent{},
		NewServices:     []domain.ChangeEvent{},
		ClosedServices:  []domain.ChangeEvent{},
		ChangedServices: []domain.ChangeEvent{},
		TimeAnomalies:   []domain.ChangeEvent{},
	}

	eventSeq := 0
	makeEvent := func(host domain.Host, svcID string, port int, evType, severity, summary string, expected, anomaly bool, before, after map[string]any) domain.ChangeEvent {
		eventSeq++
		return domain.ChangeEvent{
			ID:                 fmt.Sprintf("chg-%s-%04d", scanRunID, eventSeq),
			ScanRunID:          scanRunID,
			PrevScanRunID:      prevScanRunID,
			HostID:             host.ID,
			HostIP:             host.IP,
			ServiceID:          svcID,
			Port:               port,
			EventType:          evType,
			Severity:           severity,
			Summary:            summary,
			TimeSlot:           slot,
			IsExpectedSchedule: expected,
			IsTimeAnomaly:      anomaly,
			Before:             before,
			After:              after,
			CreatedAt:          observedAt,
		}
	}

	// Deterministic IP order across union of prev & curr.
	ipSet := make(map[string]struct{}, len(prevByIP)+len(currByIP))
	for ip := range prevByIP {
		ipSet[ip] = struct{}{}
	}
	for ip := range currByIP {
		ipSet[ip] = struct{}{}
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	for _, ip := range ips {
		prev, hadPrev := prevByIP[ip]
		curr, hasCurr := currByIP[ip]

		if !hadPrev && hasCurr {
			ev := makeEvent(curr, "", 0, "host_new", "medium",
				fmt.Sprintf("New host discovered: %s (%d services)", curr.IP, len(curr.Services)),
				false, false, nil, map[string]any{"ip": curr.IP, "state": curr.LifecycleState, "services": len(curr.Services)})
			events = append(events, ev)
			report.NewHosts = append(report.NewHosts, ev)

			for _, s := range curr.Services {
				sev := serviceEventSeverity(s)
				sEv := makeEvent(curr, s.ID, s.Port, "service_new", sev,
					fmt.Sprintf("New service %s/%d (%s) on %s", s.Protocol, s.Port, s.ServiceName, curr.IP),
					false, false, nil, serviceSnapshot(s))
				events = append(events, sEv)
				report.NewServices = append(report.NewServices, sEv)
			}
			continue
		}

		if hadPrev && !hasCurr {
			expected, anomaly := ClassifyTimeAvailability(prev.TimeOfDayStats, slot, false)
			sev := "low"
			if anomaly {
				sev = "medium"
			} else if expected {
				sev = "info"
			}
			ev := makeEvent(prev, "", 0, "host_missing", sev,
				fmt.Sprintf("Host %s not observed in current scan", prev.IP),
				expected, anomaly, map[string]any{"state": prev.LifecycleState}, map[string]any{"state": domain.HostStateMissing})
			events = append(events, ev)
			report.MissingHosts = append(report.MissingHosts, ev)
			if anomaly {
				report.TimeAnomalies = append(report.TimeAnomalies, ev)
			}
			continue
		}

		if prev.LifecycleState != curr.LifecycleState {
			switch curr.LifecycleState {
			case domain.HostStateReactivated:
				expected, anomaly := ClassifyTimeAvailability(prev.TimeOfDayStats, slot, true)
				sev := "medium"
				if anomaly {
					sev = "high"
				}
				ev := makeEvent(curr, "", 0, "host_reactivated", sev,
					fmt.Sprintf("Host %s reactivated from %s", curr.IP, prev.LifecycleState),
					expected, anomaly, map[string]any{"state": prev.LifecycleState}, map[string]any{"state": curr.LifecycleState})
				events = append(events, ev)
				report.NewHosts = append(report.NewHosts, ev)
				if anomaly {
					report.TimeAnomalies = append(report.TimeAnomalies, ev)
				}
			case domain.HostStateMissing, domain.HostStateInactive:
				expected, anomaly := ClassifyTimeAvailability(prev.TimeOfDayStats, slot, false)
				sev := "low"
				if anomaly {
					sev = "medium"
				} else if expected {
					sev = "info"
				}
				evType := "host_missing"
				if curr.LifecycleState == domain.HostStateInactive {
					evType = "host_inactive"
				}
				ev := makeEvent(curr, "", 0, evType, sev,
					fmt.Sprintf("Host %s transitioned %s -> %s", curr.IP, prev.LifecycleState, curr.LifecycleState),
					expected, anomaly, map[string]any{"state": prev.LifecycleState}, map[string]any{"state": curr.LifecycleState})
				events = append(events, ev)
				report.MissingHosts = append(report.MissingHosts, ev)
				if anomaly {
					report.TimeAnomalies = append(report.TimeAnomalies, ev)
				}
			}
		}

		// Compare services by (protocol, port).
		prevSvcs := indexServices(prev.Services)
		currSvcs := indexServices(curr.Services)
		svcKeys := unionKeys(prevSvcs, currSvcs)

		for _, k := range svcKeys {
			ps, hadS := prevSvcs[k]
			cs, hasS := currSvcs[k]

			if !hadS && hasS {
				ev := makeEvent(curr, cs.ID, cs.Port, "service_new", serviceEventSeverity(cs),
					fmt.Sprintf("New service %s/%d (%s) discovered on %s", cs.Protocol, cs.Port, cs.ServiceName, curr.IP),
					false, false, nil, serviceSnapshot(cs))
				events = append(events, ev)
				report.NewServices = append(report.NewServices, ev)
				continue
			}
			if hadS && !hasS {
				ev := makeEvent(curr, ps.ID, ps.Port, "service_closed", "low",
					fmt.Sprintf("Service %s/%d (%s) no longer open on %s", ps.Protocol, ps.Port, ps.ServiceName, curr.IP),
					false, false, serviceSnapshot(ps), nil)
				events = append(events, ev)
				report.ClosedServices = append(report.ClosedServices, ev)
				continue
			}

			// An empty new product/version means "not observed this time", not a change.
			if (ps.Product != cs.Product && cs.Product != "") || (ps.Version != cs.Version && cs.Version != "") {
				ev := makeEvent(curr, cs.ID, cs.Port, "service_version_changed", "medium",
					fmt.Sprintf("Service %s:%d version changed (%s %s -> %s %s)", curr.IP, cs.Port, ps.Product, ps.Version, cs.Product, cs.Version),
					false, false,
					map[string]any{"product": ps.Product, "version": ps.Version},
					map[string]any{"product": cs.Product, "version": cs.Version})
				events = append(events, ev)
				report.ChangedServices = append(report.ChangedServices, ev)
			}

			if ps.HTTP != nil && cs.HTTP != nil {
				if ps.HTTP.Title != cs.HTTP.Title && cs.HTTP.Title != "" {
					ev := makeEvent(curr, cs.ID, cs.Port, "http_title_changed", "low",
						fmt.Sprintf("HTTP title changed on %s:%d (%q -> %q)", curr.IP, cs.Port, ps.HTTP.Title, cs.HTTP.Title),
						false, false,
						map[string]any{"title": ps.HTTP.Title},
						map[string]any{"title": cs.HTTP.Title})
					events = append(events, ev)
					report.ChangedServices = append(report.ChangedServices, ev)
				}
				if ps.HTTP.StatusCode != cs.HTTP.StatusCode {
					ev := makeEvent(curr, cs.ID, cs.Port, "http_status_changed", "low",
						fmt.Sprintf("HTTP status changed on %s:%d (%d -> %d)", curr.IP, cs.Port, ps.HTTP.StatusCode, cs.HTTP.StatusCode),
						false, false,
						map[string]any{"status_code": ps.HTTP.StatusCode},
						map[string]any{"status_code": cs.HTTP.StatusCode})
					events = append(events, ev)
					report.ChangedServices = append(report.ChangedServices, ev)
				}
				if ps.HTTP.TLS != nil && cs.HTTP.TLS != nil && ps.HTTP.TLS.SHA256 != cs.HTTP.TLS.SHA256 {
					ev := makeEvent(curr, cs.ID, cs.Port, "tls_cert_changed", "medium",
						fmt.Sprintf("TLS certificate changed on %s:%d (CN=%s)", curr.IP, cs.Port, cs.HTTP.TLS.SubjectCN),
						false, false,
						map[string]any{"sha256": ps.HTTP.TLS.SHA256, "subject_cn": ps.HTTP.TLS.SubjectCN, "issuer": ps.HTTP.TLS.Issuer},
						map[string]any{"sha256": cs.HTTP.TLS.SHA256, "subject_cn": cs.HTTP.TLS.SubjectCN, "issuer": cs.HTTP.TLS.Issuer})
					events = append(events, ev)
					report.ChangedServices = append(report.ChangedServices, ev)
				}
			}

			prevTech := techSignature(ps.Technologies)
			currTech := techSignature(cs.Technologies)
			if prevTech != currTech && (prevTech != "" || currTech != "") {
				ev := makeEvent(curr, cs.ID, cs.Port, "tech_changed", "medium",
					fmt.Sprintf("Detected technology stack changed on %s:%d (%s -> %s)", curr.IP, cs.Port, prevTech, currTech),
					false, false,
					map[string]any{"technologies": prevTech},
					map[string]any{"technologies": currTech})
				events = append(events, ev)
				report.ChangedServices = append(report.ChangedServices, ev)
			}
		}
	}

	report.Summary = ScanDiffSummary{
		NewHosts:        len(report.NewHosts),
		MissingHosts:    len(report.MissingHosts),
		NewServices:     len(report.NewServices),
		ClosedServices:  len(report.ClosedServices),
		ChangedServices: len(report.ChangedServices),
		TimeAnomalies:   len(report.TimeAnomalies),
		TotalChanges:    len(events),
	}

	return events, report
}

// ComputeServiceClusterKey returns a primary deterministic grouping key for a service.
func ComputeServiceClusterKey(svc domain.Service) string {
	if svc.HTTP != nil && svc.HTTP.FaviconMMH3 != "" {
		return "favicon:" + svc.HTTP.FaviconMMH3
	}
	if ts := techSignature(svc.Technologies); ts != "" {
		return "tech:" + strings.ToLower(ts)
	}
	if svc.HTTP != nil && strings.TrimSpace(svc.HTTP.Title) != "" {
		return "title:" + strings.ToLower(strings.TrimSpace(svc.HTTP.Title))
	}
	if svc.HTTP != nil && svc.HTTP.TLS != nil && strings.TrimSpace(svc.HTTP.TLS.Issuer) != "" {
		return "tls:" + strings.ToLower(strings.TrimSpace(svc.HTTP.TLS.Issuer))
	}
	if svc.Product != "" {
		return "product:" + strings.ToLower(strings.TrimSpace(svc.Product))
	}
	return fmt.Sprintf("svc:%s:%d", strings.ToLower(svc.ServiceName), svc.Port)
}

func isMeaningfulJARM(h string) bool {
	return len(h) == 62 && strings.Trim(h, "0") != ""
}

// ComputeClusters groups similar services by favicon MMH3, HTTP title, TLS issuer, JARM
// and tech stack (or product when no technology is known), keeping clusters of at least 2.
func ComputeClusters(services []domain.Service) []domain.ServiceCluster {
	return ComputeClustersWithMinSize(services, 2)
}

// ComputeClustersWithMinSize groups similar services with configurable minimum cluster membership.
func ComputeClustersWithMinSize(services []domain.Service, minSize int) []domain.ServiceCluster {
	if minSize < 1 {
		minSize = 1
	}

	type accum struct {
		key      string
		groupBy  string
		label    string
		hosts    map[string]struct{}
		svcIDs   []string
		maxScore int
		techs    map[string]struct{}
	}

	groups := make(map[string]*accum)
	add := func(groupBy, rawKey, label string, svc domain.Service) {
		rawKey = strings.TrimSpace(rawKey)
		if rawKey == "" {
			return
		}
		fullKey := groupBy + ":" + strings.ToLower(rawKey)
		a, ok := groups[fullKey]
		if !ok {
			a = &accum{
				key:     fullKey,
				groupBy: groupBy,
				label:   label,
				hosts:   make(map[string]struct{}),
				techs:   make(map[string]struct{}),
			}
			groups[fullKey] = a
		}
		a.svcIDs = append(a.svcIDs, svc.ID)
		if svc.HostIP != "" {
			a.hosts[svc.HostIP] = struct{}{}
		}
		if svc.Interestingness > a.maxScore {
			a.maxScore = svc.Interestingness
		}
		for _, t := range svc.Technologies {
			a.techs[t.Name] = struct{}{}
		}
	}

	for _, svc := range services {
		if svc.HTTP != nil {
			if svc.HTTP.FaviconMMH3 != "" {
				add("favicon", svc.HTTP.FaviconMMH3, "Favicon MMH3 "+svc.HTTP.FaviconMMH3, svc)
			}
			if title := strings.TrimSpace(svc.HTTP.Title); title != "" {
				add("http_title", title, title, svc)
			}
			if svc.HTTP.TLS != nil && strings.TrimSpace(svc.HTTP.TLS.Issuer) != "" {
				add("tls_issuer", svc.HTTP.TLS.Issuer, "TLS Issuer: "+svc.HTTP.TLS.Issuer, svc)
			}
			// Same JARM = same TLS stack + configuration (library, version, cipher order).
			if svc.HTTP.TLS != nil && isMeaningfulJARM(svc.HTTP.TLS.JARM) {
				add("tls_jarm", svc.HTTP.TLS.JARM, "JARM "+svc.HTTP.TLS.JARM, svc)
			}
		}
		if ts := techSignature(svc.Technologies); ts != "" {
			add("tech_stack", ts, ts, svc)
		} else if svc.Product != "" {
			add("service_product", svc.Product, svc.Product, svc)
		}
	}

	out := make([]domain.ServiceCluster, 0, len(groups))
	for _, a := range groups {
		if len(a.svcIDs) < minSize {
			continue
		}
		hostIPs := make([]string, 0, len(a.hosts))
		for ip := range a.hosts {
			hostIPs = append(hostIPs, ip)
		}
		sort.Strings(hostIPs)

		sampleTechs := make([]string, 0, len(a.techs))
		for t := range a.techs {
			sampleTechs = append(sampleTechs, t)
		}
		sort.Strings(sampleTechs)
		if len(sampleTechs) > 6 {
			sampleTechs = sampleTechs[:6]
		}

		out = append(out, domain.ServiceCluster{
			ClusterKey:  a.key,
			GroupBy:     a.groupBy,
			Label:       a.label,
			Count:       len(a.svcIDs),
			HostIPs:     hostIPs,
			ServiceIDs:  a.svcIDs,
			MaxScore:    a.maxScore,
			SampleTechs: sampleTechs,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].MaxScore != out[j].MaxScore {
			return out[i].MaxScore > out[j].MaxScore
		}
		return out[i].ClusterKey < out[j].ClusterKey
	})

	return out
}

func serviceEventSeverity(s domain.Service) string {
	if s.IsAdminPanel || s.Interestingness >= 60 {
		return "high"
	}
	if s.IsStagingEnv || s.IsIoT || s.Interestingness >= 30 {
		return "medium"
	}
	return "low"
}

func serviceSnapshot(s domain.Service) map[string]any {
	snap := map[string]any{
		"port":         s.Port,
		"protocol":     s.Protocol,
		"service_name": s.ServiceName,
		"product":      s.Product,
		"version":      s.Version,
	}
	if s.HTTP != nil {
		snap["title"] = s.HTTP.Title
		snap["status_code"] = s.HTTP.StatusCode
	}
	return snap
}

func indexServices(svcs []domain.Service) map[string]domain.Service {
	m := make(map[string]domain.Service, len(svcs))
	for _, s := range svcs {
		proto := s.Protocol
		if proto == "" {
			proto = "tcp"
		}
		key := fmt.Sprintf("%s/%d", proto, s.Port)
		m[key] = s
	}
	return m
}

func unionKeys(a, b map[string]domain.Service) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		set[k] = struct{}{}
	}
	for k := range b {
		set[k] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func techSignature(techs []domain.DetectedTechnology) string {
	if len(techs) == 0 {
		return ""
	}
	names := make([]string, 0, len(techs))
	seen := make(map[string]struct{}, len(techs))
	for _, t := range techs {
		if _, ok := seen[t.Name]; !ok {
			seen[t.Name] = struct{}{}
			names = append(names, t.Name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, " + ")
}
