package ingest

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ServiceAnalysis holds the intelligence output for a single observed service.
type ServiceAnalysis struct {
	// Best evidence-backed product / version (empty = keep the scanner's raw values) and
	// where each came from (nmap, cpe, banner, http-server-header, http-page).
	Product            string
	Version            string
	ProductSource      string
	VersionSource      string
	Technologies       []domain.DetectedTechnology
	MatchedSignatures  []string
	IsAdminPanel       bool
	IsStagingEnv       bool
	IsIoT              bool
	ClusterKey         string
	Interestingness    int
	InterestingFactors []domain.InterestingnessFactor
	Tags               []string
}

// LifecycleTransition captures a host state machine step and time-of-day anomaly classification.
type LifecycleTransition struct {
	NewState           string
	Changed            bool
	TotalScansSeen     int
	TotalScansChecked  int
	ConsecutiveMisses  int
	StateTransitions   int
	StabilityScore     int
	TimeOfDayStats     []domain.TimeSlotStat
	IsExpectedSchedule bool
	IsTimeAnomaly      bool
	Summary            string
	Liveness           *domain.LivenessEstimate // Bayesian P(host still exists) + reason (nil if analyzer has none)
}

// SignatureTestHit describes a service matched in the retroactive Signature Playground.
type SignatureTestHit struct {
	ServiceID   string   `json:"service_id"`
	HostID      string   `json:"host_id"`
	HostIP      string   `json:"host_ip"`
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	Title       string   `json:"title,omitempty"`
	Version     string   `json:"version,omitempty"`
	Confidence  int      `json:"confidence"`
	MatchedText []string `json:"matched_text"`
}

// Analyzer plugs signature matching, Noisy-OR confidence, interestingness scoring,
// host lifecycle FSM, clustering, and signature validation into the unified pipeline and API.
type Analyzer interface {
	AnalyzeService(svc *domain.ObservedService, customSigs []domain.Signature) ServiceAnalysis
	EvaluateLifecycle(prev *domain.Host, seen bool, now time.Time, missingThreshold int, graceHours int) LifecycleTransition
	ScoreHost(host *domain.Host, services []domain.Service) (int, []domain.InterestingnessFactor)
	ComputeClusters(hosts []domain.Host) []domain.ServiceCluster
	ValidateSignature(sig domain.Signature) error
	RetroactiveTest(sig domain.Signature, services []domain.Service) []SignatureTestHit
	BuiltinSignatures() []domain.Signature
}

// DefaultAnalyzer provides a clean, working stdlib implementation of Analyzer so
// backend-core compiles, runs, and passes tests independently before scanner-engine wiring.
type DefaultAnalyzer struct{}

func NewDefaultAnalyzer() *DefaultAnalyzer {
	return &DefaultAnalyzer{}
}

func (a *DefaultAnalyzer) BuiltinSignatures() []domain.Signature {
	return []domain.Signature{
		{
			ID: "builtin-wordpress", Name: "WordPress", Category: "cms", MatchMode: "any",
			ConfidenceWeight: 0.9, InterestingPts: 15, IsBuiltin: true, Enabled: true,
			Description: "WordPress CMS detection via meta generator, wp-login, or cookies",
			Tags:        []string{"cms", "wordpress"},
			Matchers: []domain.SignatureMatcher{
				{Type: "html_body", Pattern: "WordPress", Regex: false},
				{Type: "cookie", Pattern: "wp-settings", Regex: false},
				{Type: "safe_path", Pattern: "/wp-login.php", StatusCodes: []int{200, 302}},
			},
		},
		{
			ID: "builtin-admin-panel", Name: "Admin Console", Category: "admin_panel", MatchMode: "any",
			ConfidenceWeight: 0.85, InterestingPts: 35, IsBuiltin: true, Enabled: true,
			Description: "Exposed administrative interface or console",
			Tags:        []string{"admin_panel"},
			Matchers: []domain.SignatureMatcher{
				{Type: "html_body", Pattern: "Admin Console", Regex: false},
				{Type: "safe_path", Pattern: "/admin", StatusCodes: []int{200, 401, 403}},
			},
		},
		{
			ID: "builtin-staging-env", Name: "Staging / Debug Environment", Category: "staging", MatchMode: "any",
			ConfidenceWeight: 0.88, InterestingPts: 30, IsBuiltin: true, Enabled: true,
			Description: "Non-production staging/dev/debug environment exposed on network",
			Tags:        []string{"staging", "debug"},
			Matchers: []domain.SignatureMatcher{
				{Type: "header", Key: "X-Debug-Token", Pattern: ".+", Regex: true},
				{Type: "header", Key: "X-Staging-Debug", Pattern: ".+", Regex: true},
				{Type: "html_body", Pattern: "Staging", Regex: false},
			},
		},
	}
}

func (a *DefaultAnalyzer) ValidateSignature(sig domain.Signature) error {
	if strings.TrimSpace(sig.Name) == "" {
		return errors.New("signature name is required")
	}
	if len(sig.Matchers) == 0 {
		return errors.New("signature must define at least one matcher")
	}
	forbidden := []string{"POST ", "PUT ", "DELETE ", "PATCH ", "password=", "passwd=", "login_user=", "../", "..\\"}
	for i, m := range sig.Matchers {
		if strings.TrimSpace(m.Pattern) == "" {
			return fmt.Errorf("matcher[%d]: empty pattern", i)
		}
		combined := strings.ToUpper(m.Key + " " + m.Pattern)
		for _, bad := range forbidden {
			if strings.Contains(combined, strings.ToUpper(bad)) {
				return fmt.Errorf("matcher[%d]: forbidden unsafe pattern %q (GET/HEAD passive inspection only)", i, bad)
			}
		}
		if m.Regex {
			if len(m.Pattern) > 512 {
				return fmt.Errorf("matcher[%d]: regex pattern too long", i)
			}
			if _, err := regexp.Compile(m.Pattern); err != nil {
				return fmt.Errorf("matcher[%d]: invalid regex: %w", i, err)
			}
		}
	}
	return nil
}

func (a *DefaultAnalyzer) AnalyzeService(svc *domain.ObservedService, customSigs []domain.Signature) ServiceAnalysis {
	res := ServiceAnalysis{
		Technologies:      []domain.DetectedTechnology{},
		MatchedSignatures: []string{},
		Tags:              append([]string(nil), svc.Tags...),
	}
	factors := []domain.InterestingnessFactor{}
	score := 0

	allSigs := append(a.BuiltinSignatures(), customSigs...)
	for _, sig := range allSigs {
		if !sig.Enabled {
			continue
		}
		matched, evidence, ver := evalSignature(sig, svc.Port, svc.ServiceName, svc.Product, svc.Banner, svc.HTTP)
		if !matched {
			continue
		}
		res.MatchedSignatures = append(res.MatchedSignatures, sig.Name)
		conf := fuseNoisyOR(evidence)
		res.Technologies = append(res.Technologies, domain.DetectedTechnology{
			Name:       sig.Name,
			Category:   sig.Category,
			Version:    ver,
			Confidence: conf,
			Evidence:   evidence,
		})
		if sig.Category == "admin_panel" {
			res.IsAdminPanel = true
		}
		if sig.Category == "staging" {
			res.IsStagingEnv = true
		}
		if sig.Category == "iot" {
			res.IsIoT = true
		}
		if sig.InterestingPts > 0 {
			score += sig.InterestingPts
			factors = append(factors, domain.InterestingnessFactor{Reason: "Signature: " + sig.Name, Points: sig.InterestingPts})
		}
		res.Tags = appendUnique(res.Tags, sig.Tags...)
	}

	if svc.HTTP != nil {
		titleLower := strings.ToLower(svc.HTTP.Title)
		if strings.Contains(titleLower, "admin") || strings.Contains(titleLower, "console") || strings.Contains(titleLower, "phpmyadmin") {
			if !res.IsAdminPanel {
				res.IsAdminPanel = true
				score += 30
				factors = append(factors, domain.InterestingnessFactor{Reason: "Admin portal title detected", Points: 30})
			}
		}
		if strings.Contains(titleLower, "staging") || strings.Contains(titleLower, "dev") || strings.Contains(titleLower, "test") {
			if !res.IsStagingEnv {
				res.IsStagingEnv = true
				score += 25
				factors = append(factors, domain.InterestingnessFactor{Reason: "Non-prod/staging title detected", Points: 25})
			}
		}
		if strings.Contains(titleLower, "laserjet") || strings.Contains(titleLower, "printer") || strings.Contains(titleLower, "hikvision") {
			res.IsIoT = true
			score += 15
			factors = append(factors, domain.InterestingnessFactor{Reason: "IoT device detected", Points: 15})
		}
		if svc.HTTP.TLS != nil && (svc.HTTP.TLS.IsSelfSigned || svc.HTTP.TLS.IsExpired || svc.HTTP.TLS.DaysToExpiry < 30) {
			score += 15
			factors = append(factors, domain.InterestingnessFactor{Reason: "TLS certificate issue (self-signed/expiring)", Points: 15})
		}
		if len(svc.HTTP.MissingSecHeaders) >= 3 {
			score += 10
			factors = append(factors, domain.InterestingnessFactor{Reason: "Multiple missing HTTP security headers", Points: 10})
		}
		for _, c := range svc.HTTP.Cookies {
			if !c.HttpOnly || !c.Secure {
				score += 10
				factors = append(factors, domain.InterestingnessFactor{Reason: "Insecure cookie flags on " + c.Name, Points: 10})
				break
			}
		}
	}

	if score > 100 {
		score = 100
	}
	res.Interestingness = score
	res.InterestingFactors = factors
	res.ClusterKey = computeClusterKey(svc, res.Technologies)
	return res
}

func (a *DefaultAnalyzer) EvaluateLifecycle(prev *domain.Host, seen bool, now time.Time, missingThreshold int, graceHours int) LifecycleTransition {
	if missingThreshold <= 0 {
		missingThreshold = 2
	}
	if graceHours <= 0 {
		graceHours = 24
	}
	slot := domain.TimeSlotFor(now)

	statsMap := map[string]domain.TimeSlotStat{
		domain.SlotNight:     {Slot: domain.SlotNight},
		domain.SlotMorning:   {Slot: domain.SlotMorning},
		domain.SlotAfternoon: {Slot: domain.SlotAfternoon},
		domain.SlotEvening:   {Slot: domain.SlotEvening},
	}
	if prev != nil {
		for _, st := range prev.TimeOfDayStats {
			statsMap[st.Slot] = st
		}
	}
	curSlot := statsMap[slot]
	prevRatio := curSlot.Ratio
	prevTotal := curSlot.Total
	curSlot.Total++
	if seen {
		curSlot.Seen++
	}
	curSlot.Ratio = float64(curSlot.Seen) / float64(curSlot.Total)
	statsMap[slot] = curSlot

	orderedSlots := []domain.TimeSlotStat{
		statsMap[domain.SlotNight],
		statsMap[domain.SlotMorning],
		statsMap[domain.SlotAfternoon],
		statsMap[domain.SlotEvening],
	}

	if prev == nil {
		return LifecycleTransition{
			NewState:          domain.HostStateNew,
			Changed:           true,
			TotalScansSeen:    1,
			TotalScansChecked: 1,
			StabilityScore:    100,
			TimeOfDayStats:    orderedSlots,
			Summary:           "New host discovered",
		}
	}

	totalChecked := prev.TotalScansChecked + 1
	totalSeen := prev.TotalScansSeen
	misses := prev.ConsecutiveMisses
	transitions := prev.StateTransitions
	newState := prev.LifecycleState
	isExpected := false
	isAnomaly := false
	summary := ""

	if seen {
		totalSeen++
		misses = 0
		switch prev.LifecycleState {
		case domain.HostStateInactive:
			newState = domain.HostStateReactivated
			summary = "Inactive host reactivated"
		case domain.HostStateMissing:
			newState = domain.HostStateIntermittent
			summary = "Missing host returned (intermittent)"
		case domain.HostStateNew, domain.HostStateReactivated:
			newState = domain.HostStateActive
		}
		if prevTotal >= 3 && prevRatio <= 0.2 {
			isAnomaly = true
			summary = fmt.Sprintf("Host unexpectedly active during %s slot", slot)
		}
	} else {
		misses++
		if prevTotal >= 3 && prevRatio <= 0.2 {
			isExpected = true
		} else if prevTotal >= 3 && prevRatio >= 0.8 {
			isAnomaly = true
		}
		hoursSinceSeen := now.Sub(prev.LastSeen).Hours()
		if misses >= missingThreshold && hoursSinceSeen >= float64(graceHours) {
			newState = domain.HostStateInactive
			summary = fmt.Sprintf("Host inactive after %d misses", misses)
		} else if prev.LifecycleState != domain.HostStateInactive {
			newState = domain.HostStateMissing
			summary = fmt.Sprintf("Host missing (%d consecutive misses)", misses)
		}
	}

	changed := newState != prev.LifecycleState
	if changed {
		transitions++
	}
	stability := int(math.Round((float64(totalSeen) / float64(totalChecked)) * 100))
	if transitions > 2 {
		stability -= (transitions - 2) * 5
		if stability < 0 {
			stability = 0
		}
	}

	return LifecycleTransition{
		NewState:           newState,
		Changed:            changed,
		TotalScansSeen:     totalSeen,
		TotalScansChecked:  totalChecked,
		ConsecutiveMisses:  misses,
		StateTransitions:   transitions,
		StabilityScore:     stability,
		TimeOfDayStats:     orderedSlots,
		IsExpectedSchedule: isExpected,
		IsTimeAnomaly:      isAnomaly,
		Summary:            summary,
	}
}

func (a *DefaultAnalyzer) ScoreHost(host *domain.Host, services []domain.Service) (int, []domain.InterestingnessFactor) {
	maxScore := 0
	var factors []domain.InterestingnessFactor
	for _, s := range services {
		if s.Interestingness > maxScore {
			maxScore = s.Interestingness
		}
		factors = append(factors, s.InterestingFactors...)
	}
	if host.LifecycleState == domain.HostStateNew || host.LifecycleState == domain.HostStateReactivated {
		maxScore += 10
		factors = append(factors, domain.InterestingnessFactor{Reason: "Host state: " + host.LifecycleState, Points: 10})
	}
	if maxScore > 100 {
		maxScore = 100
	}
	return maxScore, factors
}

func (a *DefaultAnalyzer) ComputeClusters(hosts []domain.Host) []domain.ServiceCluster {
	byKey := make(map[string]*domain.ServiceCluster)
	for _, h := range hosts {
		for _, s := range h.Services {
			key := s.ClusterKey
			groupBy := "service_product"
			label := strings.TrimSpace(s.Product + " " + s.ServiceName)
			if s.HTTP != nil && s.HTTP.FaviconMMH3 != "" {
				key = "favicon:" + s.HTTP.FaviconMMH3
				groupBy = "favicon"
				label = "Favicon MMH3 " + s.HTTP.FaviconMMH3
			} else if s.HTTP != nil && s.HTTP.Title != "" {
				key = "title:" + strings.ToLower(strings.TrimSpace(s.HTTP.Title))
				groupBy = "http_title"
				label = "HTTP Title: " + s.HTTP.Title
			} else if len(s.Technologies) > 0 {
				names := make([]string, 0, len(s.Technologies))
				for _, t := range s.Technologies {
					names = append(names, t.Name)
				}
				sort.Strings(names)
				key = "tech:" + strings.Join(names, "+")
				groupBy = "tech_stack"
				label = strings.Join(names, " + ")
			}
			if key == "" {
				key = fmt.Sprintf("svc:%s:%d", s.ServiceName, s.Port)
			}
			if label == "" {
				label = fmt.Sprintf("%s/%d", s.ServiceName, s.Port)
			}

			cl, ok := byKey[key]
			if !ok {
				cl = &domain.ServiceCluster{
					ClusterKey: key,
					GroupBy:    groupBy,
					Label:      label,
				}
				byKey[key] = cl
			}
			cl.Count++
			cl.HostIPs = appendUnique(cl.HostIPs, h.IP)
			cl.ServiceIDs = append(cl.ServiceIDs, s.ID)
			if s.Interestingness > cl.MaxScore {
				cl.MaxScore = s.Interestingness
			}
			for _, t := range s.Technologies {
				cl.SampleTechs = appendUnique(cl.SampleTechs, t.Name)
			}
		}
	}
	out := make([]domain.ServiceCluster, 0, len(byKey))
	for _, cl := range byKey {
		out = append(out, *cl)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].MaxScore > out[j].MaxScore
	})
	return out
}

func (a *DefaultAnalyzer) RetroactiveTest(sig domain.Signature, services []domain.Service) []SignatureTestHit {
	hits := []SignatureTestHit{}
	for _, s := range services {
		ok, ev, ver := evalSignature(sig, s.Port, s.ServiceName, s.Product, s.Banner, s.HTTP)
		if !ok {
			continue
		}
		texts := make([]string, 0, len(ev))
		for _, e := range ev {
			texts = append(texts, e.Detail)
		}
		title := ""
		if s.HTTP != nil {
			title = s.HTTP.Title
		}
		hits = append(hits, SignatureTestHit{
			ServiceID:   s.ID,
			HostID:      s.HostID,
			HostIP:      s.HostIP,
			Port:        s.Port,
			Protocol:    s.Protocol,
			Title:       title,
			Version:     ver,
			Confidence:  fuseNoisyOR(ev),
			MatchedText: texts,
		})
	}
	return hits
}

func evalSignature(sig domain.Signature, port int, svcName, product, banner string, fp *domain.HTTPFingerprint) (bool, []domain.TechEvidence, string) {
	if len(sig.Matchers) == 0 {
		return false, nil, ""
	}
	w := sig.ConfidenceWeight
	if w <= 0 || w > 0.99 {
		w = 0.75
	}
	var ev []domain.TechEvidence
	version := ""
	matchedCount := 0

	for _, m := range sig.Matchers {
		ok, detail, ver := evalMatcher(m, port, svcName, product, banner, fp)
		if ok {
			matchedCount++
			ev = append(ev, domain.TechEvidence{SignalType: m.Type, Detail: detail, Weight: w})
			if ver != "" && version == "" {
				version = ver
			}
		}
	}
	if sig.MatchMode == "all" {
		return matchedCount == len(sig.Matchers), ev, version
	}
	return matchedCount > 0, ev, version
}

func evalMatcher(m domain.SignatureMatcher, port int, svcName, product, banner string, fp *domain.HTTPFingerprint) (bool, string, string) {
	matchText := func(target string) (bool, string) {
		if target == "" {
			return false, ""
		}
		if m.Regex {
			re, err := regexp.Compile("(?i)" + m.Pattern)
			if err != nil {
				return false, ""
			}
			sub := re.FindStringSubmatch(target)
			if len(sub) == 0 {
				return false, ""
			}
			ver := ""
			if m.VersionGroup > 0 && m.VersionGroup < len(sub) {
				ver = sub[m.VersionGroup]
			}
			return true, ver
		}
		return strings.Contains(strings.ToLower(target), strings.ToLower(m.Pattern)), ""
	}

	switch m.Type {
	case "banner":
		if ok, ver := matchText(banner + " " + product + " " + svcName); ok {
			return true, "banner matched " + m.Pattern, ver
		}
	case "port":
		if fmt.Sprintf("%d", port) == strings.TrimSpace(m.Pattern) {
			return true, fmt.Sprintf("port %d", port), ""
		}
	case "header":
		if fp == nil {
			return false, "", ""
		}
		for k, v := range fp.Headers {
			if m.Key != "" && !strings.EqualFold(k, m.Key) {
				continue
			}
			if ok, ver := matchText(v); ok {
				return true, fmt.Sprintf("header %s: %s", k, v), ver
			}
		}
		if strings.EqualFold(m.Key, "server") || m.Key == "" {
			if ok, ver := matchText(fp.ServerHeader); ok {
				return true, "Server: " + fp.ServerHeader, ver
			}
		}
	case "cookie":
		if fp == nil {
			return false, "", ""
		}
		for _, c := range fp.Cookies {
			if ok, ver := matchText(c.Name + "=" + c.Value); ok {
				return true, "cookie " + c.Name, ver
			}
		}
	case "favicon_mmh3":
		if fp != nil && fp.FaviconMMH3 != "" && fp.FaviconMMH3 == strings.TrimSpace(m.Pattern) {
			return true, "favicon mmh3 " + fp.FaviconMMH3, ""
		}
	case "favicon_sha256":
		if fp != nil && fp.FaviconSHA256 != "" && strings.EqualFold(fp.FaviconSHA256, strings.TrimSpace(m.Pattern)) {
			return true, "favicon sha256 " + fp.FaviconSHA256, ""
		}
	case "html_body", "footer_version":
		if fp == nil {
			return false, "", ""
		}
		haystack := fp.Title + "\n" + fp.MetaGenerator + "\n" + fp.FooterVersion + "\n" + fp.BodySnippet
		if ok, ver := matchText(haystack); ok {
			return true, "html matched " + m.Pattern, ver
		}
	case "safe_path":
		if fp == nil {
			return false, "", ""
		}
		for _, hit := range fp.SafePathHits {
			if strings.EqualFold(hit.Path, m.Pattern) || strings.Contains(strings.ToLower(hit.Path), strings.ToLower(m.Pattern)) {
				if len(m.StatusCodes) == 0 || containsInt(m.StatusCodes, hit.StatusCode) {
					return true, fmt.Sprintf("path %s (%d)", hit.Path, hit.StatusCode), ""
				}
			}
		}
	case "tls_cert":
		if fp == nil || fp.TLS == nil {
			return false, "", ""
		}
		hay := fp.TLS.SubjectCN + " " + fp.TLS.Issuer + " " + strings.Join(fp.TLS.SANs, " ")
		if ok, ver := matchText(hay); ok {
			return true, "tls cert matched " + m.Pattern, ver
		}
	}
	return false, "", ""
}

func fuseNoisyOR(ev []domain.TechEvidence) int {
	if len(ev) == 0 {
		return 0
	}
	prod := 1.0
	for _, e := range ev {
		w := e.Weight
		if w < 0.05 {
			w = 0.05
		}
		if w > 0.99 {
			w = 0.99
		}
		prod *= (1.0 - w)
	}
	score := int(math.Round((1.0 - prod) * 100.0))
	if score > 99 {
		score = 99
	}
	return score
}

func computeClusterKey(svc *domain.ObservedService, techs []domain.DetectedTechnology) string {
	if svc.HTTP != nil && svc.HTTP.FaviconMMH3 != "" {
		return "favicon:" + svc.HTTP.FaviconMMH3
	}
	if len(techs) > 0 {
		return "tech:" + strings.ToLower(techs[0].Name)
	}
	if svc.HTTP != nil && svc.HTTP.Title != "" {
		return "title:" + strings.ToLower(strings.TrimSpace(svc.HTTP.Title))
	}
	return fmt.Sprintf("svc:%s:%d", strings.ToLower(svc.ServiceName), svc.Port)
}

func appendUnique(slice []string, items ...string) []string {
	seen := make(map[string]bool, len(slice))
	for _, s := range slice {
		seen[s] = true
	}
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it != "" && !seen[it] {
			seen[it] = true
			slice = append(slice, it)
		}
	}
	return slice
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
