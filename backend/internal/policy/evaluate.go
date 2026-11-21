package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
)

// compiledZone is a zone with parsed networks.
type compiledZone struct {
	zone domain.PolicyZone
	nets []*net.IPNet
}

// Matcher finds the zone of an IP: the enabled zone with the longest matching prefix
// (ties: earlier in the list wins).
type Matcher struct {
	zones []compiledZone
}

// NewMatcher compiles the enabled zones. Invalid CIDRs are skipped (zones are validated on
// save, so this only guards against hand-edited data).
func NewMatcher(zones []domain.PolicyZone) *Matcher {
	m := &Matcher{}
	for _, z := range zones {
		if !z.Enabled {
			continue
		}
		cz := compiledZone{zone: z}
		for _, c := range z.CIDRs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				cz.nets = append(cz.nets, n)
			}
		}
		if len(cz.nets) > 0 {
			m.zones = append(m.zones, cz)
		}
	}
	return m
}

// ZoneFor returns the zone governing ip, or nil when no enabled zone contains it.
func (m *Matcher) ZoneFor(ipStr string) *domain.PolicyZone {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || m == nil {
		return nil
	}
	best, bestOnes := -1, -1
	for i, cz := range m.zones {
		for _, n := range cz.nets {
			if !n.Contains(ip) {
				continue
			}
			if ones, _ := n.Mask.Size(); ones > bestOnes {
				best, bestOnes = i, ones
			}
		}
	}
	if best < 0 {
		return nil
	}
	return &m.zones[best].zone
}

// Evaluate returns the violations present in hosts (services loaded) at now. It is pure:
// FirstSeen/LastSeen are set to now and Status to open; Engine merges them with history.
// Gone things never violate: closed or filtered services, hosts that are MISSING or
// INACTIVE, and hosts or services an analyst marked accepted risk or false positive.
func Evaluate(zones []domain.PolicyZone, hosts []domain.Host, now time.Time) []domain.PolicyViolation {
	m := NewMatcher(zones)
	if len(m.zones) == 0 {
		return nil
	}
	var out []domain.PolicyViolation
	for i := range hosts {
		h := &hosts[i]
		if h.LifecycleState == domain.HostStateMissing || h.LifecycleState == domain.HostStateInactive {
			continue
		}
		if h.Triage.IsSuppressing(now) {
			continue
		}
		z := m.ZoneFor(h.IP)
		if z == nil {
			continue
		}
		for j := range h.Services {
			s := h.Services[j]
			if s.State != "" && !strings.EqualFold(s.State, "open") {
				continue
			}
			if s.Triage.IsSuppressing(now) {
				continue
			}
			if s.HostIP == "" {
				s.HostIP = h.IP
			}
			if v, ok := CheckService(z, h, &s, now); ok {
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

type reason struct {
	rule     string
	severity string
	evidence string
}

// CheckService checks one open service against its zone. ok=false when it complies.
func CheckService(z *domain.PolicyZone, h *domain.Host, s *domain.Service, now time.Time) (domain.PolicyViolation, bool) {
	var reasons []reason
	r := z.Rules
	label := serviceLabel(s)

	if r.NoServices {
		reasons = append(reasons, reason{domain.PolicyRuleNoServices, "medium",
			fmt.Sprintf("%s listens on port %d; this zone allows no services", label, s.Port)})
	} else if len(r.AllowedPorts) > 0 && !containsInt(r.AllowedPorts, s.Port) {
		reasons = append(reasons, reason{domain.PolicyRulePort, "medium",
			fmt.Sprintf("Port %d (%s) is not on the allowed list (%s)", s.Port, label, joinInts(r.AllowedPorts))})
	}
	for _, cat := range r.Forbidden {
		if ev, hit := categoryEvidence(cat, s, now); hit {
			c, _ := CategoryByID(cat)
			reasons = append(reasons, reason{domain.PolicyRuleForbidden + cat, c.Severity, ev})
		}
	}
	if r.RequireTLS && isPlainWeb(s) {
		reasons = append(reasons, reason{domain.PolicyRuleTLS, "low",
			fmt.Sprintf("Web service on port %d answers over plain HTTP without redirecting to HTTPS", s.Port)})
	}
	if r.MaxRisk > 0 && s.Interestingness > r.MaxRisk {
		reasons = append(reasons, reason{domain.PolicyRuleMaxRisk, "medium",
			fmt.Sprintf("Risk score %d is above the zone limit of %d", s.Interestingness, r.MaxRisk)})
	}
	if len(reasons) == 0 {
		return domain.PolicyViolation{}, false
	}

	// Most severe reason first; stable for equal severity (rule order above).
	sort.SliceStable(reasons, func(i, j int) bool { return sevRank(reasons[i].severity) > sevRank(reasons[j].severity) })
	sev := reasons[0].severity
	// Critical only when a high-severity breach sits on a service already scored near the top.
	if sev == "high" && s.Interestingness >= 90 {
		sev = "critical"
	}
	rules := make([]string, 0, len(reasons))
	evidence := make([]string, 0, len(reasons))
	for _, rs := range reasons {
		rules = append(rules, rs.rule)
		evidence = append(evidence, rs.evidence)
	}
	owner := strings.TrimSpace(h.Owner)
	if owner == "" {
		owner = z.Owner
	}
	proto := s.Protocol
	if proto == "" {
		proto = "tcp"
	}
	return domain.PolicyViolation{
		ID:          ViolationID(z.ID, h.IP, s.Port, proto),
		ZoneID:      z.ID,
		ZoneName:    z.Name,
		Rule:        rules[0],
		Rules:       rules,
		Severity:    sev,
		Summary:     fmt.Sprintf("%s on %s:%d breaks zone %q: %s", label, h.IP, s.Port, z.Name, RuleLabel(rules[0])),
		Evidence:    evidence,
		HostID:      h.ID,
		HostIP:      h.IP,
		Hostname:    h.Hostname,
		ServiceID:   s.ID,
		Port:        s.Port,
		Protocol:    proto,
		ServiceName: s.ServiceName,
		Owner:       owner,
		Status:      domain.PolicyStatusOpen,
		FirstSeen:   now,
		LastSeen:    now,
	}, true
}

// ViolationID is stable for a (zone, endpoint) pair, so a violation keeps its identity
// across scans even when the service record is re-created.
func ViolationID(zoneID, ip string, port int, proto string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s", zoneID, strings.TrimSpace(ip), port, strings.ToLower(proto))))
	return "pv-" + hex.EncodeToString(sum[:10])
}

// RuleLabel is the short human text of a rule id.
func RuleLabel(rule string) string {
	switch rule {
	case domain.PolicyRuleNoServices:
		return "no services allowed"
	case domain.PolicyRulePort:
		return "port not allowed"
	case domain.PolicyRuleTLS:
		return "TLS required"
	case domain.PolicyRuleMaxRisk:
		return "risk above limit"
	}
	if cat, ok := strings.CutPrefix(rule, domain.PolicyRuleForbidden); ok {
		if c, found := CategoryByID(cat); found {
			return strings.ToLower(c.Label) + " not allowed"
		}
		return cat + " not allowed"
	}
	return rule
}

var bmcPattern = regexp.MustCompile(`(?i)\bbmc\b|idrac|integrated lights-out|\bilo\b|ipmi|supermicro`)

// IsBMC reports out-of-band server management (iDRAC, iLO, IPMI), same rule as the UI.
func IsBMC(s *domain.Service) bool {
	if s.Port == 623 || strings.EqualFold(s.ServiceName, "asf-rmcp") || strings.EqualFold(s.ServiceName, "ipmi") {
		return true
	}
	for _, n := range s.MatchedSignatures {
		if bmcPattern.MatchString(n) {
			return true
		}
	}
	for _, t := range s.Technologies {
		if bmcPattern.MatchString(t.Name) {
			return true
		}
	}
	return false
}

func categoryEvidence(cat string, s *domain.Service, now time.Time) (string, bool) {
	switch cat {
	case domain.PolicyCatCleartext:
		if db.IsCleartextAdminService(s) {
			return fmt.Sprintf("%s on port %d sends credentials in clear text", nonEmpty(s.ServiceName, "service"), s.Port), true
		}
	case domain.PolicyCatDatabase:
		if db.IsDatabaseService(s) {
			return fmt.Sprintf("Database listener %s reachable on port %d", nonEmpty(s.ServiceName, "service"), s.Port), true
		}
	case domain.PolicyCatAdminPanel:
		if s.IsAdminPanel {
			ev := fmt.Sprintf("Admin interface on port %d", s.Port)
			if s.HTTP != nil && s.HTTP.Title != "" {
				ev += fmt.Sprintf(" (%q)", s.HTTP.Title)
			}
			return ev, true
		}
	case domain.PolicyCatIoTBMC:
		if IsBMC(s) {
			return fmt.Sprintf("%s on port %d; BMCs belong in the management VLAN", techNames(s, "bmc"), s.Port), true
		}
		if s.IsIoT {
			return fmt.Sprintf("Embedded device on port %d (%s)", s.Port, techNames(s, "")), true
		}
	case domain.PolicyCatEOL:
		outdated, _ := eol.Assess(s, now)
		if len(outdated) > 0 {
			labels := make([]string, 0, len(outdated))
			for _, o := range outdated {
				labels = append(labels, fmt.Sprintf("%s %s (end of life %s)", o.Product, nonEmpty(o.Version, o.Branch), o.EOLDate))
			}
			return "End-of-life software: " + strings.Join(labels, "; "), true
		}
	case domain.PolicyCatStaging:
		if s.IsStagingEnv {
			ev := fmt.Sprintf("Staging or dev environment on port %d", s.Port)
			if s.HTTP != nil && s.HTTP.Title != "" {
				ev += fmt.Sprintf(" (%q)", s.HTTP.Title)
			}
			return ev, true
		}
	}
	return "", false
}

var webNames = map[string]bool{"http": true, "http-alt": true, "http-proxy": true, "https": true, "https-alt": true, "ssl/http": true}

// isPlainWeb: an HTTP service that is not TLS and does not end up on https://.
func isPlainWeb(s *domain.Service) bool {
	name := strings.ToLower(s.ServiceName)
	if s.HTTP == nil && !webNames[name] {
		return false
	}
	if strings.Contains(name, "https") || strings.HasPrefix(name, "ssl") {
		return false
	}
	if s.HTTP != nil {
		if s.HTTP.TLS != nil || strings.EqualFold(s.HTTP.Scheme, "https") || strings.HasPrefix(strings.ToLower(s.HTTP.URL), "https://") {
			return false
		}
		for _, hop := range s.HTTP.RedirectChain {
			if strings.HasPrefix(strings.ToLower(hop.URL), "https://") {
				return false
			}
		}
	}
	return true
}

func serviceLabel(s *domain.Service) string {
	name := nonEmpty(s.ServiceName, "service")
	if s.Product != "" && !strings.EqualFold(s.Product, s.ServiceName) {
		name += " (" + s.Product + ")"
	}
	return name
}

func techNames(s *domain.Service, filter string) string {
	var names []string
	seen := map[string]bool{}
	for _, t := range s.Technologies {
		if seen[t.Name] {
			continue
		}
		if filter == "bmc" && !bmcPattern.MatchString(t.Name) {
			continue
		}
		seen[t.Name] = true
		names = append(names, t.Name)
		if len(names) == 2 {
			break
		}
	}
	if len(names) == 0 {
		if filter == "bmc" {
			return "Server BMC"
		}
		return nonEmpty(s.ServiceName, "device")
	}
	return strings.Join(names, ", ")
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func joinInts(list []int) string {
	parts := make([]string, len(list))
	for i, v := range list {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
