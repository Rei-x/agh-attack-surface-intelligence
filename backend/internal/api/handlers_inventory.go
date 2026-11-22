package api

import (
	"encoding/binary"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
)

// Read-only inventory view: "show me every product we run, how many hosts, which versions,
// how many of them are EOL / have a known CVE / expose an admin panel". Every number comes
// with the asset query that lists the hosts behind it, so the UI can drill down from any
// count. Also serves the one-click filter counts and the de-duplicated IP scope.

// inventoryExcludedCategories are signature categories that describe a property of a
// service (admin panel, staging, header leak), not a product.
var inventoryExcludedCategories = map[string]bool{
	"admin_panel": true, "staging": true, "custom": true,
	"interesting_header": true, "interesting_cookie": true,
}

type inventoryVersion struct {
	Version string `json:"version"`
	Count   int    `json:"count"`
}

type inventoryProduct struct {
	Name         string             `json:"name"`
	Category     string             `json:"category,omitempty"`
	Query        string             `json:"query"`
	LogoNames    []string           `json:"logo_names"`
	HostCount    int                `json:"host_count"`
	ServiceCount int                `json:"service_count"`
	EOLCount     int                `json:"eol_count"`
	VulnCount    int                `json:"vuln_count"`
	AdminCount   int                `json:"admin_count"`
	NewCount     int                `json:"new_count"`
	MaxScore     int                `json:"max_score"`
	Versions     []inventoryVersion `json:"versions"`
	Ports        []int              `json:"ports"`

	hosts, eolHosts, vulnHosts, adminHosts, newHosts map[string]bool
	versions                                         map[string]int
	ports                                            map[int]int
}

type quickFilterCount struct {
	Key   string `json:"key"`
	Query string `json:"query"`
	Count int    `json:"count"`
}

// inventoryQuickFilters are the one-click chips above the asset list. The query strings
// are the contract with the UI; counts are computed with the same matcher as the list.
var inventoryQuickFilters = []struct{ Key, Query string }{
	{"admin", "admin:true"},
	{"eol", "eol:true"},
	{"vuln", "vuln:true"},
	{"db", "db:true"},
	{"staging", "staging:true"},
	{"iot", "iot:true"},
	{"cleartext", "cleartext:true"},
	{"cert_expired", "cert:expired"},
	{"new", "state:new"},
}

type inventoryScope struct {
	IPs     int `json:"ips"`
	RawIPs  int `json:"raw_ips"`
	Targets int `json:"targets"`
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, _, err := s.store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	now := time.Now().UTC()
	eol.AnnotateHosts(hosts, now)

	products := buildInventory(hosts)

	quick := make([]quickFilterCount, 0, len(inventoryQuickFilters))
	for _, qf := range inventoryQuickFilters {
		q, err := db.ParseAssetQuery(qf.Query)
		if err != nil {
			continue
		}
		n := 0
		for i := range hosts {
			if q.MatchHost(&hosts[i]) {
				n++
			}
		}
		quick = append(quick, quickFilterCount{Key: qf.Key, Query: qf.Query, Count: n})
	}

	profiles, _ := s.store.ListProfiles(ctx)
	var targets []string
	for _, p := range profiles {
		if p.Enabled {
			targets = append(targets, p.Targets...)
		}
	}
	scope := dedupedScope(targets)
	if scope.IPs == 0 {
		scope.IPs = len(hosts)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"products":      products,
		"quick_filters": quick,
		"scope":         scope,
		"total_hosts":   len(hosts),
	})
}

func buildInventory(hosts []domain.Host) []inventoryProduct {
	byKey := map[string]*inventoryProduct{}
	get := func(name, category string, svc *domain.Service) *inventoryProduct {
		key := strings.ToLower(strings.TrimSpace(name))
		p := byKey[key]
		if p == nil {
			p = &inventoryProduct{
				Name: name, Category: category, Query: assetQueryValue("tech", name),
				hosts: map[string]bool{}, eolHosts: map[string]bool{}, vulnHosts: map[string]bool{},
				adminHosts: map[string]bool{}, newHosts: map[string]bool{},
				versions: map[string]int{}, ports: map[int]int{},
			}
			p.LogoNames = append(p.LogoNames, name)
			if svc.Product != "" && !strings.EqualFold(svc.Product, name) {
				p.LogoNames = append(p.LogoNames, svc.Product)
			}
			byKey[key] = p
		}
		return p
	}
	for hi := range hosts {
		h := &hosts[hi]
		for si := range h.Services {
			svc := &h.Services[si]
			seen := map[string]bool{}
			add := func(name, category, version string) {
				k := strings.ToLower(name)
				if name == "" || seen[k] {
					return
				}
				seen[k] = true
				p := get(name, category, svc)
				p.ServiceCount++
				p.hosts[h.ID] = true
				p.ports[svc.Port]++
				if v := shortVersion(version); v != "" {
					p.versions[v]++
				}
				if svc.Interestingness > p.MaxScore {
					p.MaxScore = svc.Interestingness
				}
				if svc.IsAdminPanel {
					p.adminHosts[h.ID] = true
				}
				if h.LifecycleState == domain.HostStateNew {
					p.newHosts[h.ID] = true
				}
				for _, o := range svc.Outdated {
					if productMatches(o.Product, name) {
						p.eolHosts[h.ID] = true
					}
				}
				for _, v := range svc.KnownVulns {
					if productMatches(v.Product, name) {
						p.vulnHosts[h.ID] = true
					}
				}
			}
			for _, t := range svc.Technologies {
				if inventoryExcludedCategories[t.Category] {
					continue
				}
				ver := t.Version
				if ver == "" && svc.Product != "" && productMatches(svc.Product, t.Name) {
					ver = svc.Version
				}
				add(t.Name, t.Category, ver)
			}
			if len(seen) == 0 && svc.Product != "" {
				add(svc.Product, "", svc.Version)
			}
		}
	}

	out := make([]inventoryProduct, 0, len(byKey))
	for _, p := range byKey {
		p.HostCount = len(p.hosts)
		p.EOLCount = len(p.eolHosts)
		p.VulnCount = len(p.vulnHosts)
		p.AdminCount = len(p.adminHosts)
		p.NewCount = len(p.newHosts)
		for v, n := range p.versions {
			p.Versions = append(p.Versions, inventoryVersion{Version: v, Count: n})
		}
		sort.Slice(p.Versions, func(i, j int) bool {
			if p.Versions[i].Count != p.Versions[j].Count {
				return p.Versions[i].Count > p.Versions[j].Count
			}
			return p.Versions[i].Version < p.Versions[j].Version
		})
		if p.Versions == nil {
			p.Versions = []inventoryVersion{}
		}
		for port := range p.ports {
			p.Ports = append(p.Ports, port)
		}
		sort.Ints(p.Ports)
		if len(p.Ports) > 6 {
			p.Ports = p.Ports[:6]
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HostCount != out[j].HostCount {
			return out[i].HostCount > out[j].HostCount
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// productMatches loosely matches an nmap/EOL product name against a technology name by
// their first word ("Apache httpd" ~ "Apache HTTP Server", "nginx" ~ "Nginx").
func productMatches(a, b string) bool {
	fa := strings.Fields(strings.ToLower(a))
	fb := strings.Fields(strings.ToLower(b))
	if len(fa) == 0 || len(fb) == 0 {
		return false
	}
	return fa[0] == fb[0] || strings.Contains(strings.ToLower(a), strings.ToLower(b)) || strings.Contains(strings.ToLower(b), strings.ToLower(a))
}

// shortVersion keeps the version core ("8.9p1 Ubuntu 3ubuntu0.10" -> "8.9p1",
// "9.6.0 or later" -> "9.6.0").
func shortVersion(v string) string {
	f := strings.Fields(strings.TrimSpace(v))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// assetQueryValue renders key:value, quoting values that contain spaces or commas.
func assetQueryValue(key, value string) string {
	v := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), `"`, "")
	if strings.ContainsAny(v, " ,\t") {
		return key + `:"` + v + `"`
	}
	return key + ":" + v
}

// dedupedScope counts scan-scope IPs with overlapping CIDRs merged (a /22 inside a /18 is
// counted once). IPv6 targets are counted as-is.
func dedupedScope(targets []string) inventoryScope {
	type span struct{ lo, hi uint64 }
	var spans []span
	sc := inventoryScope{}
	extra := 0
	for _, raw := range targets {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		sc.Targets++
		sc.RawIPs += countTargetIPs(t)
		lo, hi, ok := ipv4Span(t)
		if !ok {
			extra += countTargetIPs(t)
			continue
		}
		spans = append(spans, span{lo, hi})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	var total uint64
	var cur *span
	for i := range spans {
		sp := spans[i]
		if cur != nil && sp.lo <= cur.hi+1 {
			if sp.hi > cur.hi {
				cur.hi = sp.hi
			}
			continue
		}
		if cur != nil {
			total += cur.hi - cur.lo + 1
		}
		c := sp
		cur = &c
	}
	if cur != nil {
		total += cur.hi - cur.lo + 1
	}
	sc.IPs = int(total) + extra
	return sc
}

func ipv4Span(t string) (uint64, uint64, bool) {
	switch {
	case strings.Contains(t, "/"):
		_, n, err := net.ParseCIDR(t)
		if err != nil || n.IP.To4() == nil {
			return 0, 0, false
		}
		ones, bits := n.Mask.Size()
		lo := uint64(binary.BigEndian.Uint32(n.IP.To4()))
		return lo, lo + (uint64(1) << uint(bits-ones)) - 1, true
	case strings.Contains(t, "-"):
		parts := strings.SplitN(t, "-", 2)
		a := net.ParseIP(strings.TrimSpace(parts[0])).To4()
		b := net.ParseIP(strings.TrimSpace(parts[1])).To4()
		if a == nil || b == nil {
			return 0, 0, false
		}
		lo, hi := uint64(binary.BigEndian.Uint32(a)), uint64(binary.BigEndian.Uint32(b))
		if hi < lo {
			return 0, 0, false
		}
		return lo, hi, true
	default:
		ip := net.ParseIP(t).To4()
		if ip == nil {
			return 0, 0, false
		}
		v := uint64(binary.BigEndian.Uint32(ip))
		return v, v, true
	}
}

/* ---------- light host list projection (GET /api/v1/hosts?fields=summary) ---------- */

type summaryTLS struct {
	IsExpired    bool `json:"is_expired"`
	IsSelfSigned bool `json:"is_self_signed"`
	DaysToExpiry int  `json:"days_to_expiry"`
}

type summaryHTTP struct {
	Title         string      `json:"title,omitempty"`
	ServerHeader  string      `json:"server_header,omitempty"`
	MetaGenerator string      `json:"meta_generator,omitempty"`
	StatusCode    int         `json:"status_code,omitempty"`
	TLS           *summaryTLS `json:"tls,omitempty"`
}

type summaryTech struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version,omitempty"`
	Confidence int    `json:"confidence"`
}

type summaryService struct {
	ID                string                     `json:"id"`
	HostID            string                     `json:"host_id"`
	Port              int                        `json:"port"`
	Protocol          string                     `json:"protocol"`
	State             string                     `json:"state"`
	ServiceName       string                     `json:"service_name"`
	Product           string                     `json:"product,omitempty"`
	Version           string                     `json:"version,omitempty"`
	HTTP              *summaryHTTP               `json:"http,omitempty"`
	Technologies      []summaryTech              `json:"technologies"`
	MatchedSignatures []string                   `json:"matched_signatures"`
	IsAdminPanel      bool                       `json:"is_admin_panel"`
	IsStagingEnv      bool                       `json:"is_staging_env"`
	IsIoT             bool                       `json:"is_iot"`
	Outdated          []domain.OutdatedComponent `json:"outdated,omitempty"`
	KnownVulns        []domain.VulnHint          `json:"known_vulns,omitempty"`
	Vulns             []domain.VulnSummary       `json:"vulns,omitempty"`    // without the full CVE id list
	Verified          []domain.VerifiedFinding   `json:"verified,omitempty"` // check, name and severity only
	Interestingness   int                        `json:"interestingness"`
	TriageStatus      string                     `json:"triage_status"`
	Triage            *domain.TriageInfo         `json:"triage,omitempty"`
	Tags              []string                   `json:"tags"`

	PolicyViolations []domain.PolicyHit `json:"policy_violations,omitempty"`
}

type summaryHost struct {
	ID                string             `json:"id"`
	IP                string             `json:"ip"`
	Hostname          string             `json:"hostname,omitempty"`
	OSGuess           string             `json:"os_guess,omitempty"`
	LifecycleState    string             `json:"lifecycle_state"`
	Environment       string             `json:"environment,omitempty"`
	Owner             string             `json:"owner,omitempty"`
	Tags              []string           `json:"tags"`
	FirstSeen         time.Time          `json:"first_seen"`
	LastSeen          time.Time          `json:"last_seen"`
	TotalScansSeen    int                `json:"total_scans_seen"`
	TotalScansChecked int                `json:"total_scans_checked"`
	ConsecutiveMisses int                `json:"consecutive_misses"`
	StateTransitions  int                `json:"state_transitions"`
	StabilityScore    int                `json:"stability_score"`
	Interestingness   int                `json:"interestingness"`
	LockedFields      []string           `json:"locked_fields,omitempty"`
	Services          []summaryService   `json:"services"`
	ServiceCount      int                `json:"service_count"`
	TriageStatus      string             `json:"triage_status,omitempty"`
	Triage            *domain.TriageInfo `json:"triage,omitempty"`
}

// summarizeHosts drops evidence, headers, cookies, bodies, banners and history from the
// list response (the drawer loads the full host by id).
func summarizeHosts(hosts []domain.Host) []summaryHost {
	out := make([]summaryHost, 0, len(hosts))
	for _, h := range hosts {
		sh := summaryHost{
			ID: h.ID, IP: h.IP, Hostname: h.Hostname, OSGuess: h.OSGuess, LifecycleState: h.LifecycleState,
			Environment: h.Environment, Owner: h.Owner, Tags: h.Tags, FirstSeen: h.FirstSeen, LastSeen: h.LastSeen,
			TotalScansSeen: h.TotalScansSeen, TotalScansChecked: h.TotalScansChecked,
			ConsecutiveMisses: h.ConsecutiveMisses, StateTransitions: h.StateTransitions,
			StabilityScore: h.StabilityScore, Interestingness: h.Interestingness, LockedFields: h.LockedFields,
			ServiceCount: h.ServiceCount, TriageStatus: h.TriageStatus, Triage: h.Triage,
			Services: make([]summaryService, 0, len(h.Services)),
		}
		if sh.ServiceCount == 0 {
			sh.ServiceCount = len(h.Services)
		}
		for _, s := range h.Services {
			ss := summaryService{
				ID: s.ID, HostID: s.HostID, Port: s.Port, Protocol: s.Protocol, State: s.State,
				ServiceName: s.ServiceName, Product: s.Product, Version: s.Version,
				MatchedSignatures: s.MatchedSignatures, IsAdminPanel: s.IsAdminPanel, IsStagingEnv: s.IsStagingEnv,
				IsIoT: s.IsIoT, Outdated: s.Outdated, KnownVulns: s.KnownVulns, Interestingness: s.Interestingness,
				TriageStatus: s.TriageStatus, Triage: s.Triage, Tags: s.Tags,
				Technologies: make([]summaryTech, 0, len(s.Technologies)),
			}
			ss.PolicyViolations = s.PolicyViolations
			ss.Vulns, ss.Verified = slimVulnEvidence(s.Vulns, s.Verified)
			for _, t := range s.Technologies {
				ss.Technologies = append(ss.Technologies, summaryTech{Name: t.Name, Category: t.Category, Version: t.Version, Confidence: t.Confidence})
			}
			if s.HTTP != nil {
				ss.HTTP = &summaryHTTP{Title: s.HTTP.Title, ServerHeader: s.HTTP.ServerHeader, MetaGenerator: s.HTTP.MetaGenerator, StatusCode: s.HTTP.StatusCode}
				if s.HTTP.TLS != nil {
					ss.HTTP.TLS = &summaryTLS{IsExpired: s.HTTP.TLS.IsExpired, IsSelfSigned: s.HTTP.TLS.IsSelfSigned, DaysToExpiry: s.HTTP.TLS.DaysToExpiry}
				}
			}
			sh.Services = append(sh.Services, ss)
		}
		out = append(out, sh)
	}
	return out
}

// slimVulnEvidence keeps what the list badges need (counts, KEV, top CVEs, verified check
// names) and drops the full CVE id lists and request/response evidence.
func slimVulnEvidence(vulns []domain.VulnSummary, verified []domain.VerifiedFinding) ([]domain.VulnSummary, []domain.VerifiedFinding) {
	var vs []domain.VulnSummary
	for _, v := range vulns {
		v.CVEIDs = nil
		vs = append(vs, v)
	}
	var vf []domain.VerifiedFinding
	for _, f := range verified {
		vf = append(vf, domain.VerifiedFinding{CheckID: f.CheckID, Name: f.Name, Severity: f.Severity, ServiceID: f.ServiceID, Port: f.Port, DefaultCreds: f.DefaultCreds, CheckedAt: f.CheckedAt})
	}
	return vs, vf
}
