// Command scorer compares AegisASI JSON exports (GET /api/v1/export?format=json)
// with scale-lab ground truth and prints a markdown accuracy report.
//
//	scorer -truth1 truth-run1.json -export1 export-run1.json \
//	       [-truth2 truth-run2.json -export2 export-run2.json -app-diff diff.json] \
//	       [-ports 22,80,...] [-meta meta.json] [-out report.md] [-json summary.json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/truth"
)

// ---------------------------------------------------------------- export model (subset of backend domain.Host)

type exCookie struct {
	Name     string   `json:"name"`
	HttpOnly bool     `json:"http_only"`
	Secure   bool     `json:"secure"`
	Flags    []string `json:"flags"`
}

type exTLS struct {
	SubjectCN    string `json:"subject_cn"`
	Issuer       string `json:"issuer"`
	IsSelfSigned bool   `json:"is_self_signed"`
	IsExpired    bool   `json:"is_expired"`
}

type exHTTP struct {
	StatusCode         int        `json:"status_code"`
	Title              string     `json:"title"`
	ServerHeader       string     `json:"server_header"`
	MissingSecHeaders  []string   `json:"missing_sec_headers"`
	InterestingHeaders []string   `json:"interesting_headers"`
	Cookies            []exCookie `json:"cookies"`
	TLS                *exTLS     `json:"tls"`
	MetaGenerator      string     `json:"meta_generator"`
}

type exTech struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Version  string `json:"version"`
}

type exService struct {
	Port         int      `json:"port"`
	Protocol     string   `json:"protocol"`
	State        string   `json:"state"`
	ServiceName  string   `json:"service_name"`
	Product      string   `json:"product"`
	Version      string   `json:"version"`
	HTTP         *exHTTP  `json:"http"`
	Technologies []exTech `json:"technologies"`
	IsAdminPanel bool     `json:"is_admin_panel"`
	IsStagingEnv bool     `json:"is_staging_env"`
	IsIoT        bool     `json:"is_iot"`
}

type exHost struct {
	IP             string      `json:"ip"`
	Hostname       string      `json:"hostname"`
	LifecycleState string      `json:"lifecycle_state"`
	Environment    string      `json:"environment"`
	StabilityScore int         `json:"stability_score"`
	TotalSeen      int         `json:"total_scans_seen"`
	TotalChecked   int         `json:"total_scans_checked"`
	Services       []exService `json:"services"`
}

type export struct {
	Count int      `json:"count"`
	Hosts []exHost `json:"hosts"`
}

// ---------------------------------------------------------------- helpers

type prf struct{ TP, FP, FN int }

func (m prf) P() float64 {
	if m.TP+m.FP == 0 {
		return 1
	}
	return float64(m.TP) / float64(m.TP+m.FP)
}
func (m prf) R() float64 {
	if m.TP+m.FN == 0 {
		return 1
	}
	return float64(m.TP) / float64(m.TP+m.FN)
}
func (m prf) F1() float64 {
	p, r := m.P(), m.R()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}
func (m *prf) add(o prf) { m.TP += o.TP; m.FP += o.FP; m.FN += o.FN }

func cmpSets(truthSet, pred map[string]bool) (m prf, fps, fns []string) {
	for k := range pred {
		if truthSet[k] {
			m.TP++
		} else {
			m.FP++
			fps = append(fps, k)
		}
	}
	for k := range truthSet {
		if !pred[k] {
			m.FN++
			fns = append(fns, k)
		}
	}
	sort.Strings(fps)
	sort.Strings(fns)
	return
}

func pct(x float64) string { return fmt.Sprintf("%.1f%%", 100*x) }

type acc struct{ OK, N int }

func (a *acc) add(ok bool) {
	a.N++
	if ok {
		a.OK++
	}
}
func (a acc) String() string {
	if a.N == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%s (%d/%d)", pct(float64(a.OK)/float64(a.N)), a.OK, a.N)
}

func loadJSON(path string, v any) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(v); err != nil {
		log.Fatalf("decode %s: %v", path, err)
	}
}

// service name equivalence classes.
func svcClass(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	n = strings.TrimSuffix(n, "?")
	n = strings.TrimPrefix(n, "ssl/")
	n = strings.TrimPrefix(n, "tls/")
	switch n {
	case "http", "https", "http-alt", "http-proxy", "https-alt", "www", "http-mgmt", "ppp", "upnp", "sun-answerbook", "ssl", "commplex-main", "commplex-link", "irdmi", "cslistener", "wap-wsp", "esmagent", "websm", "ajp13":
		return "http"
	case "ms-wbt-server", "rdp":
		return "rdp"
	case "microsoft-ds", "smb", "netbios-ssn":
		return "smb"
	case "postgres", "postgresql":
		return "postgresql"
	case "mysql", "mariadb":
		return "mysql"
	case "smtp", "smtps", "submission":
		return "smtp"
	case "ipp", "cups":
		return "ipp"
	case "jetdirect", "pdl-datastream":
		return "jetdirect"
	}
	return n
}

var genericTech = map[string]bool{
	"admin panel / management console": true, "authentication / login portal": true, "exposed database service": true,
	"exposed docker engine api": true, "admin console": true, "staging / debug environment": true,
}

var techAlias = map[string]string{
	"apache http server": "apache", "apache httpd": "apache", "apache": "apache", "microsoft iis": "iis", "iis": "iis",
	"microsoft-iis": "iis", "apache tomcat": "tomcat", "tomcat": "tomcat", "nginx": "nginx", "roundcube webmail": "roundcube",
	"hp printer / embedded web server": "hp-printer", "brother printer web interface": "brother-printer",
	"hikvision ip camera / nvr": "hikvision", "mikrotik routeros": "mikrotik-routeros", "synology dsm": "synology-dsm",
	"server bmc (dell idrac / hpe ilo)": "idrac", "spring boot": "spring-boot", "asp.net": "asp.net", "express": "express",
	"node.js": "node.js", "canon printer / remote ui": "canon-printer", "vue.js": "vue.js", "next.js": "next.js",
	"jetty": "jetty", "php": "php", "elastic": "elasticsearch", "elasticsearch": "elasticsearch",
}

// banner-level products are scored via product accuracy, not as web technologies.
var bannerTech = map[string]bool{"openssh": true, "vsftpd": true, "proftpd": true, "postfix": true, "exim": true, "dovecot": true, "mysql": true, "mariadb": true, "postgresql": true, "redis": true}

var nonAlnum = regexp.MustCompile(`[^a-z0-9.+-]+`)

func normTech(t exTech) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(t.Name))
	switch strings.ToLower(t.Category) {
	case "staging", "interesting_header", "interesting_cookie", "tls":
		return "", false
	}
	if genericTech[n] {
		return "", false
	}
	if a, ok := techAlias[n]; ok {
		return a, true
	}
	return strings.Trim(nonAlnum.ReplaceAllString(n, "-"), "-"), true
}

func alivePred(h exHost) bool {
	switch strings.ToUpper(h.LifecycleState) {
	case "MISSING", "INACTIVE":
		return false
	}
	return true
}

func openSvcs(h exHost) []exService {
	var out []exService
	for _, s := range h.Services {
		if s.State == "" || strings.EqualFold(s.State, "open") {
			out = append(out, s)
		}
	}
	return out
}

func normTitle(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// ---------------------------------------------------------------- per-run scoring

type runScore struct {
	Label         string
	TruthAlive    int
	Unstable      int
	PredInCIDR    int
	PredAlive     int
	PredWithSvc   int
	Hosts         prf
	HostsSvcBased prf // predicted alive = has >=1 open service
	Ports         prf
	SvcName       acc
	Product       acc
	Version       acc
	Tech          prf
	TechPer       map[string]*prf
	Admin         prf
	Staging       prf
	IoT           prf
	Title         acc
	ServerHdr     acc
	IntHeaders    prf
	InsecCookie   prf
	MissingSec    prf
	SelfSigned    prf
	Expired       prf
	HTTPFp        acc // HTTP services that carry a fingerprint
	ByClass       map[string]*acc
	ByArch        map[string]*[2]acc // host recall, port recall
	UnstableRows  []string
	MissedHostEx  []string
	FPHostEx      []string
	FPPortEx      []string
	FNPortEx      []string
	SvcNameEx     []string
	TechFPEx      []string
	TechFNEx      []string
	VersionEx     []string
}

type predIndex struct {
	hosts map[string]exHost
}

func indexExport(ex *export, pfx netip.Prefix) predIndex {
	pi := predIndex{hosts: map[string]exHost{}}
	for _, h := range ex.Hosts {
		a, err := netip.ParseAddr(h.IP)
		if err != nil || !pfx.Contains(a) {
			continue
		}
		pi.hosts[h.IP] = h
	}
	return pi
}

func hostTruthTechs(h *truth.Host) map[string]bool {
	out := map[string]bool{}
	for _, s := range h.Services {
		if s.HTTP == nil {
			continue
		}
		for _, t := range s.Technologies {
			if !bannerTech[t] {
				out[t] = true
			}
		}
	}
	return out
}

func hostPredTechs(h exHost) map[string]bool {
	out := map[string]bool{}
	for _, s := range openSvcs(h) {
		for _, t := range s.Technologies {
			if n, ok := normTech(t); ok && !bannerTech[n] {
				out[n] = true
			}
		}
	}
	return out
}

func limit(xs []string, n int) []string {
	if len(xs) > n {
		return append(xs[:n:n], fmt.Sprintf("… (+%d more)", len(xs)-n))
	}
	return xs
}

func scoreRun(label string, td *truth.Document, ex *export, ports map[int]bool) *runScore {
	pfx := netip.MustParsePrefix(td.CIDR)
	pi := indexExport(ex, pfx)
	rs := &runScore{Label: label, TechPer: map[string]*prf{}, ByClass: map[string]*acc{}, ByArch: map[string]*[2]acc{}}
	unstable := map[string]bool{}
	alive := map[string]*truth.Host{}
	for i := range td.Hosts {
		h := &td.Hosts[i]
		if h.Unstable() {
			unstable[h.IP] = true
			rs.Unstable++
			ph, found := pi.hosts[h.IP]
			state := "-"
			if found {
				state = ph.LifecycleState
			}
			kind := "flapping"
			if !h.Flapping {
				kind = "toggled during scan"
			}
			rs.UnstableRows = append(rs.UnstableRows, fmt.Sprintf("| %s | %s | %s | %v | %v | %s |", h.IP, h.Archetype, kind, h.Alive, found && alivePred(ph), state))
			continue
		}
		if h.Alive {
			alive[h.IP] = h
		}
	}
	rs.TruthAlive = len(alive)
	rs.PredInCIDR = len(pi.hosts)

	// Hosts.
	tset, pset, pset2 := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for ip := range alive {
		tset[ip] = true
	}
	for ip, h := range pi.hosts {
		if unstable[ip] {
			continue
		}
		if alivePred(h) {
			pset[ip] = true
			rs.PredAlive++
			if len(openSvcs(h)) > 0 {
				pset2[ip] = true
				rs.PredWithSvc++
			}
		}
	}
	var fps, fns []string
	rs.Hosts, fps, fns = cmpSets(tset, pset)
	rs.HostsSvcBased, _, _ = cmpSets(tset, pset2)
	rs.FPHostEx = limit(fps, 10)
	for _, ip := range fns {
		h := alive[ip]
		var ps []string
		for _, s := range h.Services {
			ps = append(ps, strconv.Itoa(s.Port))
		}
		rs.MissedHostEx = append(rs.MissedHostEx, fmt.Sprintf("%s (%s, icmp_blocked=%v firewalled=%v, ports %s)", ip, h.Archetype, h.ICMPBlocked, h.Firewalled, strings.Join(ps, ",")))
	}
	rs.MissedHostEx = limit(rs.MissedHostEx, 15)

	// Host recall by network class and archetype.
	for ip, h := range alive {
		class := "normal"
		switch {
		case h.ICMPBlocked && h.Firewalled:
			class = "icmp_blocked+firewalled"
		case h.ICMPBlocked:
			class = "icmp_blocked"
		case h.Firewalled:
			class = "firewalled"
		}
		if rs.ByClass[class] == nil {
			rs.ByClass[class] = &acc{}
		}
		rs.ByClass[class].add(pset[ip])
		if rs.ByArch[h.Archetype] == nil {
			rs.ByArch[h.Archetype] = &[2]acc{}
		}
		rs.ByArch[h.Archetype][0].add(pset[ip])
	}

	// Ports, service identification, HTTP details.
	tports, pports := map[string]bool{}, map[string]bool{}
	tsvc := map[string]truth.Service{}
	psvc := map[string]exService{}
	for ip, h := range alive {
		for _, s := range h.Services {
			if !ports[s.Port] {
				continue
			}
			k := ip + ":" + strconv.Itoa(s.Port)
			tports[k] = true
			tsvc[k] = s
		}
	}
	for ip, h := range pi.hosts {
		if unstable[ip] || !alivePred(h) {
			continue
		}
		for _, s := range openSvcs(h) {
			k := ip + ":" + strconv.Itoa(s.Port)
			pports[k] = true
			psvc[k] = s
		}
	}
	rs.Ports, fps, fns = cmpSets(tports, pports)
	rs.FPPortEx = limit(fps, 10)
	var fnEx []string
	for _, k := range fns {
		ip := k[:strings.LastIndexByte(k, ':')]
		fnEx = append(fnEx, fmt.Sprintf("%s (%s, host found=%v)", k, alive[ip].Archetype, pset[ip]))
	}
	rs.FNPortEx = limit(fnEx, 12)
	for ip, h := range alive {
		for _, s := range h.Services {
			if ports[s.Port] {
				rs.ByArch[h.Archetype][1].add(pports[ip+":"+strconv.Itoa(s.Port)])
			}
		}
	}
	var svcEx, verEx []string
	for k, ts := range tsvc {
		ps, ok := psvc[k]
		if !ok {
			continue
		}
		okName := svcClass(ps.ServiceName) == svcClass(ts.Service)
		rs.SvcName.add(okName)
		if !okName {
			svcEx = append(svcEx, fmt.Sprintf("%s want %s got %q", k, ts.Service, ps.ServiceName))
		}
		if ts.Product != "" {
			rs.Product.add(ps.Product != "" && (strings.Contains(strings.ToLower(ps.Product), strings.ToLower(strings.Fields(ts.Product)[0]))))
		}
		if ts.Version != "" {
			okV := ps.Version != "" && (strings.HasPrefix(ps.Version, ts.Version) || strings.HasPrefix(ts.Version, strings.Fields(ps.Version + " x")[0]))
			rs.Version.add(okV)
			if !okV {
				verEx = append(verEx, fmt.Sprintf("%s %s want %q got %q %q", k, ts.Product, ts.Version, ps.Product, ps.Version))
			}
		}
		if ts.HTTP == nil {
			continue
		}
		rs.HTTPFp.add(ps.HTTP != nil && ps.HTTP.StatusCode > 0)
		if ps.HTTP == nil {
			continue
		}
		th := ts.HTTP
		if th.Title != "" {
			rs.Title.add(normTitle(ps.HTTP.Title) == normTitle(th.Title))
		}
		if th.Server != "" {
			rs.ServerHdr.add(ps.HTTP.ServerHeader == th.Server)
		}
		ti, pi2 := map[string]bool{}, map[string]bool{}
		for _, x := range th.InterestingHeaders {
			ti[k+"|"+x] = true
		}
		for _, x := range ps.HTTP.InterestingHeaders {
			name := strings.ToLower(strings.TrimSpace(strings.SplitN(x, ":", 2)[0]))
			if name != "server" && name != "" {
				pi2[k+"|"+name] = true
			}
		}
		m, _, _ := cmpSets(ti, pi2)
		rs.IntHeaders.add(m)
		tc, pc := map[string]bool{}, map[string]bool{}
		for _, x := range th.InsecureCookies {
			tc[k+"|"+x] = true
		}
		for _, c := range ps.HTTP.Cookies {
			if !c.HttpOnly || !c.Secure || len(c.Flags) > 0 {
				pc[k+"|"+c.Name] = true
			}
		}
		m, _, _ = cmpSets(tc, pc)
		rs.InsecCookie.add(m)
		tm, pm := map[string]bool{}, map[string]bool{}
		for _, x := range th.MissingSecHeaders {
			tm[k+"|"+strings.ToLower(x)] = true
		}
		for _, x := range ps.HTTP.MissingSecHeaders {
			pm[k+"|"+strings.ToLower(x)] = true
		}
		m, _, _ = cmpSets(tm, pm)
		rs.MissingSec.add(m)
		if ts.TLS {
			var tl *exTLS = ps.HTTP.TLS
			ss, exp := tl != nil && tl.IsSelfSigned, tl != nil && tl.IsExpired
			rs.SelfSigned.add(prf{TP: b2i(ss && th.CertKind == "self_signed"), FP: b2i(ss && th.CertKind != "self_signed"), FN: b2i(!ss && th.CertKind == "self_signed")})
			rs.Expired.add(prf{TP: b2i(exp && th.CertKind == "expired"), FP: b2i(exp && th.CertKind != "expired"), FN: b2i(!exp && th.CertKind == "expired")})
		}
	}
	sort.Strings(svcEx)
	sort.Strings(verEx)
	rs.SvcNameEx = limit(svcEx, 12)
	rs.VersionEx = limit(verEx, 12)

	// Technologies & flags (host level).
	var techFP, techFN []string
	allIPs := map[string]bool{}
	for ip := range alive {
		allIPs[ip] = true
	}
	for ip := range pset {
		allIPs[ip] = true
	}
	for ip := range allIPs {
		var tt map[string]bool
		th := alive[ip]
		if th != nil {
			tt = hostTruthTechs(th)
		} else {
			tt = map[string]bool{}
		}
		pt := map[string]bool{}
		ph, found := pi.hosts[ip]
		if found && pset[ip] {
			pt = hostPredTechs(ph)
		}
		for t := range tt {
			if rs.TechPer[t] == nil {
				rs.TechPer[t] = &prf{}
			}
			if pt[t] {
				rs.TechPer[t].TP++
			} else {
				rs.TechPer[t].FN++
				arch := ""
				if th != nil {
					arch = th.Archetype
				}
				techFN = append(techFN, fmt.Sprintf("%s %s (%s)", ip, t, arch))
			}
		}
		for t := range pt {
			if !tt[t] {
				if rs.TechPer[t] == nil {
					rs.TechPer[t] = &prf{}
				}
				rs.TechPer[t].FP++
				arch := "not-in-truth"
				if th != nil {
					arch = th.Archetype
				}
				techFP = append(techFP, fmt.Sprintf("%s %s (%s)", ip, t, arch))
			}
		}
		var tf, pf [3]bool
		if th != nil {
			for _, s := range th.Services {
				tf[0] = tf[0] || s.Flags.AdminPanel
				tf[1] = tf[1] || s.Flags.Staging
				tf[2] = tf[2] || s.Flags.IoT
			}
		}
		if found && pset[ip] {
			for _, s := range openSvcs(ph) {
				pf[0] = pf[0] || s.IsAdminPanel
				pf[1] = pf[1] || s.IsStagingEnv
				pf[2] = pf[2] || s.IsIoT
			}
			if strings.EqualFold(ph.Environment, "staging") || strings.EqualFold(ph.Environment, "test") || strings.EqualFold(ph.Environment, "dev") {
				pf[1] = true
			}
		}
		for i, m := range []*prf{&rs.Admin, &rs.Staging, &rs.IoT} {
			m.TP += b2i(tf[i] && pf[i])
			m.FP += b2i(!tf[i] && pf[i])
			m.FN += b2i(tf[i] && !pf[i])
		}
	}
	for _, m := range rs.TechPer {
		rs.Tech.add(*m)
	}
	sort.Strings(techFP)
	sort.Strings(techFN)
	rs.TechFPEx = limit(techFP, 12)
	rs.TechFNEx = limit(techFN, 12)
	sort.Strings(rs.UnstableRows)
	return rs
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------- diff scoring

type diffSets struct{ newHosts, goneHosts, newPorts, closedPorts, changed map[string]bool }

func svcSig(product, version, title string, techs []string) string {
	t := append([]string(nil), techs...)
	sort.Strings(t)
	return strings.ToLower(product + "|" + version + "|" + normTitle(title) + "|" + strings.Join(t, ","))
}

func truthDiff(a, b *truth.Document, ports map[int]bool, excl map[string]bool) diffSets {
	d := diffSets{map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}}
	ha, hb := map[string]*truth.Host{}, map[string]*truth.Host{}
	for i := range a.Hosts {
		ha[a.Hosts[i].IP] = &a.Hosts[i]
	}
	for i := range b.Hosts {
		hb[b.Hosts[i].IP] = &b.Hosts[i]
	}
	svcMap := func(h *truth.Host) map[int]truth.Service {
		m := map[int]truth.Service{}
		for _, s := range h.Services {
			if ports[s.Port] {
				m[s.Port] = s
			}
		}
		return m
	}
	for ip := range union(keys(ha), keys(hb)) {
		if excl[ip] {
			continue
		}
		x, y := ha[ip], hb[ip]
		ax, ay := x != nil && x.Alive, y != nil && y.Alive
		switch {
		case ay && !ax:
			d.newHosts[ip] = true
		case ax && !ay:
			d.goneHosts[ip] = true
		case ax && ay:
			sx, sy := svcMap(x), svcMap(y)
			for p, s := range sy {
				k := ip + ":" + strconv.Itoa(p)
				o, ok := sx[p]
				if !ok {
					d.newPorts[k] = true
					continue
				}
				ta, tb := "", ""
				if o.HTTP != nil {
					ta = o.HTTP.Title
				}
				if s.HTTP != nil {
					tb = s.HTTP.Title
				}
				if svcSig(o.Product, o.Version, ta, o.Technologies) != svcSig(s.Product, s.Version, tb, s.Technologies) {
					d.changed[k] = true
				}
			}
			for p := range sx {
				if _, ok := sy[p]; !ok {
					d.closedPorts[ip+":"+strconv.Itoa(p)] = true
				}
			}
		}
	}
	return d
}

func predDiff(a, b *export, pfx netip.Prefix, excl map[string]bool) diffSets {
	d := diffSets{map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}}
	ia, ib := indexExport(a, pfx), indexExport(b, pfx)
	for ip := range union(keysH(ia.hosts), keysH(ib.hosts)) {
		if excl[ip] {
			continue
		}
		x, okx := ia.hosts[ip]
		y, oky := ib.hosts[ip]
		ax, ay := okx && alivePred(x), oky && alivePred(y)
		switch {
		case ay && !ax:
			d.newHosts[ip] = true
		case ax && !ay:
			d.goneHosts[ip] = true
		case ax && ay:
			sx, sy := map[int]exService{}, map[int]exService{}
			for _, s := range openSvcs(x) {
				sx[s.Port] = s
			}
			for _, s := range openSvcs(y) {
				sy[s.Port] = s
			}
			sig := func(s exService) string {
				var ts []string
				for _, t := range s.Technologies {
					if n, ok := normTech(t); ok {
						ts = append(ts, n)
					}
				}
				title := ""
				if s.HTTP != nil {
					title = s.HTTP.Title
				}
				return svcSig(s.Product, s.Version, title, ts)
			}
			for p, s := range sy {
				k := ip + ":" + strconv.Itoa(p)
				o, ok := sx[p]
				if !ok {
					d.newPorts[k] = true
				} else if sig(o) != sig(s) {
					d.changed[k] = true
				}
			}
			for p := range sx {
				if _, ok := sy[p]; !ok {
					d.closedPorts[ip+":"+strconv.Itoa(p)] = true
				}
			}
		}
	}
	return d
}

type appDiff struct {
	NewHosts []struct {
		IP string `json:"ip"`
	} `json:"new_hosts"`
	MissingHosts []struct {
		IP string `json:"ip"`
	} `json:"missing_hosts"`
	NewServices []struct {
		HostIP string `json:"host_ip"`
		Port   int    `json:"port"`
	} `json:"new_services"`
	ClosedServices []struct {
		HostIP string `json:"host_ip"`
		Port   int    `json:"port"`
	} `json:"closed_services"`
	ChangedServices []struct {
		HostIP string `json:"host_ip"`
		Port   int    `json:"port"`
	} `json:"changed_services"`
}

func appDiffSets(ad *appDiff, pfx netip.Prefix, excl, newHostIPs map[string]bool) diffSets {
	d := diffSets{map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}}
	in := func(ip string) bool {
		a, err := netip.ParseAddr(ip)
		return err == nil && pfx.Contains(a) && !excl[ip]
	}
	for _, h := range ad.NewHosts {
		if in(h.IP) {
			d.newHosts[h.IP] = true
		}
	}
	for _, h := range ad.MissingHosts {
		if in(h.IP) {
			d.goneHosts[h.IP] = true
		}
	}
	for _, s := range ad.NewServices {
		// new_services also lists every service of a new host; keep only ports on existing hosts.
		if in(s.HostIP) && !d.newHosts[s.HostIP] {
			d.newPorts[s.HostIP+":"+strconv.Itoa(s.Port)] = true
		}
	}
	for _, s := range ad.ClosedServices {
		if in(s.HostIP) {
			d.closedPorts[s.HostIP+":"+strconv.Itoa(s.Port)] = true
		}
	}
	for _, s := range ad.ChangedServices {
		if in(s.HostIP) {
			d.changed[s.HostIP+":"+strconv.Itoa(s.Port)] = true
		}
	}
	return d
}

func keys(m map[string]*truth.Host) map[string]bool {
	o := map[string]bool{}
	for k := range m {
		o[k] = true
	}
	return o
}
func keysH(m map[string]exHost) map[string]bool {
	o := map[string]bool{}
	for k := range m {
		o[k] = true
	}
	return o
}
func union(a, b map[string]bool) map[string]bool {
	o := map[string]bool{}
	for k := range a {
		o[k] = true
	}
	for k := range b {
		o[k] = true
	}
	return o
}

// ---------------------------------------------------------------- report

func row(w io.Writer, name string, m prf) {
	fmt.Fprintf(w, "| %s | %d | %d | %d | %s | %s | **%s** |\n", name, m.TP, m.FP, m.FN, pct(m.P()), pct(m.R()), pct(m.F1()))
}

const prfHead = "| Metric | TP | FP | FN | Precision | Recall | F1 |\n|---|---:|---:|---:|---:|---:|---:|\n"

func writeRun(w io.Writer, rs *runScore) {
	fmt.Fprintf(w, "## %s\n\n", rs.Label)
	fmt.Fprintf(w, "Truth: **%d** stable live hosts (+%d unstable, scored separately). Export: %d hosts in lab CIDR, %d predicted alive (%d with ≥1 open port).\n\n",
		rs.TruthAlive, rs.Unstable, rs.PredInCIDR, rs.PredAlive, rs.PredWithSvc)
	fmt.Fprint(w, prfHead)
	row(w, "Live hosts (export lifecycle ≠ MISSING/INACTIVE)", rs.Hosts)
	row(w, "Live hosts (≥1 open port in export)", rs.HostsSvcBased)
	row(w, "Open ports (ip:port)", rs.Ports)
	row(w, "Web technologies / CMS (host level)", rs.Tech)
	row(w, "Admin-panel flag (host level)", rs.Admin)
	row(w, "Staging/test flag (host level)", rs.Staging)
	row(w, "IoT flag (host level)", rs.IoT)
	row(w, "Interesting headers (per HTTP service, excl. Server)", rs.IntHeaders)
	row(w, "Insecure cookies (no Secure or no HttpOnly)", rs.InsecCookie)
	row(w, "Missing security headers (HSTS/CSP/XFO/XCTO)", rs.MissingSec)
	row(w, "Self-signed TLS cert", rs.SelfSigned)
	row(w, "Expired TLS cert", rs.Expired)
	fmt.Fprintf(w, "\n| Identification on correctly found ports | Accuracy |\n|---|---:|\n")
	fmt.Fprintf(w, "| Service name (equivalence classes, e.g. http≡https≡http-alt) | %s |\n", rs.SvcName)
	fmt.Fprintf(w, "| Product (where the wire discloses one) | %s |\n", rs.Product)
	fmt.Fprintf(w, "| Version (where the wire discloses one) | %s |\n", rs.Version)
	fmt.Fprintf(w, "| HTTP services with an HTTP fingerprint | %s |\n", rs.HTTPFp)
	fmt.Fprintf(w, "| HTTP title exact match | %s |\n", rs.Title)
	fmt.Fprintf(w, "| HTTP Server header exact match | %s |\n\n", rs.ServerHdr)

	fmt.Fprintf(w, "**Host recall by network behaviour**\n\n| Class | Recall |\n|---|---:|\n")
	for _, c := range []string{"normal", "icmp_blocked", "firewalled", "icmp_blocked+firewalled"} {
		if a := rs.ByClass[c]; a != nil {
			fmt.Fprintf(w, "| %s | %s |\n", c, a)
		}
	}
	fmt.Fprintf(w, "\n<details><summary>Per-archetype recall</summary>\n\n| Archetype | Host recall | Port recall |\n|---|---:|---:|\n")
	var archs []string
	for a := range rs.ByArch {
		archs = append(archs, a)
	}
	sort.Strings(archs)
	for _, a := range archs {
		fmt.Fprintf(w, "| %s | %s | %s |\n", a, rs.ByArch[a][0], rs.ByArch[a][1])
	}
	fmt.Fprintf(w, "\n</details>\n\n<details><summary>Per-technology breakdown</summary>\n\n"+prfHead)
	var techs []string
	for t := range rs.TechPer {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	for _, t := range techs {
		row(w, t, *rs.TechPer[t])
	}
	fmt.Fprintf(w, "\n</details>\n\n")
	ex := func(title string, xs []string) {
		if len(xs) == 0 {
			return
		}
		fmt.Fprintf(w, "<details><summary>%s</summary>\n\n", title)
		for _, x := range xs {
			fmt.Fprintf(w, "- `%s`\n", x)
		}
		fmt.Fprintf(w, "\n</details>\n\n")
	}
	ex("Missed live hosts (examples)", rs.MissedHostEx)
	ex("False-positive hosts (examples)", rs.FPHostEx)
	ex("Missed open ports (examples)", rs.FNPortEx)
	ex("False-positive open ports (examples)", rs.FPPortEx)
	ex("Service-name mismatches (examples)", rs.SvcNameEx)
	ex("Version mismatches (examples)", rs.VersionEx)
	ex("Technology false positives (examples)", rs.TechFPEx)
	ex("Technology misses (examples)", rs.TechFNEx)
	if len(rs.UnstableRows) > 0 {
		fmt.Fprintf(w, "<details><summary>Unstable hosts (flapping / toggled during the scan) — not scored above</summary>\n\n| IP | Archetype | Kind | Up at truth dump | Predicted alive | App lifecycle |\n|---|---|---|---|---|---|\n")
		for _, r := range rs.UnstableRows {
			fmt.Fprintln(w, r)
		}
		fmt.Fprintf(w, "\n</details>\n\n")
	}
}

func diffRows(w io.Writer, label string, want, got diffSets) map[string]prf {
	out := map[string]prf{}
	fmt.Fprintf(w, "**%s**\n\n"+prfHead, label)
	for _, c := range []struct {
		n    string
		a, b map[string]bool
	}{{"New hosts", want.newHosts, got.newHosts}, {"Disappeared hosts", want.goneHosts, got.goneHosts},
		{"New ports on existing hosts", want.newPorts, got.newPorts}, {"Closed ports", want.closedPorts, got.closedPorts},
		{"Changed services (product/version/title/tech)", want.changed, got.changed}} {
		m, _, _ := cmpSets(c.a, c.b)
		row(w, c.n, m)
		out[c.n] = m
	}
	fmt.Fprintln(w)
	return out
}

func main() {
	var (
		t1      = flag.String("truth1", "", "truth for run 1 (required)")
		e1      = flag.String("export1", "", "AegisASI JSON export for run 1 (required)")
		t2      = flag.String("truth2", "", "truth for run 2")
		e2      = flag.String("export2", "", "AegisASI JSON export for run 2")
		ad      = flag.String("app-diff", "", "GET /api/v1/scans/diff?from=run1&to=run2 response")
		portStr = flag.String("ports", "", "ports that were scanned (default: all lab ports)")
		meta    = flag.String("meta", "", "JSON object with run metadata (durations etc.) to include")
		out     = flag.String("out", "", "write markdown here (default stdout)")
		jsonOut = flag.String("json", "", "write machine-readable summary here")
	)
	flag.Parse()
	if *t1 == "" || *e1 == "" {
		flag.Usage()
		os.Exit(2)
	}
	var td1 truth.Document
	var ex1 export
	loadJSON(*t1, &td1)
	loadJSON(*e1, &ex1)
	ports := map[int]bool{}
	if *portStr != "" {
		for _, p := range strings.Split(*portStr, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				ports[n] = true
			}
		}
	} else {
		for _, p := range td1.Ports {
			ports[p] = true
		}
	}

	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = f
	}
	fmt.Fprintf(w, "# AegisASI scale-lab accuracy report\n\nLab: `%s`, seed %d, %d IPs in scope, ports scored: %d.\n\n", td1.CIDR, td1.Seed, 1<<(32-netip.MustParsePrefix(td1.CIDR).Bits()), len(ports))
	summary := map[string]any{}
	if *meta != "" {
		var m map[string]any
		loadJSON(*meta, &m)
		summary["meta"] = m
		fmt.Fprintf(w, "| Run metadata | Value |\n|---|---|\n")
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			fmt.Fprintf(w, "| %s | %v |\n", k, m[k])
		}
		fmt.Fprintln(w)
	}
	rs1 := scoreRun("Run 1 — scenario "+td1.Scenario, &td1, &ex1, ports)
	writeRun(w, rs1)
	summary["run1"] = summarize(rs1)

	if *t2 != "" && *e2 != "" {
		var td2 truth.Document
		var ex2 export
		loadJSON(*t2, &td2)
		loadJSON(*e2, &ex2)
		rs2 := scoreRun("Run 2 — scenario "+td2.Scenario, &td2, &ex2, ports)
		writeRun(w, rs2)
		summary["run2"] = summarize(rs2)

		excl := map[string]bool{}
		for _, d := range []*truth.Document{&td1, &td2} {
			for _, h := range d.Hosts {
				if h.Unstable() || h.TimeOfDay != nil {
					excl[h.IP] = true
				}
			}
		}
		want := truthDiff(&td1, &td2, ports, excl)
		fmt.Fprintf(w, "## Change detection (run 1 → run 2)\n\nExpected (from ground truth, excluding %d flapping/toggled/time-of-day hosts): %d new hosts, %d disappeared, %d new ports, %d closed ports, %d changed services.\n\n",
			len(excl), len(want.newHosts), len(want.goneHosts), len(want.newPorts), len(want.closedPorts), len(want.changed))
		pfx := netip.MustParsePrefix(td1.CIDR)
		summary["diff_exports"] = diffRows(w, "Diff derived from the two exports (scanner observation quality)", want, predDiff(&ex1, &ex2, pfx, excl))
		if *ad != "" {
			var adoc appDiff
			loadJSON(*ad, &adoc)
			summary["diff_app"] = diffRows(w, "Diff reported by the app (`GET /api/v1/scans/diff`)", want, appDiffSets(&adoc, pfx, excl, nil))
		}
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(summary, "", " ")
		_ = os.WriteFile(*jsonOut, b, 0o644)
	}
}

func summarize(rs *runScore) map[string]any {
	f := func(m prf) map[string]any {
		return map[string]any{"tp": m.TP, "fp": m.FP, "fn": m.FN, "precision": m.P(), "recall": m.R(), "f1": m.F1()}
	}
	return map[string]any{
		"truth_alive": rs.TruthAlive, "pred_alive": rs.PredAlive, "hosts": f(rs.Hosts), "hosts_with_ports": f(rs.HostsSvcBased),
		"ports": f(rs.Ports), "tech": f(rs.Tech), "admin": f(rs.Admin), "staging": f(rs.Staging), "iot": f(rs.IoT),
		"service_name_acc": rs.SvcName.String(), "product_acc": rs.Product.String(), "version_acc": rs.Version.String(),
		"title_acc": rs.Title.String(), "interesting_headers": f(rs.IntHeaders), "insecure_cookies": f(rs.InsecCookie),
	}
}
