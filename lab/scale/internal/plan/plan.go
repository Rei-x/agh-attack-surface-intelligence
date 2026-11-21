// Package plan deterministically generates the scale-lab population
// (which IPs are alive, what each one runs) and the scenario variants
// used to test change detection.
package plan

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sort"
	"strings"
)

// Svc is one listening TCP service on a host.
type Svc struct {
	Port int `json:"port"`
	// Kind selects the wire protocol emulator:
	// http, https, ssh, ftp, smtp, pop3, imap, mysql, postgres, redis,
	// rdp, rtsp, telnet, silent (accepts, never speaks).
	Kind string `json:"kind"`
	// App selects the HTTP application personality for http/https.
	App string `json:"app,omitempty"`
	// Banner product variant for server-first protocols (openssh, rosssh, vsftpd,
	// proftpd, mikrotik-ftp, postfix, exim, dovecot, mysql, mariadb ...).
	Product string `json:"product,omitempty"`
	// Ver is the product version string (format depends on Product/App).
	Ver string `json:"ver,omitempty"`
	// Server is the HTTP Server header to emit for apps fronted by a generic web server.
	Server string `json:"server,omitempty"`
	// Cert kind for TLS services: valid|self_signed|expired.
	Cert string `json:"cert,omitempty"`
	// Site is a human-facing site name used in titles.
	Site string `json:"site,omitempty"`
	// Staging marks a pre-production deployment.
	Staging bool `json:"staging,omitempty"`
	// Auth for redis: "none" (open) or "noauth" (requirepass).
	Auth string `json:"auth,omitempty"`
	// Model for devices (printers, cameras, NAS).
	Model string `json:"model,omitempty"`
}

// Host is one lab host.
type Host struct {
	IP          netip.Addr `json:"ip"`
	Hostname    string     `json:"hostname"`
	Archetype   string     `json:"archetype"`
	ICMPBlocked bool       `json:"icmp_blocked,omitempty"`
	Firewalled  bool       `json:"firewalled,omitempty"`
	FlapPeriod  int        `json:"flap_period,omitempty"` // seconds; 0 = stable
	FlapPhase   int        `json:"flap_phase,omitempty"`
	TOD         bool       `json:"tod,omitempty"`
	Svcs        []Svc      `json:"svcs"`
}

// Clone deep-copies a host.
func (h *Host) Clone() *Host {
	c := *h
	c.Svcs = append([]Svc(nil), h.Svcs...)
	return &c
}

// Svc returns the service on port p or nil.
func (h *Host) Svc(p int) *Svc {
	for i := range h.Svcs {
		if h.Svcs[i].Port == p {
			return &h.Svcs[i]
		}
	}
	return nil
}

// Scenario is the set of hosts that exist (may be up) in one scenario.
type Scenario struct {
	Name  string
	Hosts map[netip.Addr]*Host
}

// Plan is the full deterministic lab population.
type Plan struct {
	CIDR      netip.Prefix
	Seed      uint64
	Scenarios map[string]*Scenario
	// All is the sorted union of every IP across scenarios.
	All []netip.Addr
}

// Config controls generation.
type Config struct {
	CIDR       netip.Prefix
	Hosts      int
	Seed       uint64
	FlapHosts  int
	FlapPeriod int // base seconds
	TODHosts   int
}

type archetype struct {
	name   string
	weight int
	build  func(r *rand.Rand, h *Host)
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

var (
	sshUbuntu = []string{"8.9p1 Ubuntu-3ubuntu0.6", "8.9p1 Ubuntu-3ubuntu0.10", "9.6p1 Ubuntu-3ubuntu13.5", "8.2p1 Ubuntu-4ubuntu0.11", "7.6p1 Ubuntu-4ubuntu0.7"}
	sshDebian = []string{"8.4p1 Debian-5+deb11u3", "9.2p1 Debian-2+deb12u3", "7.9p1 Debian-10+deb10u4"}
	sshRHEL   = []string{"7.4", "8.0", "8.7"}
	nginxSrv  = []string{"nginx/1.18.0 (Ubuntu)", "nginx/1.24.0 (Ubuntu)", "nginx/1.22.1", "nginx/1.20.1", "nginx"}
	apacheSrv = []string{"Apache/2.4.41 (Ubuntu)", "Apache/2.4.52 (Ubuntu)", "Apache/2.4.57 (Debian)", "Apache/2.4.62 (Debian)", "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.33", "Apache"}
	units     = []string{"wi", "weaiib", "wimiip", "wggios", "wfiis", "wms", "wh", "wz", "cbi", "dziekanat", "rekrutacja", "biblioteka", "ckm", "uci", "skn", "ds", "lab", "kn"}
)

func sshSvc(r *rand.Rand) Svc {
	switch r.IntN(10) {
	case 0, 1:
		return Svc{Port: 22, Kind: "ssh", Product: "openssh", Ver: pick(r, sshDebian)}
	case 2:
		return Svc{Port: 22, Kind: "ssh", Product: "openssh", Ver: pick(r, sshRHEL)}
	default:
		return Svc{Port: 22, Kind: "ssh", Product: "openssh", Ver: pick(r, sshUbuntu)}
	}
}

func certKind(r *rand.Rand) string {
	switch n := r.IntN(10); {
	case n < 5:
		return "valid"
	case n < 8:
		return "self_signed"
	default:
		return "expired"
	}
}

func web(r *rand.Rand, port int, app, server string) Svc {
	s := Svc{Port: port, Kind: "http", App: app, Server: server}
	if port == 443 || port == 8443 || port == 5001 || port == 9443 {
		s.Kind = "https"
		s.Cert = certKind(r)
	}
	return s
}

func windowsBase() []Svc {
	return []Svc{
		{Port: 135, Kind: "silent"},
		{Port: 139, Kind: "silent"},
		{Port: 445, Kind: "silent"},
		{Port: 3389, Kind: "rdp"},
	}
}

var archetypes = []archetype{
	{"linux-ssh", 140, func(r *rand.Rand, h *Host) { h.Svcs = []Svc{sshSvc(r)} }},
	{"nginx-site", 80, func(r *rand.Rand, h *Host) {
		srv := pick(r, nginxSrv)
		h.Svcs = []Svc{sshSvc(r), web(r, 80, "redirect-https", srv), web(r, 443, "nginx-default", srv)}
		if r.IntN(3) == 0 {
			h.Svcs[1].App = "nginx-default"
			h.Svcs = h.Svcs[:2]
		}
	}},
	{"apache-site", 60, func(r *rand.Rand, h *Host) {
		srv := pick(r, apacheSrv)
		h.Svcs = []Svc{sshSvc(r), web(r, 80, "apache-default", srv)}
		if r.IntN(2) == 0 {
			h.Svcs = append(h.Svcs, web(r, 443, "apache-default", srv))
		}
	}},
	{"wordpress", 60, func(r *rand.Rand, h *Host) {
		srv := pick(r, apacheSrv[:4])
		ver := pick(r, []string{"6.4.3", "6.5.2", "6.2.2", "5.8.3", "6.6.1"})
		site := "Wydział " + strings.ToUpper(h.Hostname[:2])
		a := web(r, 80, "wordpress", srv)
		a.Ver, a.Site = ver, site
		b := web(r, 443, "wordpress", srv)
		b.Ver, b.Site = ver, site
		h.Svcs = []Svc{sshSvc(r), a, b}
	}},
	{"joomla", 20, func(r *rand.Rand, h *Host) {
		a := web(r, 80, "joomla", pick(r, apacheSrv[:4]))
		a.Ver, a.Site = pick(r, []string{"4.4.2", "3.10.12", "5.0.3"}), "Koło Naukowe "+strings.ToUpper(h.Hostname[:3])
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"drupal", 20, func(r *rand.Rand, h *Host) {
		srv := pick(r, append(nginxSrv[:3:3], apacheSrv[1]))
		a := web(r, 80, "drupal", srv)
		a.Ver, a.Site = pick(r, []string{"10", "9", "7"}), "Instytut "+strings.ToUpper(h.Hostname[:3])
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"moodle", 10, func(r *rand.Rand, h *Host) {
		a := web(r, 443, "moodle", pick(r, apacheSrv[:3]))
		a.Ver = pick(r, []string{"4.1.9", "4.3.3", "3.11.18"})
		h.Svcs = []Svc{sshSvc(r), web(r, 80, "redirect-https", a.Server), a}
	}},
	{"jenkins", 15, func(r *rand.Rand, h *Host) {
		a := web(r, 8080, "jenkins", "")
		a.Ver = pick(r, []string{"2.426.1", "2.440.3", "2.375.4", "2.462.2"})
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"grafana", 15, func(r *rand.Rand, h *Host) {
		a := web(r, 3000, "grafana", "")
		a.Ver = pick(r, []string{"10.2.3", "9.5.15", "11.1.0", "8.5.27"})
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"phpmyadmin", 15, func(r *rand.Rand, h *Host) {
		a := web(r, 80, "phpmyadmin", pick(r, apacheSrv[:4]))
		a.Ver = pick(r, []string{"5.2.1", "5.1.3", "4.9.7"})
		h.Svcs = []Svc{sshSvc(r), a, {Port: 3306, Kind: "mysql", Product: "mysql", Ver: pick(r, []string{"8.0.35-0ubuntu0.22.04.1", "5.7.42"})}}
	}},
	{"tomcat", 20, func(r *rand.Rand, h *Host) {
		a := web(r, 8080, "tomcat", "")
		a.Ver = pick(r, []string{"9.0.83", "8.5.96", "10.1.16", "7.0.109"})
		h.Svcs = []Svc{sshSvc(r), a}
		if r.IntN(3) == 0 {
			b := web(r, 8443, "tomcat", "")
			b.Ver = a.Ver
			h.Svcs = append(h.Svcs, b)
		}
	}},
	{"iis-default", 30, func(r *rand.Rand, h *Host) {
		a := web(r, 80, "iis-default", pick(r, []string{"Microsoft-IIS/10.0", "Microsoft-IIS/8.5"}))
		h.Svcs = append(windowsBase(), a)
	}},
	{"iis-aspnet", 20, func(r *rand.Rand, h *Host) {
		srv := pick(r, []string{"Microsoft-IIS/10.0", "Microsoft-IIS/8.5"})
		a := web(r, 80, "iis-aspnet", srv)
		a.Site = pick(r, []string{"Dziekanat", "Rezerwacja Sal", "Ankiety", "Delegacje"})
		b := web(r, 443, "iis-aspnet", srv)
		b.Site = a.Site
		h.Svcs = append(windowsBase(), a, b)
	}},
	{"windows-ws", 80, func(r *rand.Rand, h *Host) { h.Svcs = windowsBase() }},
	{"synology", 15, func(r *rand.Rand, h *Host) {
		a := web(r, 5000, "synology", "nginx")
		a.Model, a.Ver = pick(r, []string{"DS920+", "DS1621+", "RS1221+", "DS218"}), pick(r, []string{"7.2", "7.1", "6.2"})
		b := web(r, 5001, "synology", "nginx")
		b.Model, b.Ver = a.Model, a.Ver
		h.Svcs = []Svc{a, b}
		if r.IntN(2) == 0 {
			h.Svcs = append(h.Svcs, Svc{Port: 22, Kind: "ssh", Product: "openssh", Ver: "8.2"})
		}
	}},
	{"mikrotik", 20, func(r *rand.Rand, h *Host) {
		ver := pick(r, []string{"6.49.10", "6.48.6", "7.12.1", "7.14.3"})
		a := web(r, 80, "mikrotik", "")
		a.Ver = ver
		h.Svcs = []Svc{
			{Port: 21, Kind: "ftp", Product: "mikrotik-ftp", Ver: ver},
			{Port: 22, Kind: "ssh", Product: "rosssh"},
			{Port: 23, Kind: "telnet"},
			a,
			{Port: 8291, Kind: "silent"},
		}
	}},
	{"hp-printer", 30, func(r *rand.Rand, h *Host) {
		model := pick(r, []string{"HP Color LaserJet MFP M479fdw", "HP LaserJet Pro M404dn", "HP LaserJet MFP M528", "HP OfficeJet Pro 9020 series"})
		a := web(r, 80, "hp-printer", "")
		a.Model = model
		b := web(r, 443, "hp-printer", "")
		b.Model, b.Cert = model, "self_signed"
		h.Svcs = []Svc{a, b, {Port: 631, Kind: "silent"}, {Port: 9100, Kind: "silent"}}
	}},
	{"brother-printer", 20, func(r *rand.Rand, h *Host) {
		a := web(r, 80, "brother-printer", "")
		a.Model = pick(r, []string{"MFC-L2710DW", "HL-L2350DW", "DCP-L2550DN", "MFC-L8900CDW"})
		h.Svcs = []Svc{a, {Port: 9100, Kind: "silent"}}
	}},
	{"hikvision", 30, func(r *rand.Rand, h *Host) {
		a := web(r, 80, "hikvision", "")
		a.Model = pick(r, []string{"DS-2CD2143G2-I", "DS-2CD2043G0-I", "DS-7608NI-K2"})
		h.Svcs = []Svc{a, {Port: 554, Kind: "rtsp", Model: a.Model}, {Port: 8000, Kind: "silent"}}
	}},
	{"gitlab", 10, func(r *rand.Rand, h *Host) {
		a := web(r, 443, "gitlab", "nginx")
		a.Ver = pick(r, []string{"16.7.2", "15.11.13", "17.2.1"})
		h.Svcs = []Svc{sshSvc(r), web(r, 80, "redirect-https", "nginx"), a}
	}},
	{"keycloak", 10, func(r *rand.Rand, h *Host) {
		a := web(r, 8443, "keycloak", "")
		a.Ver = pick(r, []string{"21.1.2", "23.0.4", "19.0.3"})
		b := web(r, 8080, "keycloak", "")
		b.Ver = a.Ver
		h.Svcs = []Svc{sshSvc(r), b, a}
	}},
	{"elk", 10, func(r *rand.Rand, h *Host) {
		ver := pick(r, []string{"7.17.9", "8.11.3", "8.6.2"})
		a := web(r, 5601, "kibana", "")
		a.Ver = ver
		b := web(r, 9200, "elasticsearch", "")
		b.Ver = ver
		h.Svcs = []Svc{sshSvc(r), a, b}
	}},
	{"prometheus", 10, func(r *rand.Rand, h *Host) {
		a := web(r, 9090, "prometheus", "")
		a.Ver = pick(r, []string{"2.45.0", "2.48.1", "2.37.9"})
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"zabbix", 10, func(r *rand.Rand, h *Host) {
		a := web(r, 80, "zabbix", pick(r, apacheSrv[:4]))
		a.Ver = pick(r, []string{"6.0", "6.4", "5.0"})
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"mail-postfix", 20, func(r *rand.Rand, h *Host) {
		a := web(r, 443, "roundcube", "nginx/1.18.0 (Ubuntu)")
		a.Ver = pick(r, []string{"1.6.5", "1.5.6", "1.4.15"})
		h.Svcs = []Svc{sshSvc(r),
			{Port: 25, Kind: "smtp", Product: "postfix"},
			{Port: 110, Kind: "pop3", Product: "dovecot"},
			{Port: 143, Kind: "imap", Product: "dovecot"},
			web(r, 80, "redirect-https", "nginx/1.18.0 (Ubuntu)"), a}
	}},
	{"mail-exim", 10, func(r *rand.Rand, h *Host) {
		h.Svcs = []Svc{sshSvc(r), {Port: 25, Kind: "smtp", Product: "exim", Ver: pick(r, []string{"4.96", "4.94.2", "4.97"})}}
	}},
	{"ftp", 20, func(r *rand.Rand, h *Host) {
		f := Svc{Port: 21, Kind: "ftp", Product: "vsftpd", Ver: pick(r, []string{"3.0.3", "3.0.5", "2.3.4"})}
		if r.IntN(2) == 0 {
			f = Svc{Port: 21, Kind: "ftp", Product: "proftpd", Ver: pick(r, []string{"1.3.6", "1.3.8", "1.3.5e"})}
		}
		h.Svcs = []Svc{f, sshSvc(r)}
	}},
	{"db-mysql", 30, func(r *rand.Rand, h *Host) {
		m := Svc{Port: 3306, Kind: "mysql", Product: "mysql", Ver: pick(r, []string{"8.0.35-0ubuntu0.22.04.1", "8.0.36", "5.7.44-log"})}
		if r.IntN(3) == 0 {
			m = Svc{Port: 3306, Kind: "mysql", Product: "mariadb", Ver: pick(r, []string{"10.6.16-MariaDB-0ubuntu0.22.04.1", "10.11.6-MariaDB-0+deb12u1", "10.3.39-MariaDB"})}
		}
		h.Svcs = []Svc{sshSvc(r), m}
	}},
	{"db-postgres", 20, func(r *rand.Rand, h *Host) {
		h.Svcs = []Svc{sshSvc(r), {Port: 5432, Kind: "postgres", Ver: pick(r, []string{"14", "15", "16", "12"})}}
	}},
	{"redis", 15, func(r *rand.Rand, h *Host) {
		h.Svcs = []Svc{sshSvc(r), {Port: 6379, Kind: "redis", Ver: pick(r, []string{"6.2.6", "7.0.15", "7.2.4", "5.0.7"}), Auth: pick(r, []string{"none", "noauth", "noauth"})}}
	}},
	{"staging-node", 20, func(r *rand.Rand, h *Host) {
		a := web(r, pick(r, []int{3000, 8080}), "express-staging", "")
		a.Site, a.Staging = pick(r, []string{"USOSweb", "Rekrutacja", "e-Indeks", "Portal Pracownika"}), true
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"spring-boot", 20, func(r *rand.Rand, h *Host) {
		a := web(r, 8080, "spring-boot", "")
		a.Site, a.Ver = pick(r, []string{"rekrutacja-api", "sale-api", "plan-zajec", "ankiety-svc"}), pick(r, []string{"1.4.2", "2.0.0-SNAPSHOT", "0.9.1"})
		a.Staging = strings.Contains(a.Ver, "SNAPSHOT")
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"django-dev", 10, func(r *rand.Rand, h *Host) {
		a := web(r, 8000, "django-dev", "WSGIServer/0.2 CPython/3.11.6")
		a.Staging = true
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"custom-admin", 20, func(r *rand.Rand, h *Host) {
		a := web(r, 80, "custom-admin", pick(r, nginxSrv))
		a.Ver, a.Site = pick(r, []string{"2.3.1", "1.8.0", "3.0.4"}), pick(r, []string{"System Sal", "Ewidencja Sprzętu", "Rejestr Licencji"})
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"test-env", 15, func(r *rand.Rand, h *Host) {
		a := web(r, 80, "test-apache", pick(r, apacheSrv))
		a.Site, a.Staging = pick(r, []string{"System Rejestracji", "Elektroniczny Dziennik", "Wirtualny Dziekanat"}), true
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"cups", 10, func(r *rand.Rand, h *Host) {
		a := web(r, 631, "cups", "")
		a.Ver = pick(r, []string{"2.4", "2.3", "2.2"})
		h.Svcs = []Svc{sshSvc(r), a}
	}},
	{"idrac", 10, func(r *rand.Rand, h *Host) {
		a := web(r, 443, "idrac", "")
		a.Cert = "self_signed"
		a.Ver = pick(r, []string{"9", "8"})
		h.Svcs = []Svc{web(r, 80, "redirect-https", ""), a, {Port: 22, Kind: "ssh", Product: "openssh", Ver: "7.4"}}
	}},
}

func hostnameFor(r *rand.Rand, arch string, ip netip.Addr) string {
	b := ip.As4()
	u := pick(r, units)
	switch arch {
	case "hp-printer", "brother-printer":
		return fmt.Sprintf("prn-%s-%d-%d", u, b[2], b[3])
	case "hikvision":
		return fmt.Sprintf("cam-%s-%03d", u, b[3])
	case "mikrotik":
		return fmt.Sprintf("rtr-%s-%d", u, b[2])
	case "synology":
		return fmt.Sprintf("nas-%s%02d", u, b[3]%50)
	case "windows-ws", "iis-default", "iis-aspnet":
		return fmt.Sprintf("%s-pc%03d", u, int(b[3]))
	case "staging-node", "test-env", "django-dev":
		return fmt.Sprintf("staging-%s", u)
	case "mail-postfix", "mail-exim":
		return fmt.Sprintf("mail-%s", u)
	}
	return fmt.Sprintf("%s-%s-%d", u, strings.Split(arch, "-")[0], b[3])
}

// Generate builds the plan: scenario A and its mutation B.
func Generate(cfg Config) (*Plan, error) {
	if !cfg.CIDR.Addr().Is4() {
		return nil, fmt.Errorf("only IPv4 CIDRs supported")
	}
	size := 1 << (32 - cfg.CIDR.Bits())
	extra := cfg.Hosts / 20 // pool of hosts that appear only in B
	if cfg.Hosts+extra > size/2 {
		return nil, fmt.Errorf("too many hosts (%d) for %s", cfg.Hosts, cfg.CIDR)
	}
	r := rand.New(rand.NewPCG(cfg.Seed, 0x5ca1e1ab))

	base := cfg.CIDR.Masked().Addr().As4()
	baseU := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	used := map[uint32]bool{}
	nextIP := func() netip.Addr {
		for {
			off := uint32(r.IntN(size))
			v := baseU + off
			if used[v] || v&0xff == 0 || v&0xff == 255 {
				continue
			}
			used[v] = true
			return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
	total := 0
	for _, a := range archetypes {
		total += a.weight
	}
	newHost := func() *Host {
		ip := nextIP()
		n := r.IntN(total)
		var a archetype
		for _, a = range archetypes {
			if n < a.weight {
				break
			}
			n -= a.weight
		}
		h := &Host{IP: ip, Archetype: a.name}
		h.Hostname = hostnameFor(r, a.name, ip)
		a.build(r, h)
		h.ICMPBlocked = r.IntN(100) < 12
		h.Firewalled = r.IntN(100) < 15
		if a.name == "windows-ws" || a.name == "iis-default" || a.name == "iis-aspnet" {
			// Windows Defender Firewall drops echo by default on public profile.
			h.ICMPBlocked = r.IntN(100) < 40
		}
		return h
	}

	A := &Scenario{Name: "A", Hosts: map[netip.Addr]*Host{}}
	order := make([]*Host, 0, cfg.Hosts)
	for i := 0; i < cfg.Hosts; i++ {
		h := newHost()
		A.Hosts[h.IP] = h
		order = append(order, h)
	}
	// Flapping and time-of-day hosts are chosen from simple stable archetypes.
	simple := func(h *Host) bool {
		switch h.Archetype {
		case "linux-ssh", "windows-ws", "nginx-site", "apache-site", "hp-printer":
			return h.FlapPeriod == 0 && !h.TOD
		}
		return false
	}
	pickSimple := func() *Host {
		for {
			h := order[r.IntN(len(order))]
			if simple(h) {
				return h
			}
		}
	}
	for i := 0; i < cfg.FlapHosts; i++ {
		h := pickSimple()
		h.FlapPeriod = cfg.FlapPeriod + r.IntN(cfg.FlapPeriod+1)
		h.FlapPhase = r.IntN(h.FlapPeriod)
	}
	for i := 0; i < cfg.TODHosts; i++ {
		pickSimple().TOD = true
	}

	B := &Scenario{Name: "B", Hosts: map[netip.Addr]*Host{}}
	for ip, h := range A.Hosts {
		B.Hosts[ip] = h.Clone()
	}
	mutate(r, cfg, order, B, newHost, extra)

	p := &Plan{CIDR: cfg.CIDR, Seed: cfg.Seed, Scenarios: map[string]*Scenario{"A": A, "B": B}}
	seen := map[netip.Addr]bool{}
	for _, s := range p.Scenarios {
		for ip := range s.Hosts {
			if !seen[ip] {
				seen[ip] = true
				p.All = append(p.All, ip)
			}
		}
	}
	sort.Slice(p.All, func(i, j int) bool { return p.All[i].Less(p.All[j]) })
	return p, nil
}

func stableCandidate(h *Host) bool { return h.FlapPeriod == 0 && !h.TOD }

// mutate turns scenario B into a realistic "a week later" state.
func mutate(r *rand.Rand, cfg Config, order []*Host, B *Scenario, newHost func() *Host, extra int) {
	n := len(order)
	pickStable := func(pred func(*Host) bool) *Host {
		for tries := 0; tries < 10000; tries++ {
			a := order[r.IntN(n)]
			h, ok := B.Hosts[a.IP]
			if ok && stableCandidate(h) && (pred == nil || pred(h)) && !touched[h.IP] {
				touched[h.IP] = true
				return h
			}
		}
		return nil
	}
	defer func() { touched = map[netip.Addr]bool{} }()

	// 1. New hosts.
	for i := 0; i < extra; i++ {
		h := newHost()
		h.FlapPeriod, h.TOD = 0, false
		B.Hosts[h.IP] = h
		touched[h.IP] = true
	}
	// 2. Disappeared hosts (~3%).
	for i := 0; i < n*3/100; i++ {
		if h := pickStable(nil); h != nil {
			delete(B.Hosts, h.IP)
		}
	}
	// 3. Newly opened ports (~3%).
	extraSvcs := []func() Svc{
		func() Svc { return Svc{Port: 3306, Kind: "mysql", Product: "mysql", Ver: "8.0.36"} },
		func() Svc { return Svc{Port: 6379, Kind: "redis", Ver: "7.2.4", Auth: "none"} },
		func() Svc {
			return Svc{Port: 8080, Kind: "http", App: "jenkins", Ver: "2.462.2"}
		},
		func() Svc { return Svc{Port: 21, Kind: "ftp", Product: "vsftpd", Ver: "3.0.5"} },
		func() Svc {
			return Svc{Port: 8000, Kind: "http", App: "django-dev", Server: "WSGIServer/0.2 CPython/3.12.1", Staging: true}
		},
		func() Svc {
			return Svc{Port: 9090, Kind: "http", App: "prometheus", Ver: "2.48.1"}
		},
	}
	for i := 0; i < n*3/100; i++ {
		s := extraSvcs[r.IntN(len(extraSvcs))]()
		h := pickStable(func(h *Host) bool { return h.Svc(s.Port) == nil && h.Svc(22) != nil })
		if h != nil {
			h.Svcs = append(h.Svcs, s)
		}
	}
	// 4. Closed ports (~3%): drop a non-primary port on multi-port hosts.
	for i := 0; i < n*3/100; i++ {
		h := pickStable(func(h *Host) bool { return len(h.Svcs) >= 2 })
		if h != nil {
			k := 1 + r.IntN(len(h.Svcs)-1)
			h.Svcs = append(h.Svcs[:k:k], h.Svcs[k+1:]...)
		}
	}
	// 5. Version upgrades (~4%).
	upgrades := map[string]string{
		"8.9p1 Ubuntu-3ubuntu0.6": "8.9p1 Ubuntu-3ubuntu0.10", "8.2p1 Ubuntu-4ubuntu0.11": "9.6p1 Ubuntu-3ubuntu13.5",
		"7.6p1 Ubuntu-4ubuntu0.7": "8.9p1 Ubuntu-3ubuntu0.10", "8.4p1 Debian-5+deb11u3": "9.2p1 Debian-2+deb12u3",
		"7.9p1 Debian-10+deb10u4": "9.2p1 Debian-2+deb12u3", "7.4": "8.0",
	}
	for i := 0; i < n*4/100; i++ {
		h := pickStable(func(h *Host) bool {
			for _, s := range h.Svcs {
				if (s.Kind == "ssh" && upgrades[s.Ver] != "") || s.App == "wordpress" || s.App == "jenkins" || s.App == "grafana" || s.App == "tomcat" || strings.HasPrefix(s.Server, "nginx/1.18") || strings.HasPrefix(s.Server, "Apache/2.4.41") {
					return true
				}
			}
			return false
		})
		if h == nil {
			continue
		}
		for j := range h.Svcs {
			s := &h.Svcs[j]
			switch {
			case s.Kind == "ssh" && upgrades[s.Ver] != "":
				s.Ver = upgrades[s.Ver]
			case s.App == "wordpress":
				s.Ver = "6.7.1"
			case s.App == "jenkins":
				s.Ver = "2.479.1"
			case s.App == "grafana":
				s.Ver = "11.3.0"
			case s.App == "tomcat":
				s.Ver = "9.0.97"
			}
			if strings.HasPrefix(s.Server, "nginx/1.18") {
				s.Server = "nginx/1.24.0 (Ubuntu)"
			}
			if strings.HasPrefix(s.Server, "Apache/2.4.41") {
				s.Server = "Apache/2.4.58 (Ubuntu)"
			}
		}
	}
	// 6. Technology / title changes (~1.5%): a default page becomes a real app.
	for i := 0; i < n*15/1000; i++ {
		h := pickStable(func(h *Host) bool {
			for _, s := range h.Svcs {
				if s.App == "nginx-default" || s.App == "apache-default" || s.App == "iis-default" {
					return true
				}
			}
			return false
		})
		if h == nil {
			continue
		}
		for j := range h.Svcs {
			s := &h.Svcs[j]
			switch s.App {
			case "nginx-default":
				s.App, s.Ver, s.Site = "custom-admin", "3.1.0", "Nowy Panel"
			case "apache-default":
				s.App, s.Ver, s.Site = "wordpress", "6.7.1", "Nowa Strona"
			case "iis-default":
				s.App, s.Site = "iis-aspnet", "Rezerwacja Sal"
			}
		}
	}
}

var touched = map[netip.Addr]bool{}

// Ports returns the sorted union of all ports used anywhere in the plan.
func (p *Plan) Ports() []int {
	set := map[int]bool{}
	for _, s := range p.Scenarios {
		for _, h := range s.Hosts {
			for _, sv := range h.Svcs {
				set[sv.Port] = true
			}
		}
	}
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
