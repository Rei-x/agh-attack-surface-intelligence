package emu

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/plan"
	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/truth"
)

// appMeta is the ground-truth classification of each HTTP personality.
// tech: canonical id of the application; ver: whether the app version is
// disclosed in what an unauthenticated GET / (plus redirects) returns.
type appMeta struct {
	tech     string
	admin    bool
	iot      bool
	verShown bool
}

var apps = map[string]appMeta{
	"redirect-https":  {},
	"nginx-default":   {},
	"apache-default":  {},
	"wordpress":       {tech: "wordpress", admin: true, verShown: true},
	"joomla":          {tech: "joomla", admin: true},
	"drupal":          {tech: "drupal", verShown: true},
	"moodle":          {tech: "moodle"},
	"jenkins":         {tech: "jenkins", admin: true, verShown: true},
	"grafana":         {tech: "grafana", admin: true, verShown: true},
	"phpmyadmin":      {tech: "phpmyadmin", admin: true, verShown: true},
	"tomcat":          {tech: "tomcat", admin: true, verShown: true},
	"iis-default":     {},
	"iis-aspnet":      {},
	"synology":        {tech: "synology-dsm", admin: true, iot: true},
	"mikrotik":        {tech: "mikrotik-routeros", admin: true, iot: true, verShown: true},
	"hp-printer":      {tech: "hp-printer", iot: true},
	"brother-printer": {tech: "brother-printer", iot: true},
	"hikvision":       {tech: "hikvision", iot: true},
	"gitlab":          {tech: "gitlab"},
	"keycloak":        {tech: "keycloak", admin: true},
	"kibana":          {tech: "kibana", admin: true, verShown: true},
	"elasticsearch":   {tech: "elasticsearch", verShown: true},
	"prometheus":      {tech: "prometheus"},
	"zabbix":          {tech: "zabbix", admin: true},
	"roundcube":       {tech: "roundcube"},
	"express-staging": {tech: "express"},
	"spring-boot":     {tech: "spring-boot"},
	"django-dev":      {tech: "django", admin: false},
	"custom-admin":    {admin: true},
	"test-apache":     {},
	"cups":            {tech: "cups", verShown: true},
	"idrac":           {tech: "idrac", admin: true, iot: true},
}

// disclosure headers: technology / version revealing response headers.
var disclosureHeaders = map[string]bool{
	"x-powered-by": true, "x-aspnet-version": true, "x-aspnetmvc-version": true, "x-generator": true,
	"x-drupal-cache": true, "x-drupal-dynamic-cache": true, "x-jenkins": true, "x-hudson": true,
	"x-jenkins-session": true, "x-gitlab-meta": true, "kbn-name": true, "kbn-license-sig": true,
	"x-elastic-product": true, "x-runtime": true, "www-authenticate": true, "x-instance-identity": true,
}

var secHeaders = []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"}

var (
	reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reGen   = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
)

// techsFromHeaders derives server-side technologies from observed headers.
func techsFromHeaders(h http.Header) []string {
	var out []string
	srv := h.Get("Server")
	pb := h.Values("X-Powered-By")
	switch {
	case strings.HasPrefix(srv, "nginx"):
		out = append(out, "nginx")
	case strings.HasPrefix(srv, "Apache"):
		out = append(out, "apache")
	case strings.HasPrefix(srv, "Microsoft-IIS"):
		out = append(out, "iis")
	case strings.HasPrefix(srv, "Jetty"):
		out = append(out, "jetty")
	}
	all := srv + " " + strings.Join(pb, " ")
	if strings.Contains(all, "PHP/") {
		out = append(out, "php")
	}
	if strings.Contains(all, "ASP.NET") || h.Get("X-AspNet-Version") != "" {
		out = append(out, "asp.net")
	}
	if strings.Contains(all, "Express") {
		out = append(out, "express")
	}
	return out
}

func svcName(s *plan.Svc) (name, product, version string) {
	switch s.Kind {
	case "ssh":
		if s.Product == "rosssh" {
			return "ssh", "MikroTik RouterOS sshd", ""
		}
		v := s.Ver
		if i := strings.IndexByte(v, ' '); i > 0 {
			v = v[:i]
		}
		return "ssh", "OpenSSH", v
	case "ftp":
		switch s.Product {
		case "proftpd":
			return "ftp", "ProFTPD", s.Ver
		case "mikrotik-ftp":
			return "ftp", "MikroTik router ftpd", s.Ver
		}
		return "ftp", "vsftpd", s.Ver
	case "smtp":
		if s.Product == "exim" {
			return "smtp", "Exim smtpd", s.Ver
		}
		return "smtp", "Postfix smtpd", ""
	case "pop3":
		return "pop3", "Dovecot pop3d", ""
	case "imap":
		return "imap", "Dovecot imapd", ""
	case "mysql":
		v := s.Ver
		if i := strings.IndexAny(v, "-"); i > 0 {
			v = v[:i]
		}
		if s.Product == "mariadb" {
			return "mysql", "MariaDB", v
		}
		return "mysql", "MySQL", v
	case "postgres":
		return "postgresql", "PostgreSQL DB", ""
	case "redis":
		if s.Auth == "none" {
			return "redis", "Redis key-value store", s.Ver
		}
		return "redis", "Redis key-value store", ""
	case "rdp":
		return "ms-wbt-server", "", ""
	case "rtsp":
		return "rtsp", "", ""
	case "telnet":
		return "telnet", "", ""
	case "silent":
		switch s.Port {
		case 135:
			return "msrpc", "", ""
		case 139:
			return "netbios-ssn", "", ""
		case 445:
			return "microsoft-ds", "", ""
		case 631:
			return "ipp", "", ""
		case 9100:
			return "jetdirect", "", ""
		case 8291:
			return "winbox", "", ""
		}
		return "unknown", "", ""
	case "https":
		return "https", "", ""
	}
	return "http", "", ""
}

// serverProduct maps an HTTP Server header to nmap-style product/version.
func serverProduct(srv string) (string, string) {
	if strings.TrimSpace(srv) == "" {
		return "", ""
	}
	name, ver, _ := strings.Cut(strings.Fields(srv)[0], "/")
	switch {
	case strings.HasPrefix(srv, "nginx"):
		return "nginx", ver
	case strings.HasPrefix(srv, "Apache"):
		return "Apache httpd", ver
	case strings.HasPrefix(srv, "Microsoft-IIS"):
		return "Microsoft IIS httpd", ver
	case strings.HasPrefix(srv, "Jetty"):
		return "Jetty", strings.TrimSuffix(strings.TrimPrefix(srv, "Jetty("), ")")
	case strings.HasPrefix(srv, "CUPS"):
		return "CUPS", ver
	case strings.HasPrefix(srv, "WSGIServer"):
		return "WSGIServer", ver
	case strings.HasPrefix(srv, "debut"):
		return "Debut embedded httpd", ver
	case strings.HasPrefix(srv, "HP HTTP Server"):
		return "HP HTTP Server", ""
	}
	_ = name
	return "", ""
}

// simulate performs a browser-like GET / against the emulator in-process.
func simulate(h *plan.Host, s *plan.Svc, ip string) (*truth.HTTP, *plan.Svc, http.Header) {
	scheme := "http"
	if s.Kind == "https" {
		scheme = "https"
	}
	port := s.Port
	path := "/"
	cur := s
	th := &truth.HTTP{App: s.App}
	cookies := map[string]truth.Cookie{}
	interesting := map[string]bool{}
	var final *httptest.ResponseRecorder
	for hop := 0; hop < 5; hop++ {
		req := httptest.NewRequest("GET", scheme+"://"+ip+":"+strconv.Itoa(port)+path, nil)
		req.Host = ip
		if !((scheme == "http" && port == 80) || (scheme == "https" && port == 443)) {
			req.Host = ip + ":" + strconv.Itoa(port)
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		rec := httptest.NewRecorder()
		ServeApp(rec, req, h, cur, scheme, ip, port)
		final = rec
		for k := range rec.Header() {
			if disclosureHeaders[strings.ToLower(k)] {
				interesting[strings.ToLower(k)] = true
			}
		}
		for _, c := range (&http.Response{Header: rec.Header()}).Cookies() {
			cookies[c.Name] = truth.Cookie{Name: c.Name, Secure: c.Secure, HttpOnly: c.HttpOnly, Path: c.Path}
		}
		if rec.Code < 300 || rec.Code > 399 {
			break
		}
		loc := rec.Header().Get("Location")
		u, err := url.Parse(loc)
		if err != nil || loc == "" {
			break
		}
		th.Redirects = append(th.Redirects, loc)
		if u.Host != "" {
			if hostOnly(u.Host, "") != ip {
				break
			}
			scheme = u.Scheme
			if _, p, err := splitPort(u.Host); err == nil && p > 0 {
				port = p
			} else if scheme == "https" {
				port = 443
			} else {
				port = 80
			}
			next := h.Svc(port)
			if next == nil || (next.Kind != "http" && next.Kind != "https") {
				break
			}
			cur = next
		}
		path = u.RequestURI()
		if u.Path == "" {
			path = "/"
		}
	}
	th.FinalPath = path
	th.Status = final.Code
	body := final.Body.String()
	if m := reTitle.FindStringSubmatch(body); m != nil {
		th.Title = strings.TrimSpace(htmlUnescape(m[1]))
	}
	if m := reGen.FindStringSubmatch(body); m != nil {
		th.MetaGen = m[1]
	}
	th.Server = final.Header().Get("Server")
	for _, sh := range secHeaders {
		if final.Header().Get(sh) == "" {
			th.MissingSecHeaders = append(th.MissingSecHeaders, sh)
		}
	}
	for k := range interesting {
		th.InterestingHeaders = append(th.InterestingHeaders, k)
	}
	sort.Strings(th.InterestingHeaders)
	for _, c := range cookies {
		th.Cookies = append(th.Cookies, c)
		if !c.Secure || !c.HttpOnly {
			th.InsecureCookies = append(th.InsecureCookies, c.Name)
		}
	}
	sort.Slice(th.Cookies, func(i, j int) bool { return th.Cookies[i].Name < th.Cookies[j].Name })
	sort.Strings(th.InsecureCookies)
	if s.Kind == "https" {
		th.CertKind = s.Cert
		if th.CertKind == "" {
			th.CertKind = "self_signed"
		}
		th.CertCN = h.Hostname + ".lab.agh.local"
	}
	// The final service decides the app shown to the user (after cross-port redirects).
	th.App = cur.App
	return th, cur, final.Header()
}

func splitPort(hp string) (string, int, error) {
	i := strings.LastIndexByte(hp, ':')
	if i < 0 {
		return hp, 0, fmt.Errorf("no port")
	}
	p, err := strconv.Atoi(hp[i+1:])
	return hp[:i], p, err
}

func htmlUnescape(s string) string {
	r := strings.NewReplacer("&#8211;", "–", "&#8212;", "—", "&lsaquo;", "‹", "&#8250;", "›", "&nbsp;", " ", "&amp;", "&", "&raquo;", "»")
	return strings.Join(strings.Fields(r.Replace(s)), " ")
}

// ServiceTruth computes the expected identification for one service.
func ServiceTruth(h *plan.Host, s *plan.Svc, ip string) truth.Service {
	name, product, version := svcName(s)
	ts := truth.Service{Port: s.Port, Proto: "tcp", Service: name, Product: product, Version: version}
	ts.Banner = Banner(h, s, ip)
	switch h.Archetype {
	case "hp-printer", "brother-printer", "hikvision", "synology", "mikrotik":
		ts.Flags.IoT = true
	}
	if s.Kind == "http" || s.Kind == "https" {
		ts.TLS = s.Kind == "https"
		th, final, fh := simulate(h, s, ip)
		ts.HTTP = th
		meta := apps[th.App]
		if p, v := serverProduct(s.Server); p != "" && s.App == "redirect-https" {
			// nmap identifies the port itself (the redirecting server), not the redirect target.
			ts.Product, ts.Version = p, v
		} else if p, v := serverProduct(th.Server); p != "" && final == s {
			ts.Product, ts.Version = p, v
		} else if th.App == "tomcat" && final == s {
			ts.Product, ts.Version = "Apache Tomcat", s.Ver
		}
		techs := map[string]bool{}
		if meta.tech != "" {
			techs[meta.tech] = true
		}
		for _, t := range techsFromHeaders(fh) {
			techs[t] = true
		}
		if th.App == "tomcat" {
			techs["tomcat"] = true
		}
		for t := range techs {
			ts.Technologies = append(ts.Technologies, t)
		}
		sort.Strings(ts.Technologies)
		ts.Flags.AdminPanel = meta.admin
		ts.Flags.IoT = ts.Flags.IoT || meta.iot
		ts.Flags.Staging = final.Staging
		if meta.verShown {
			ts.HTTP.TechVersion = final.Ver
		}
		if ts.TLS {
			ts.Service = "https"
		}
		if th.App == "jenkins" && final == s {
			ts.Product, ts.Version = "Jetty", strings.TrimSuffix(strings.TrimPrefix(th.Server, "Jetty("), ")")
		}
	} else {
		switch s.Kind {
		case "ssh":
			ts.Technologies = []string{"openssh"}
			if s.Product == "rosssh" {
				ts.Technologies = []string{"mikrotik-routeros"}
			}
		case "ftp":
			ts.Technologies = []string{map[string]string{"proftpd": "proftpd", "mikrotik-ftp": "mikrotik-routeros"}[s.Product]}
			if ts.Technologies[0] == "" {
				ts.Technologies = []string{"vsftpd"}
			}
		case "smtp":
			ts.Technologies = []string{s.Product}
		case "pop3", "imap":
			ts.Technologies = []string{"dovecot"}
		case "mysql":
			ts.Technologies = []string{s.Product}
		case "postgres":
			ts.Technologies = []string{"postgresql"}
		case "redis":
			ts.Technologies = []string{"redis"}
		}
	}
	if h.Archetype == "staging-node" || h.Archetype == "test-env" || h.Archetype == "django-dev" {
		if s.Kind == "http" || s.Kind == "https" {
			ts.Flags.Staging = true
		}
	}
	return ts
}
