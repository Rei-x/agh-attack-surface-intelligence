package intelligence

import (
	"regexp"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Service product/version identification.
//
// The exported service product/version follow nmap's naming (nmap-service-probes "p/"
// and "v/" fields, e.g. "Apache httpd", "Microsoft IIS httpd", "nginx", "Jetty"), so the
// inventory lines up with nmap XML, CPEs and DefectDojo. Sources, best first:
//
//  1. nmap -sV <service product= version=> (a protocol-level match);
//  2. the service CPE (cpe:/a:vendor:product:version) when -sV gave no product;
//  3. HTTP evidence when nmap stayed generic (no product) or gave no version:
//     the Server header ("nginx/1.24.0", "Apache/2.4.52 (Ubuntu)", "Microsoft-IIS/10.0",
//     "Jetty(10.0.18)", "CUPS/2.4 IPP/2.1", "WSGIServer/0.2 CPython/3.10", "debut/1.30"),
//     then page identity that names the server (Tomcat's default/error page title
//     "Apache Tomcat/9.0.83").
//
// Web applications (WordPress, Jenkins, Grafana…) are technologies, not the service
// product: nmap reports the HTTP server (Jetty for Jenkins), and so do we.

// Product identification sources (ProductSource values).
const (
	SourceNmap         = "nmap"
	SourceCPE          = "cpe"
	SourceBanner       = "banner"
	SourceServerHeader = "http-server-header"
	SourceHTTPPage     = "http-page"
)

// ProductIdentity is the best evidence-backed product/version of a service.
type ProductIdentity struct {
	Product string
	Version string
	Source  string // where Product came from (Source* constants)
	// VersionSource differs from Source when the version was filled from another channel
	// (e.g. nmap said "nginx" without a version, the Server header said nginx/1.24.0).
	VersionSource string
}

// productAliases maps lower-cased spellings seen in the wild (Server tokens, CPE product
// parts, vendor names) to nmap's canonical product name.
var productAliases = map[string]string{
	"apache":                        "Apache httpd",
	"apache httpd":                  "Apache httpd",
	"apache http server":            "Apache httpd",
	"http_server":                   "Apache httpd",
	"microsoft-iis":                 "Microsoft IIS httpd",
	"microsoft iis":                 "Microsoft IIS httpd",
	"microsoft iis httpd":           "Microsoft IIS httpd",
	"iis":                           "Microsoft IIS httpd",
	"internet_information_services": "Microsoft IIS httpd",
	"internet information services": "Microsoft IIS httpd",
	"nginx":                         "nginx",
	"openresty":                     "OpenResty web app server",
	"lighttpd":                      "lighttpd",
	"caddy":                         "Caddy httpd",
	"jetty":                         "Jetty",
	"eclipse jetty":                 "Jetty",
	"tomcat":                        "Apache Tomcat",
	"apache tomcat":                 "Apache Tomcat",
	"apache-coyote":                 "Apache Tomcat/Coyote JSP engine",
	"cups":                          "CUPS",
	"wsgiserver":                    "WSGIServer",
	"werkzeug":                      "Werkzeug httpd",
	"gunicorn":                      "Gunicorn",
	"uvicorn":                       "Uvicorn",
	"debut":                         "Debut embedded httpd",
	"kestrel":                       "Kestrel",
	"microsoft-httpapi":             "Microsoft HTTPAPI httpd",
	"envoy":                         "Envoy",
	"traefik":                       "Traefik",
	"haproxy":                       "HAProxy http proxy",
	"squid":                         "Squid http proxy",
	"varnish":                       "Varnish",
	"openssh":                       "OpenSSH",
	"vsftpd":                        "vsftpd",
	"proftpd":                       "ProFTPD",
	"postfix":                       "Postfix smtpd",
	"exim":                          "Exim smtpd",
	"dovecot":                       "Dovecot",
	"mysql":                         "MySQL",
	"mariadb":                       "MariaDB",
	"postgresql":                    "PostgreSQL DB",
	"redis":                         "Redis key-value store",
	"elasticsearch":                 "Elasticsearch REST API",
	"node.js":                       "Node.js",
	"express":                       "Node.js Express framework",
	"mini_httpd":                    "mini_httpd",
	"boa":                           "Boa HTTPd",
	"goahead-webs":                  "GoAhead WebServer",
	"micro_httpd":                   "micro_httpd",
	"allegro-software-rompager":     "Allegro RomPager",
	"rompager":                      "Allegro RomPager",
	"hp http server":                "HP HTTP Server",
	"hp-chaisoe":                    "HP-ChaiSOE",
	"virata-emweb":                  "Virata-EmWeb",
	"apache_http_server":            "Apache httpd",
	"igor_sysoev:nginx":             "nginx",
	"f5:nginx":                      "nginx",
	"microsoft:iis":                 "Microsoft IIS httpd",
	"microsoft:internet_information_services": "Microsoft IIS httpd",
	"apache:http_server":                      "Apache httpd",
	"apache:tomcat":                           "Apache Tomcat",
	"eclipse:jetty":                           "Jetty",
	"mortbay:jetty":                           "Jetty",
	"openbsd:openssh":                         "OpenSSH",
	"oracle:mysql":                            "MySQL",
	"mysql:mysql":                             "MySQL",
	"mariadb:mariadb":                         "MariaDB",
	"postgresql:postgresql":                   "PostgreSQL DB",
	"redislabs:redis":                         "Redis key-value store",
	"redis:redis":                             "Redis key-value store",
	"beasts:vsftpd":                           "vsftpd",
	"proftpd:proftpd":                         "ProFTPD",
	"postfix:postfix":                         "Postfix smtpd",
	"exim:exim":                               "Exim smtpd",
	"dovecot:dovecot":                         "Dovecot",
	"apple:cups":                              "CUPS",
	"cups:cups":                               "CUPS",
}

// NormalizeProductName maps vendor/CPE/Server-header spellings to nmap's canonical
// product name ("Apache HTTP Server" and "Apache" -> "Apache httpd", "Microsoft-IIS" ->
// "Microsoft IIS httpd"); unknown names are returned trimmed and unchanged.
func NormalizeProductName(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return ""
	}
	if canon, ok := productAliases[strings.ToLower(n)]; ok {
		return canon
	}
	return n
}

// serverTokenRules parse one product token of an HTTP Server header. Order matters:
// specific products before generic ones. Each rule documents a real header.
var serverTokenRules = []struct {
	re      *regexp.Regexp
	product string
}{
	// Apache/2.4.52 (Ubuntu) | Apache (ServerTokens Prod) | Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.33
	{regexp.MustCompile(`(?i)^Apache(?:/([0-9][0-9.]*[0-9]))?(?:\s|$)`), "Apache httpd"},
	// Apache-Coyote/1.1 (Tomcat HTTP connector, Tomcat <= 8.0 default)
	{regexp.MustCompile(`(?i)^Apache-Coyote(?:/([0-9][0-9.]*))?`), "Apache Tomcat/Coyote JSP engine"},
	// nginx | nginx/1.24.0 | nginx/1.18.0 (Ubuntu)
	{regexp.MustCompile(`(?i)^nginx(?:/([0-9][0-9.]*[0-9]))?`), "nginx"},
	// openresty/1.21.4.1
	{regexp.MustCompile(`(?i)^openresty(?:/([0-9][0-9.]*[0-9]))?`), "OpenResty web app server"},
	// Microsoft-IIS/10.0
	{regexp.MustCompile(`(?i)^Microsoft-IIS(?:/([0-9][0-9.]*))?`), "Microsoft IIS httpd"},
	// Microsoft-HTTPAPI/2.0 (http.sys without IIS: WinRM, SSRS, ...)
	{regexp.MustCompile(`(?i)^Microsoft-HTTPAPI(?:/([0-9][0-9.]*))?`), "Microsoft HTTPAPI httpd"},
	// Jetty(9.4.50.v20221201) | Jetty(10.0.18) | Jetty/9.4
	{regexp.MustCompile(`(?i)^Jetty(?:[(/]([0-9][0-9.]*[0-9])[^)\s]*\)?)?`), "Jetty"},
	// lighttpd/1.4.59
	{regexp.MustCompile(`(?i)^lighttpd(?:/([0-9][0-9.]*[0-9]))?`), "lighttpd"},
	// Caddy
	{regexp.MustCompile(`(?i)^Caddy(?:/([0-9][0-9.]*[0-9]))?`), "Caddy httpd"},
	// CUPS/2.4 IPP/2.1
	{regexp.MustCompile(`(?i)^CUPS(?:/([0-9][0-9.]*[0-9]))?`), "CUPS"},
	// WSGIServer/0.2 CPython/3.10.12 (Django runserver / wsgiref)
	{regexp.MustCompile(`(?i)^WSGIServer(?:/([0-9][0-9.]*[0-9]))?`), "WSGIServer"},
	// Werkzeug/2.3.7 Python/3.11.4 (Flask development server)
	{regexp.MustCompile(`(?i)^Werkzeug(?:/([0-9][0-9.]*[0-9]))?`), "Werkzeug httpd"},
	// gunicorn | gunicorn/20.1.0
	{regexp.MustCompile(`(?i)^gunicorn(?:/([0-9][0-9.]*[0-9]))?`), "Gunicorn"},
	// uvicorn
	{regexp.MustCompile(`(?i)^uvicorn(?:/([0-9][0-9.]*[0-9]))?`), "Uvicorn"},
	// Kestrel (ASP.NET Core)
	{regexp.MustCompile(`(?i)^Kestrel`), "Kestrel"},
	// debut/1.30 (Brother printers' embedded server)
	{regexp.MustCompile(`(?i)^debut(?:/([0-9][0-9.]*[0-9]))?`), "Debut embedded httpd"},
	// HP HTTP Server; HP Color LaserJet MFP M479fdw - W1A79A; Serial Number: ...
	{regexp.MustCompile(`(?i)^HP HTTP Server`), "HP HTTP Server"},
	// HP-ChaiSOE/1.0 (older HP printers)
	{regexp.MustCompile(`(?i)^HP-ChaiSOE(?:/([0-9][0-9.]*[0-9]))?`), "HP-ChaiSOE"},
	// Virata-EmWeb/R6_2_1
	{regexp.MustCompile(`(?i)^Virata-EmWeb(?:/(R[0-9_]+))?`), "Virata-EmWeb"},
	// GoAhead-Webs | GoAhead-http
	{regexp.MustCompile(`(?i)^GoAhead-(?:Webs|http)(?:/([0-9][0-9.]*[0-9]))?`), "GoAhead WebServer"},
	// Boa/0.94.14rc21
	{regexp.MustCompile(`(?i)^Boa(?:/([0-9][0-9.]*[0-9a-z]*))?`), "Boa HTTPd"},
	// mini_httpd/1.30 26Oct2018
	{regexp.MustCompile(`(?i)^mini_httpd(?:/([0-9][0-9.]*[0-9]))?`), "mini_httpd"},
	// Allegro-Software-RomPager/4.07
	{regexp.MustCompile(`(?i)^Allegro-Software-RomPager(?:/([0-9][0-9.]*[0-9]))?`), "Allegro RomPager"},
	// Envoy | envoy
	{regexp.MustCompile(`(?i)^envoy`), "Envoy"},
	// Traefik (rarely sent, but some setups add it)
	{regexp.MustCompile(`(?i)^traefik`), "Traefik"},
	// Squid/5.7
	{regexp.MustCompile(`(?i)^squid(?:/([0-9][0-9.]*[0-9]))?`), "Squid http proxy"},
}

// ParseServerHeader extracts nmap-style product/version from an HTTP Server header.
// Only the first (primary) product token counts: "Apache/2.4.6 (CentOS) PHP/7.4" is
// Apache httpd 2.4.6, not PHP. Generic or unknown values ("webserver", "Server") yield "".
func ParseServerHeader(server string) (product, version string) {
	s := strings.TrimSpace(server)
	if s == "" {
		return "", ""
	}
	for _, r := range serverTokenRules {
		if m := r.re.FindStringSubmatch(s); m != nil {
			v := ""
			if len(m) > 1 {
				v = m[1]
			}
			return r.product, v
		}
	}
	return "", ""
}

var (
	// Tomcat's default page / error pages: <title>Apache Tomcat/9.0.83</title>, <h3>Apache Tomcat/9.0.83</h3>
	reTomcatPage = regexp.MustCompile(`(?i)Apache Tomcat/([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	// nginx / Apache default error pages: <hr><center>nginx/1.24.0</center>, <address>Apache/2.4.52 (Ubuntu) Server at ...</address>
	reNginxErrPage  = regexp.MustCompile(`<center>nginx/([0-9]+\.[0-9]+\.[0-9]+)</center>`)
	reApacheAddress = regexp.MustCompile(`<address>Apache/([0-9]+\.[0-9]+\.[0-9]+)[^<]*Server at`)
	// IIS default page title
	reIISStart = regexp.MustCompile(`(?i)<title>IIS Windows Server</title>|<title>IIS[0-9. ]*Welcome|iisstart\.png`)
)

// productFromPage identifies the HTTP server from page content when no Server header
// names it (Tomcat >= 8.5 sends no Server header but prints its version on the default
// page and on every error page).
func productFromPage(fp *domain.HTTPFingerprint) (product, version string) {
	if fp == nil {
		return "", ""
	}
	texts := []string{fp.Title, fp.BodySnippet}
	for _, h := range fp.SafePathHits {
		texts = append(texts, h.Title, h.Snippet)
	}
	for _, t := range texts {
		if m := reTomcatPage.FindStringSubmatch(t); m != nil {
			return "Apache Tomcat", m[1]
		}
	}
	for _, t := range texts {
		if m := reNginxErrPage.FindStringSubmatch(t); m != nil {
			return "nginx", m[1]
		}
		if m := reApacheAddress.FindStringSubmatch(t); m != nil {
			return "Apache httpd", m[1]
		}
	}
	if reIISStart.MatchString(fp.BodySnippet) {
		return "Microsoft IIS httpd", ""
	}
	return "", ""
}

// ParseCPE returns nmap-style product and version from a CPE 2.2 URI
// ("cpe:/a:igor_sysoev:nginx:1.24.0") or CPE 2.3 string ("cpe:2.3:a:apache:http_server:2.4.52:...").
// Only application CPEs ("a") name a service product.
func ParseCPE(cpe string) (product, version string) {
	c := strings.TrimSpace(cpe)
	var parts []string
	switch {
	case strings.HasPrefix(c, "cpe:2.3:"):
		parts = strings.Split(strings.TrimPrefix(c, "cpe:2.3:"), ":")
	case strings.HasPrefix(c, "cpe:/"):
		parts = strings.Split(strings.TrimPrefix(c, "cpe:/"), ":")
	default:
		return "", ""
	}
	if len(parts) < 3 || parts[0] != "a" {
		return "", ""
	}
	vendor, prod := strings.ToLower(parts[1]), strings.ToLower(parts[2])
	if len(parts) > 3 && parts[3] != "*" && parts[3] != "-" {
		version = parts[3]
	}
	if canon, ok := productAliases[vendor+":"+prod]; ok {
		return canon, version
	}
	if canon, ok := productAliases[prod]; ok {
		return canon, version
	}
	words := strings.Fields(strings.ReplaceAll(prod, "_", " "))
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " "), version
}

// sameProductFamily reports whether two product names refer to the same software
// (first significant word matches: "Apache httpd" ~ "Apache Tomcat" is NOT the same).
func sameProductFamily(a, b string) bool {
	a, b = strings.ToLower(NormalizeProductName(a)), strings.ToLower(NormalizeProductName(b))
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

// genericNmapProducts are -sV answers that name a protocol stack, not a product, so
// HTTP evidence may refine them.
var genericNmapProducts = map[string]bool{
	"golang net/http server": true,
}

func isHTTPService(svc domain.ObservedService) bool {
	if svc.HTTP != nil {
		return true
	}
	n := strings.ToLower(svc.ServiceName)
	return strings.Contains(n, "http") || n == "ssl" || n == "https"
}

// IdentifyProduct returns the best evidence-backed product/version of a service.
func IdentifyProduct(svc domain.ObservedService) ProductIdentity {
	id := ProductIdentity{}
	if p := NormalizeProductName(svc.Product); p != "" {
		id.Product, id.Version, id.Source = p, strings.TrimSpace(svc.Version), SourceNmap
	}
	if id.Product == "" && svc.CPE != "" {
		if p, v := ParseCPE(svc.CPE); p != "" {
			id.Product, id.Version, id.Source = p, v, SourceCPE
		}
	} else if id.Product != "" && id.Version == "" && svc.CPE != "" {
		if p, v := ParseCPE(svc.CPE); v != "" && sameProductFamily(p, id.Product) {
			id.Version, id.VersionSource = v, SourceCPE
		}
	}

	if isHTTPService(svc) && svc.HTTP != nil {
		hp, hv, hsrc := "", "", ""
		if p, v := ParseServerHeader(svc.HTTP.ServerHeader); p != "" {
			hp, hv, hsrc = p, v, SourceServerHeader
		}
		if pp, pv := productFromPage(svc.HTTP); pp != "" {
			switch {
			case hp == "":
				hp, hv, hsrc = pp, pv, SourceHTTPPage
			case sameProductFamily(hp, pp) && hv == "":
				hv = pv
			}
		}
		generic := id.Product == "" || genericNmapProducts[strings.ToLower(id.Product)]
		switch {
		case hp != "" && generic:
			id.Product, id.Version, id.Source, id.VersionSource = hp, hv, hsrc, ""
		case hp != "" && id.Version == "" && hv != "" && sameProductFamily(hp, id.Product):
			id.Version, id.VersionSource = hv, hsrc
		}
	}
	if id.VersionSource == "" && id.Version != "" {
		id.VersionSource = id.Source
	}
	return id
}
