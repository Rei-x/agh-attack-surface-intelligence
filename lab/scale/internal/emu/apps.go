package emu

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/plan"
)

// The HTTP personalities below are modelled on what the real products put on
// the wire (headers, cookies, titles, redirect behaviour, paths). They are not
// derived from — and must not be tuned to — AegisASI's fingerprinter.

type reqCtx struct {
	w      http.ResponseWriter
	r      *http.Request
	h      *plan.Host
	s      *plan.Svc
	scheme string
	ip     string
	port   int
}

func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func randAlnum(n int) string {
	const a = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = a[int(b[i])%len(a)]
	}
	return string(b)
}

func (c *reqCtx) set(kv ...string) {
	for i := 0; i+1 < len(kv); i += 2 {
		c.w.Header().Set(kv[i], kv[i+1])
	}
}

func (c *reqCtx) add(k, v string) { c.w.Header().Add(k, v) }

func (c *reqCtx) server() {
	if c.s.Server != "" {
		c.w.Header().Set("Server", c.s.Server)
	}
}

func (c *reqCtx) base() string {
	host := c.r.Host
	if host == "" {
		host = net.JoinHostPort(c.ip, fmt.Sprint(c.port))
	}
	return c.scheme + "://" + host
}

func (c *reqCtx) html(code int, body string) {
	if c.w.Header().Get("Content-Type") == "" {
		c.w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	}
	c.w.WriteHeader(code)
	if c.r.Method != http.MethodHead {
		_, _ = c.w.Write([]byte(body))
	}
}

func (c *reqCtx) text(code int, ctype, body string) {
	c.w.Header().Set("Content-Type", ctype)
	c.w.WriteHeader(code)
	if c.r.Method != http.MethodHead {
		_, _ = c.w.Write([]byte(body))
	}
}

func (c *reqCtx) redirect(code int, loc string) {
	c.w.Header().Set("Location", loc)
	c.html(code, fmt.Sprintf("<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n<center><h1>%d %s</h1></center>\r\n</body>\r\n</html>\r\n", code, http.StatusText(code), code, http.StatusText(code)))
}

func (c *reqCtx) fqdn() string { return c.h.Hostname + ".lab.agh.local" }

func php(server string) string {
	if strings.Contains(server, "PHP/") {
		return ""
	}
	switch {
	case strings.Contains(server, "Ubuntu"):
		return "PHP/8.1.2-1ubuntu2.19"
	case strings.Contains(server, "Debian"):
		return "PHP/8.2.20"
	}
	return "PHP/7.4.33"
}

func (c *reqCtx) poweredByPHP() {
	if p := php(c.s.Server); p != "" && c.s.Server != "Apache" && c.s.Server != "nginx" {
		c.set("X-Powered-By", p)
	}
}

// notFound mimics the default 404 page of the fronting server.
func (c *reqCtx) notFound() {
	srv := c.s.Server
	switch {
	case strings.HasPrefix(srv, "nginx"):
		c.html(404, "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>"+srv+"</center>\r\n</body>\r\n</html>\r\n")
	case strings.HasPrefix(srv, "Apache"):
		c.html(404, fmt.Sprintf("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n<hr>\n<address>%s Server at %s Port %d</address>\n</body></html>\n", srv, c.ip, c.port))
	case strings.HasPrefix(srv, "Microsoft-IIS"):
		c.html(404, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n<head>\r\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\"/>\r\n<title>404 - File or directory not found.</title>\r\n</head>\r\n<body>\r\n<div id=\"header\"><h1>Server Error</h1></div>\r\n<div id=\"content\">\r\n <div class=\"content-container\"><fieldset>\r\n  <h2>404 - File or directory not found.</h2>\r\n  <h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>\r\n </fieldset></div>\r\n</div>\r\n</body>\r\n</html>\r\n")
	default:
		c.text(404, "text/plain; charset=utf-8", "404 page not found\n")
	}
}

// favicon returns deterministic per-product icon bytes so that identical
// products share a favicon hash, like real deployments do.
func favicon(product string) []byte {
	sum := sha256.Sum256([]byte("favicon:" + product))
	ico := []byte{0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0}
	body := make([]byte, 0, 318)
	for len(body) < 318 {
		body = append(body, sum[:]...)
	}
	return append(ico, body[:318]...)
}

func (c *reqCtx) favicon(product string) {
	c.w.Header().Set("Content-Type", "image/x-icon")
	c.w.WriteHeader(200)
	if c.r.Method != http.MethodHead {
		_, _ = c.w.Write(favicon(product))
	}
}

func cookie(name, val string, attrs ...string) string {
	return name + "=" + val + "; " + strings.Join(attrs, "; ")
}

// ServeApp dispatches a request to the service's application personality.
func ServeApp(w http.ResponseWriter, r *http.Request, h *plan.Host, s *plan.Svc, scheme, ip string, port int) {
	c := &reqCtx{w: w, r: r, h: h, s: s, scheme: scheme, ip: ip, port: port}
	p := r.URL.Path
	switch s.App {
	case "redirect-https":
		c.server()
		loc := "https://" + hostOnly(r.Host, ip) + r.URL.RequestURI()
		if strings.HasPrefix(s.Server, "Apache") {
			c.w.Header().Set("Location", loc)
			c.html(301, fmt.Sprintf("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>301 Moved Permanently</title>\n</head><body>\n<h1>Moved Permanently</h1>\n<p>The document has moved <a href=\"%s\">here</a>.</p>\n</body></html>\n", loc))
			return
		}
		c.redirect(301, loc)
	case "nginx-default":
		appNginxDefault(c, p)
	case "apache-default":
		appApacheDefault(c, p)
	case "wordpress":
		appWordPress(c, p)
	case "joomla":
		appJoomla(c, p)
	case "drupal":
		appDrupal(c, p)
	case "moodle":
		appMoodle(c, p)
	case "jenkins":
		appJenkins(c, p)
	case "grafana":
		appGrafana(c, p)
	case "phpmyadmin":
		appPhpMyAdmin(c, p)
	case "tomcat":
		appTomcat(c, p)
	case "iis-default":
		appIISDefault(c, p)
	case "iis-aspnet":
		appIISAspNet(c, p)
	case "synology":
		appSynology(c, p)
	case "mikrotik":
		appMikroTik(c, p)
	case "hp-printer":
		appHPPrinter(c, p)
	case "brother-printer":
		appBrother(c, p)
	case "hikvision":
		appHikvision(c, p)
	case "gitlab":
		appGitLab(c, p)
	case "keycloak":
		appKeycloak(c, p)
	case "kibana":
		appKibana(c, p)
	case "elasticsearch":
		appElasticsearch(c, p)
	case "prometheus":
		appPrometheus(c, p)
	case "zabbix":
		appZabbix(c, p)
	case "roundcube":
		appRoundcube(c, p)
	case "express-staging":
		appExpress(c, p)
	case "spring-boot":
		appSpring(c, p)
	case "django-dev":
		appDjango(c, p)
	case "custom-admin":
		appCustomAdmin(c, p)
	case "test-apache":
		appTestApache(c, p)
	case "cups":
		appCUPS(c, p)
	case "idrac":
		appIDRAC(c, p)
	default:
		c.server()
		c.notFound()
	}
}

func hostOnly(hostport, fallback string) string {
	if hostport == "" {
		return fallback
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// ---------------------------------------------------------------- generic web servers

func appNginxDefault(c *reqCtx, p string) {
	c.server()
	switch p {
	case "/", "/index.html":
		c.set("Last-Modified", "Tue, 21 Apr 2020 14:09:01 GMT", "ETag", `"5e9efe7d-264"`, "Accept-Ranges", "bytes")
		c.html(200, "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\n    body {\n        width: 35em;\n        margin: 0 auto;\n        font-family: Tahoma, Verdana, Arial, sans-serif;\n    }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n\n<p>For online documentation and support please refer to\n<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\nCommercial support is available at\n<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\n<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n")
	default:
		c.notFound()
	}
}

func appApacheDefault(c *reqCtx, p string) {
	c.server()
	srv := c.s.Server
	switch p {
	case "/", "/index.html":
		c.set("Last-Modified", "Mon, 11 Mar 2024 09:12:44 GMT", "ETag", `"29af-6135c3f1a6f00"`, "Accept-Ranges", "bytes", "Vary", "Accept-Encoding")
		switch {
		case strings.Contains(srv, "Ubuntu"):
			c.html(200, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\">\n  <head>\n    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n    <title>Apache2 Ubuntu Default Page: It works</title>\n  </head>\n  <body>\n    <div class=\"main_page\">\n      <div class=\"page_header floating_element\">\n        <img src=\"/icons/ubuntu-logo.png\" alt=\"Ubuntu Logo\" class=\"floating_element\"/>\n        <span class=\"floating_element\">\n          Apache2 Ubuntu Default Page\n        </span>\n      </div>\n      <div class=\"content_section_text\">\n        <p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems.</p>\n      </div>\n    </div>\n  </body>\n</html>\n")
		case strings.Contains(srv, "Debian"):
			c.html(200, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\">\n  <head>\n    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n    <title>Apache2 Debian Default Page: It works</title>\n  </head>\n  <body>\n    <div class=\"main_page\">\n      <div class=\"page_header floating_element\">\n        <img src=\"/icons/openlogo-75.png\" alt=\"Debian Logo\" class=\"floating_element\"/>\n        <span class=\"floating_element\">Apache2 Debian Default Page</span>\n      </div>\n    </div>\n  </body>\n</html>\n")
		case strings.Contains(srv, "CentOS"):
			c.html(403, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n<html><head>\n<title>Apache HTTP Server Test Page powered by CentOS</title>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n</head><body>\n<h1>Apache HTTP Server <strong>Test Page</strong></h1>\n<p class=\"lead\">This page is used to test the proper operation of the Apache HTTP server after it has been installed.</p>\n</body></html>\n")
		default:
			c.html(200, "<html><body><h1>It works!</h1></body></html>\n")
		}
	case "/server-status":
		c.html(403, fmt.Sprintf("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\n<p>You don't have permission to access this resource.</p>\n<hr>\n<address>%s Server at %s Port %d</address>\n</body></html>\n", srv, c.ip, c.port))
	default:
		c.notFound()
	}
}

// ---------------------------------------------------------------- CMS

func appWordPress(c *reqCtx, p string) {
	c.server()
	c.poweredByPHP()
	b := c.base()
	ver := c.s.Ver
	site := c.s.Site
	switch p {
	case "/", "/index.php":
		c.add("Link", "<"+b+"/wp-json/>; rel=\"https://api.w.org/\"")
		c.add("Link", "<"+b+"/>; rel=shortlink")
		c.set("Vary", "Accept-Encoding")
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html lang="pl-PL">
<head>
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name='robots' content='max-image-preview:large' />
	<title>%[1]s &#8211; Akademia Górniczo-Hutnicza</title>
<link rel="alternate" type="application/rss+xml" title="%[1]s &raquo; Kanał z wpisami" href="%[2]s/feed/" />
<link rel='stylesheet' id='wp-block-library-css' href='%[2]s/wp-includes/css/dist/block-library/style.min.css?ver=%[3]s' media='all' />
<link rel='stylesheet' id='twentytwentyfour-style-css' href='%[2]s/wp-content/themes/twentytwentyfour/style.css?ver=1.0' media='all' />
<script src="%[2]s/wp-includes/js/jquery/jquery.min.js?ver=3.7.1" id="jquery-core-js"></script>
<link rel="https://api.w.org/" href="%[2]s/wp-json/" /><link rel="EditURI" type="application/rsd+xml" title="RSD" href="%[2]s/xmlrpc.php?rsd" />
<meta name="generator" content="WordPress %[3]s" />
</head>
<body class="home blog wp-embed-responsive">
<div class="wp-site-blocks"><header class="wp-block-template-part"><h1 class="wp-block-site-title"><a href="%[2]s" rel="home">%[1]s</a></h1></header>
<main><h2 class="wp-block-post-title"><a href="%[2]s/2024/03/witamy/">Witamy na stronie</a></h2></main>
<footer class="wp-block-template-part"><p class="has-text-align-center">Wspierane przez <a href="https://pl.wordpress.org" rel="nofollow">WordPress</a></p></footer></div>
<script src="%[2]s/wp-includes/js/wp-emoji-release.min.js?ver=%[3]s" id="wp-emoji-js"></script>
</body>
</html>
`, site, b, ver))
	case "/wp-login.php":
		c.set("Expires", "Wed, 11 Jan 1984 05:00:00 GMT", "Cache-Control", "no-cache, must-revalidate, max-age=0, no-store, private",
			"X-Frame-Options", "SAMEORIGIN", "Referrer-Policy", "strict-origin-when-cross-origin")
		attrs := []string{"path=/"}
		if c.scheme == "https" {
			attrs = append(attrs, "secure")
		}
		c.add("Set-Cookie", cookie("wordpress_test_cookie", "WP%20Cookie%20check", attrs...))
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html lang="pl-PL">
	<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<title>Zaloguj się &lsaquo; %[1]s &#8212; WordPress</title>
	<link rel='stylesheet' id='login-css' href='%[2]s/wp-admin/css/login.min.css?ver=%[3]s' media='all' />
	<meta name='robots' content='max-image-preview:large, noindex, noarchive' />
	</head>
	<body class="login no-js login-action-login wp-core-ui  locale-pl-pl">
	<div id="login">
		<h1><a href="https://pl.wordpress.org/">Wspierane przez WordPress</a></h1>
		<form name="loginform" id="loginform" action="%[2]s/wp-login.php" method="post">
			<p><label for="user_login">Nazwa użytkownika lub adres e-mail</label>
			<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required="required" /></p>
			<div class="user-pass-wrap"><label for="user_pass">Hasło</label>
			<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" required="required" /></div>
			<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Zaloguj się" /></p>
		</form>
		<p id="nav"><a href="%[2]s/wp-login.php?action=lostpassword">Nie pamiętasz hasła?</a></p>
	</div>
	</body>
</html>
`, c.s.Site, c.base(), ver))
	case "/wp-admin", "/wp-admin/":
		c.set("Cache-Control", "no-cache, must-revalidate, max-age=0, no-store, private")
		c.redirect(302, b+"/wp-login.php?redirect_to="+strings.ReplaceAll(b, ":", "%3A")+"%2Fwp-admin%2F&reauth=1")
	case "/admin":
		c.redirect(302, b+"/wp-admin/")
	case "/login":
		c.redirect(302, b+"/wp-login.php")
	case "/wp-json/", "/wp-json":
		c.set("X-Robots-Tag", "noindex", "Access-Control-Expose-Headers", "X-WP-Total, X-WP-TotalPages, Link", "Allow", "GET")
		c.text(200, "application/json; charset=UTF-8", fmt.Sprintf(`{"name":"%s","description":"","url":"%s","home":"%s","gmt_offset":"1","timezone_string":"Europe/Warsaw","namespaces":["oembed/1.0","wp/v2","wp-site-health/v1","wp-block-editor/v1"],"authentication":[],"routes":{}}`, site, b, b))
	case "/xmlrpc.php":
		c.text(405, "text/plain;charset=UTF-8", "XML-RPC server accepts POST requests only.")
	case "/readme.html":
		c.html(200, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n\t<meta name=\"viewport\" content=\"width=device-width\" />\n\t<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n\t<title>WordPress &#8250; ReadMe</title>\n</head>\n<body>\n<h1 id=\"logo\"><a href=\"https://wordpress.org/\"><img alt=\"WordPress\" src=\"wp-admin/images/wordpress-logo.png\" /></a></h1>\n<p style=\"text-align: center\">Semantic Personal Publishing Platform</p>\n</body>\n</html>\n")
	case "/robots.txt":
		c.text(200, "text/plain; charset=utf-8", "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n\nSitemap: "+b+"/wp-sitemap.xml\n")
	case "/feed/":
		c.text(200, "application/rss+xml; charset=UTF-8", fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?><rss version=\"2.0\"><channel><title>%s</title><link>%s</link><generator>https://wordpress.org/?v=%s</generator></channel></rss>", site, b, ver))
	case "/favicon.ico":
		c.favicon("wordpress")
	default:
		c.set("Expires", "Wed, 11 Jan 1984 05:00:00 GMT", "Cache-Control", "no-cache, must-revalidate, max-age=0, no-store, private")
		c.add("Link", "<"+b+"/wp-json/>; rel=\"https://api.w.org/\"")
		c.html(404, fmt.Sprintf("<!DOCTYPE html>\n<html lang=\"pl-PL\">\n<head>\n<meta charset=\"UTF-8\" />\n<title>Nie znaleziono strony &#8211; %s</title>\n<meta name=\"generator\" content=\"WordPress %s\" />\n</head>\n<body class=\"error404\"><h1>Nie znaleziono strony</h1></body>\n</html>\n", site, ver))
	}
}

func joomlaSessionName(c *reqCtx) string {
	s := sha256.Sum256([]byte("joomla-session:" + c.ip))
	return hex.EncodeToString(s[:16])
}

func appJoomla(c *reqCtx, p string) {
	c.server()
	c.poweredByPHP()
	b := c.base()
	j4 := !strings.HasPrefix(c.s.Ver, "3.")
	sess := func() {
		c.add("Set-Cookie", cookie(joomlaSessionName(c), randAlnum(26), "path=/", "HttpOnly"))
	}
	switch p {
	case "/", "/index.php":
		sess()
		c.set("Expires", "Wed, 17 Aug 2005 00:00:00 GMT", "Last-Modified", time.Now().UTC().Format(http.TimeFormat), "Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0", "Pragma", "no-cache")
		if j4 {
			c.set("Referrer-Policy", "strict-origin-when-cross-origin", "Cross-Origin-Opener-Policy", "same-origin", "X-Frame-Options", "SAMEORIGIN")
		}
		js := "/media/jui/js/jquery.min.js?" + randHex(32)
		if j4 {
			js = "/media/system/js/core.min.js?" + randHex(20)
		}
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html lang="pl-pl" dir="ltr">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="generator" content="Joomla! - Open Source Content Management">
	<title>Strona główna - %[1]s</title>
	<link href="%[2]s/index.php?format=feed&amp;type=rss" rel="alternate" type="application/rss+xml" title="Strona główna - %[1]s">
	<link href="/templates/cassiopeia/images/joomla-favicon.svg" rel="icon" type="image/svg+xml">
	<script src="%[3]s"></script>
</head>
<body class="site com_content view-featured layout-blog">
	<header class="header container-header full-width"><div class="navbar-brand"><a class="brand-logo" href="/"><span>%[1]s</span></a></div></header>
	<div class="site-grid"><main><div class="blog-featured"><h2>Aktualności</h2></div></main></div>
	<footer class="container-footer footer full-width"><div class="grid-child"></div></footer>
</body>
</html>
`, c.s.Site, b, js))
	case "/administrator", "/administrator/", "/administrator/index.php":
		if p == "/administrator" {
			c.redirect(301, b+"/administrator/")
			return
		}
		sess()
		c.set("X-Frame-Options", "SAMEORIGIN", "Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html lang="pl-pl" dir="ltr">
<head>
	<meta charset="utf-8">
	<meta name="generator" content="Joomla! - Open Source Content Management">
	<title>%s - Administracja</title>
	<link href="/media/templates/administrator/atum/images/logos/brand-large.svg" rel="preload" as="image">
</head>
<body class="admin com_login view-login">
	<section id="content" class="content"><form action="/administrator/index.php" method="post" id="form-login">
	<h2>Zaloguj się do panelu Joomla!</h2>
	<input name="username" id="mod-login-username" type="text" required autofocus>
	<input name="passwd" id="mod-login-password" type="password" required>
	<button type="submit">Zaloguj się</button>
	<input type="hidden" name="option" value="com_login"><input type="hidden" name="task" value="login">
	</form></section>
</body>
</html>
`, c.s.Site))
	case "/administrator/manifests/files/joomla.xml":
		c.text(200, "application/xml", fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<extension type=\"file\" method=\"upgrade\">\n\t<name>files_joomla</name>\n\t<author>Joomla! Project</author>\n\t<copyright>(C) 2019 Open Source Matters, Inc.</copyright>\n\t<version>%s</version>\n\t<creationDate>2024-01</creationDate>\n\t<description>FILES_JOOMLA_XML_DESCRIPTION</description>\n</extension>\n", c.s.Ver))
	case "/robots.txt":
		c.text(200, "text/plain", "# If the Joomla site is installed within a folder\n# eg www.example.com/joomla/ then the robots.txt file\n# MUST be moved to the site root\nUser-agent: *\nDisallow: /administrator/\nDisallow: /api/\nDisallow: /bin/\nDisallow: /cache/\nDisallow: /cli/\nDisallow: /components/\nDisallow: /includes/\nDisallow: /installation/\nDisallow: /language/\nDisallow: /layouts/\nDisallow: /libraries/\nDisallow: /logs/\nDisallow: /modules/\nDisallow: /plugins/\nDisallow: /tmp/\n")
	case "/favicon.ico":
		c.favicon("joomla")
	default:
		sess()
		c.html(404, "<!DOCTYPE html>\n<html lang=\"pl-pl\" dir=\"ltr\">\n<head>\n<meta charset=\"utf-8\">\n<title>404 - Nie znaleziono strony</title>\n</head>\n<body class=\"error-page\"><h1>404 - Nie znaleziono strony</h1><p>Nie znaleziono strony.</p></body>\n</html>\n")
	}
}

func appDrupal(c *reqCtx, p string) {
	c.server()
	if strings.HasPrefix(c.s.Server, "Apache") {
		c.poweredByPHP()
	}
	b := c.base()
	major := c.s.Ver
	gen := "Drupal " + major + " (https://www.drupal.org)"
	if major == "7" {
		gen = "Drupal 7 (http://drupal.org)"
	}
	common := func() {
		c.set("X-Generator", gen, "X-Content-Type-Options", "nosniff", "X-Frame-Options", "SAMEORIGIN",
			"Cache-Control", "must-revalidate, no-cache, private", "Expires", "Sun, 19 Nov 1978 05:00:00 GMT",
			"Content-Language", "pl", "Vary", "Cookie")
		if major != "7" {
			c.set("X-Drupal-Cache", "MISS", "X-Drupal-Dynamic-Cache", "MISS", "X-UA-Compatible", "IE=edge",
				"Permissions-Policy", "interest-cohort=()")
		} else {
			c.set("X-Drupal-Cache", "MISS", "Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		}
	}
	page := func(code int, title, body string) {
		common()
		c.html(code, fmt.Sprintf(`<!DOCTYPE html>
<html lang="pl" dir="ltr">
  <head>
    <meta charset="utf-8" />
<meta name="Generator" content="%[1]s" />
<meta name="MobileOptimized" content="width" />
<link rel="icon" href="/core/misc/favicon.ico" type="image/vnd.microsoft.icon" />
    <title>%[2]s</title>
    <link rel="stylesheet" media="all" href="/sites/default/files/css/css_%[4]s.css?delta=0&amp;language=pl&amp;theme=olivero" />
    <script src="/core/misc/drupal.js?v=%[5]s"></script>
  </head>
  <body class="path-frontpage">
    <a href="#main-content" class="visually-hidden focusable skip-link">Przejdź do treści</a>
    <div class="dialog-off-canvas-main-canvas" data-off-canvas-main-canvas>%[3]s</div>
    <script type="application/json" data-drupal-selector="drupal-settings-json">{"path":{"baseUrl":"\/","scriptPath":null,"pathPrefix":"","currentPath":"node","isFront":true},"pluralDelimiter":"\u0003"}</script>
  </body>
</html>
`, gen, title, body, randHex(43), major))
	}
	switch p {
	case "/", "/node":
		page(200, c.s.Site, "<h1>"+c.s.Site+"</h1><p>Witamy</p>")
	case "/user/login", "/user", "/login":
		if p == "/login" {
			page(404, "Nie znaleziono strony | "+c.s.Site, "<h1>Nie znaleziono strony</h1>")
			return
		}
		page(200, "Zaloguj | "+c.s.Site, `<form class="user-login-form" action="/user/login" method="post" id="user-login-form"><input name="name" type="text"/><input name="pass" type="password"/><input type="submit" value="Zaloguj"/></form>`)
	case "/admin":
		page(403, "Odmowa dostępu | "+c.s.Site, "<h1>Odmowa dostępu</h1><p>Nie masz uprawnień dostępu do tej strony.</p>")
	case "/CHANGELOG.txt":
		if major == "7" {
			c.text(200, "text/plain", "Drupal 7.98, 2023-06-07\n-----------------------\n- Fixed security issues:\n   - SA-CORE-2023-005\n")
			return
		}
		common()
		c.notFound()
	case "/robots.txt":
		c.text(200, "text/plain", "#\n# robots.txt\n#\n# This file is to prevent the crawling and indexing of certain parts\n# of your site by web crawlers and spiders run by sites like Yahoo!\n# and Google.\nUser-agent: *\n# CSS, JS, Images\nAllow: /core/*.css$\n# Directories\nDisallow: /core/\nDisallow: /profiles/\n# Paths (clean URLs)\nDisallow: /admin/\nDisallow: /user/login\n")
	case "/favicon.ico":
		c.favicon("drupal")
	default:
		page(404, "Nie znaleziono strony | "+c.s.Site, "<h1>Nie znaleziono strony</h1><p>Żądana strona \""+p+"\" nie mogła zostać odnaleziona.</p>")
	}
	_ = b
}

func appMoodle(c *reqCtx, p string) {
	c.server()
	c.poweredByPHP()
	b := c.base()
	sess := func() {
		attrs := []string{"path=/"}
		if c.scheme == "https" {
			attrs = append(attrs, "secure")
		}
		c.add("Set-Cookie", cookie("MoodleSession", randAlnum(26), attrs...))
		c.set("Cache-Control", "private, pre-check=0, post-check=0, max-age=0, no-transform", "Pragma", "no-cache",
			"Expires", "Mon, 20 Aug 1969 09:23:00 GMT", "Content-Language", "pl", "Content-Script-Type", "text/javascript",
			"Content-Style-Type", "text/css", "X-UA-Compatible", "IE=edge", "Accept-Ranges", "none")
	}
	switch p {
	case "/":
		sess()
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html  dir="ltr" lang="pl" xml:lang="pl">
<head>
    <title>UPeL - Platforma e-Learningowa AGH</title>
    <link rel="shortcut icon" href="%[1]s/theme/image.php/boost/theme/1709123456/favicon" />
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="keywords" content="moodle, UPeL - Platforma e-Learningowa AGH" />
<link rel="stylesheet" type="text/css" href="%[1]s/theme/styles.php/boost/1709123456_1/all" />
<script>
//<![CDATA[
var M = {}; M.yui = {};
M.cfg = {"wwwroot":"%[1]s","homeurl":{},"sesskey":"%[2]s","sessiontimeout":"28800","themerev":"1709123456","slasharguments":1,"theme":"boost","iconsystemmodule":"core\/icon_system_fontawesome","jsrev":"1709123456","admin":"admin","svgicons":true,"usertimezone":"Europa\/Warszawa","language":"pl"};
//]]>
</script>
</head>
<body  id="page-site-index" class="format-site course path-site chrome dir-ltr lang-pl yui-skin-sam yui3-skin-sam pagelayout-frontpage course-1 context-2 notloggedin theme">
<div id="page-wrapper" class="d-print-block">
    <nav class="navbar fixed-top navbar-light bg-white navbar-expand" aria-label="Nawigacja strony"><a href="%[1]s/login/index.php">Zaloguj się</a></nav>
    <div id="page" class="container-fluid"><h1>UPeL</h1></div>
    <footer id="page-footer"><div class="logininfo">Nie jesteś zalogowany(a) (<a href="%[1]s/login/index.php">Zaloguj się</a>)</div><a href="https://download.moodle.org/mobile?version=2022112809&amp;lang=pl&amp;iosappid=633359593&amp;androidappid=com.moodle.moodlemobile">Pobierz aplikację mobilną</a></footer>
</div>
</body>
</html>
`, b, randAlnum(10)))
	case "/login/index.php", "/login", "/login/":
		if p != "/login/index.php" {
			c.redirect(303, b+"/login/index.php")
			return
		}
		sess()
		c.html(200, "<!DOCTYPE html>\n<html dir=\"ltr\" lang=\"pl\">\n<head>\n<title>UPeL: Zaloguj się na stronie</title>\n<meta name=\"keywords\" content=\"moodle, UPeL: Zaloguj się na stronie\" />\n</head>\n<body id=\"page-login-index\" class=\"format-site path-login\"><form action=\""+b+"/login/index.php\" method=\"post\" id=\"login\"><input type=\"hidden\" name=\"logintoken\" value=\""+randAlnum(32)+"\"><input type=\"text\" name=\"username\" id=\"username\"><input type=\"password\" name=\"password\" id=\"password\"><button type=\"submit\" id=\"loginbtn\">Zaloguj się</button></form></body>\n</html>\n")
	case "/admin", "/admin/":
		sess()
		c.redirect(303, b+"/login/index.php")
	case "/robots.txt":
		c.notFound()
	case "/favicon.ico":
		c.favicon("moodle")
	default:
		sess()
		c.html(404, "<!DOCTYPE html>\n<html><head><title>UPeL: Błąd</title></head><body><div class=\"errorbox\"><p class=\"errormessage\">Nie znaleziono strony</p></div></body></html>\n")
	}
}

// ---------------------------------------------------------------- dev & ops tools

func jettyVersion(jenkins string) string {
	if strings.HasPrefix(jenkins, "2.3") {
		return "Jetty(9.4.50.v20221201)"
	}
	return "Jetty(10.0.18)"
}

func appJenkins(c *reqCtx, p string) {
	c.set("Server", jettyVersion(c.s.Ver), "X-Content-Type-Options", "nosniff")
	jh := func() {
		c.set("X-Jenkins", c.s.Ver, "X-Jenkins-Session", randHex(8), "X-Hudson", "1.395", "X-Hudson-Theme", "default",
			"X-Instance-Identity", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"+randAlnum(40), "Referrer-Policy", "same-origin",
			"Cross-Origin-Opener-Policy", "same-origin")
	}
	switch {
	case p == "/login" || strings.HasPrefix(p, "/login"):
		jh()
		c.add("Set-Cookie", cookie("JSESSIONID."+randHex(8), "node0"+randAlnum(26)+".node0", "Path=/", "HttpOnly"))
		c.set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT", "Cache-Control", "no-cache,no-store,must-revalidate", "X-Frame-Options", "sameorigin")
		c.html(200, fmt.Sprintf(`<!DOCTYPE html><html class=""><head resURL="/static/%[1]s" data-rooturl="" data-resurl="/static/%[1]s" data-imagesurl="/static/%[1]s/images"><title>Sign in [Jenkins]</title><meta name="ROBOTS" content="NOFOLLOW"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/static/%[1]s/jsbundles/simple-page.css" type="text/css"></head><body><div class="simple-page" role="main"><div class="modal login"><div id="loginIntroDefault"><div class="logo"></div><h1>Welcome to Jenkins!</h1></div><form method="post" name="login" action="j_spring_security_check"><input autocorrect="off" autocomplete="off" name="j_username" id="j_username" placeholder="Username" type="text" class="normal" autocapitalize="off"><input name="j_password" placeholder="Password" type="password" class="normal"><button type="submit" name="Submit" class="submit-button primary ">Sign in</button></form></div></div></body></html>`, randHex(8)))
	case strings.HasPrefix(p, "/static/"):
		jh()
		c.text(200, "text/css", "/* jenkins */")
	case p == "/favicon.ico":
		c.favicon("jenkins")
	case p == "/robots.txt":
		c.text(200, "text/plain", "# we don't want robots to click \"build\" links\nUser-agent: *\nDisallow: /\n")
	default:
		jh()
		c.set("X-You-Are-Authenticated-As", "anonymous", "X-You-Are-In-Group-Disabled", "JENKINS-39402: use -Dhudson.security.AccessDeniedException2.REPORT_GROUP_HEADERS=true or use /whoAmI to diagnose",
			"X-Required-Permission", "hudson.model.Hudson.Read", "X-Permission-Implied-By", "hudson.model.Hudson.Administer", "Cache-Control", "no-cache,no-store,must-revalidate")
		from := strings.ReplaceAll(p, "/", "%2F")
		c.html(403, fmt.Sprintf("<html><head><meta http-equiv='refresh' content='1;url=/login?from=%s'/><script>window.location.replace('/login?from=%s');</script></head><body style='background-color:white; color:white;'>\n\nAuthentication required\n<!--\n-->\n\n</body></html>\n", from, from))
	}
}

func appGrafana(c *reqCtx, p string) {
	c.set("Cache-Control", "no-store", "X-Content-Type-Options", "nosniff", "X-Frame-Options", "deny", "X-Xss-Protection", "1; mode=block")
	switch p {
	case "/":
		c.add("Set-Cookie", cookie("redirect_to", "%2F", "Path=/", "HttpOnly", "SameSite=Lax"))
		c.w.Header().Set("Location", "/login")
		c.html(302, "<a href=\"/login\">Found</a>.\n\n")
	case "/login":
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html lang="en-US">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <meta name="viewport" content="width=device-width" />
    <meta name="theme-color" content="#000" />
    <title>Grafana</title>
    <base href="/" />
    <link rel="icon" type="image/png" href="public/img/fav32.png" />
    <link rel="apple-touch-icon" sizes="180x180" href="public/img/apple-touch-icon.png" />
    <link rel="mask-icon" href="public/img/grafana_mask_icon.svg" color="#F05A28" />
    <link rel="stylesheet" href="public/build/grafana.dark.%[2]s.css" />
  </head>
  <body class="theme-dark app-grafana">
    <div class="preloader"><div class="preloader__enter"><div class="preloader__bounce"><div class="preloader__logo" aria-live="polite" role="status"></div></div></div></div>
    <div id="reactRoot"></div>
    <script nonce="">
      window.grafanaBootData = {
        user: {"isSignedIn":false,"id":0,"login":"","email":"","name":"","theme":"dark","orgId":0,"orgName":"","orgRole":"","isGrafanaAdmin":false,"locale":"en-US"},
        settings: {"appSubUrl":"","appUrl":"%[3]s/","authProxyEnabled":false,"buildInfo":{"buildstamp":1702461230,"commit":"%[4]s","edition":"Open Source","env":"production","hasUpdate":false,"hideVersion":false,"latestVersion":"","version":"%[1]s"},"disableLoginForm":false,"loginHint":"email or username"},
        navTree: [],
      };
    </script>
    <script nonce="" src="public/build/runtime.%[2]s.js" type="text/javascript"></script>
  </body>
</html>
`, c.s.Ver, randHex(20), c.base(), randHex(10)))
	case "/api/health":
		c.text(200, "application/json", fmt.Sprintf("{\n  \"commit\": \"%s\",\n  \"database\": \"ok\",\n  \"version\": \"%s\"\n}", randHex(10), c.s.Ver))
	case "/metrics":
		c.text(200, "text/plain; version=0.0.4; charset=utf-8", fmt.Sprintf("# HELP grafana_build_info A metric with a constant '1' value labeled by version, revision, branch, and goversion from which Grafana was built\n# TYPE grafana_build_info gauge\ngrafana_build_info{branch=\"HEAD\",edition=\"oss\",goversion=\"go1.21.5\",revision=\"%s\",version=\"%s\"} 1\n", randHex(10), c.s.Ver))
	case "/robots.txt":
		c.text(200, "text/plain; charset=utf-8", "User-agent: *\nDisallow: /\n")
	case "/favicon.ico", "/public/img/fav32.png":
		c.favicon("grafana")
	default:
		c.add("Set-Cookie", cookie("redirect_to", strings.ReplaceAll(p, "/", "%2F"), "Path=/", "HttpOnly", "SameSite=Lax"))
		c.w.Header().Set("Location", "/login")
		c.html(302, "<a href=\"/login\">Found</a>.\n\n")
	}
}

func appPhpMyAdmin(c *reqCtx, p string) {
	c.server()
	c.poweredByPHP()
	v := c.s.Ver
	newer := !strings.HasPrefix(v, "4.")
	login := func() {
		ss := []string{"path=/", "HttpOnly"}
		if newer {
			ss = append(ss, "SameSite=Strict")
		}
		if c.scheme == "https" {
			ss = append(ss, "secure")
		}
		c.add("Set-Cookie", cookie("phpMyAdmin", randHex(32), ss...))
		c.add("Set-Cookie", cookie("pma_lang", "pl", append([]string{"expires=" + time.Now().Add(30*24*time.Hour).UTC().Format(http.TimeFormat), "Max-Age=2592000"}, ss...)...))
		c.set("X-Ob_Mode", "1", "X-Frame-Options", "DENY", "Referrer-Policy", "no-referrer",
			"Content-Security-Policy", "default-src 'self' ;script-src 'self' 'unsafe-inline' 'unsafe-eval' ;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';",
			"X-XSS-Protection", "1; mode=block", "X-Content-Type-Options", "nosniff", "X-Permitted-Cross-Domain-Policies", "none",
			"X-Robots-Tag", "noindex, nofollow", "Expires", time.Now().UTC().Format(http.TimeFormat),
			"Cache-Control", "no-store, no-cache, must-revalidate,  pre-check=0, post-check=0, max-age=0", "Pragma", "no-cache", "Vary", "Accept-Encoding")
		c.html(200, fmt.Sprintf(`<!DOCTYPE HTML>
<html lang="pl" dir="ltr">
<head>
  <meta charset="utf-8">
  <meta name="referrer" content="no-referrer">
  <meta name="robots" content="noindex,nofollow,notranslate">
  <meta name="google" content="notranslate">
  <style id="cfs-style">html{display: none;}</style>
  <link rel="icon" href="favicon.ico" type="image/x-icon">
  <link rel="shortcut icon" href="favicon.ico" type="image/x-icon">
  <link rel="stylesheet" type="text/css" href="./themes/pmahomme/jquery/jquery-ui.css">
  <link rel="stylesheet" type="text/css" href="js/vendor/codemirror/lib/codemirror.css?v=%[1]s">
  <link rel="stylesheet" type="text/css" href="./themes/pmahomme/css/theme.css?v=%[1]s">
  <title>phpMyAdmin</title>
    <script data-cfasync="false" type="text/javascript" src="js/vendor/jquery/jquery.min.js?v=%[1]s"></script>
</head>
<body id="loginform">
<div class="container">
<a href="./url.php?url=https%%3A%%2F%%2Fwww.phpmyadmin.net%%2F" target="_blank" rel="noopener noreferrer" class="logo">
  <img src="./themes/pmahomme/img/logo_right.png" id="imLogo" name="imLogo" alt="phpMyAdmin" border="0">
</a>
<h1>Witamy w <bdo dir="ltr" lang="en">phpMyAdmin</bdo></h1>
<form method="post" id="login_form" action="index.php?route=/" name="login_form" class="disableAjax hide js-show">
  <fieldset><legend>Zaloguj się</legend>
  <input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield" autocomplete="username">
  <input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield" autocomplete="current-password">
  <input type="hidden" name="server" value="1">
  </fieldset>
  <input class="btn btn-primary" value="Zaloguj" type="submit" id="input_go">
  <input type="hidden" name="token" value="%[2]s">
</form>
</div>
</body>
</html>
`, v, randAlnum(32)))
	}
	switch p {
	case "/", "/index.php", "/phpmyadmin/", "/phpmyadmin/index.php":
		login()
	case "/phpmyadmin":
		c.redirect(301, c.base()+"/phpmyadmin/")
	case "/robots.txt":
		c.text(200, "text/plain", "User-agent: *\nDisallow: /\n")
	case "/favicon.ico", "/phpmyadmin/favicon.ico":
		c.favicon("phpmyadmin")
	case "/README", "/ChangeLog":
		c.text(200, "text/plain", "phpMyAdmin - Readme\n===================\n\nVersion "+v+"\n\nA web interface for MySQL and MariaDB.\n")
	default:
		c.notFound()
	}
}

func appTomcat(c *reqCtx, p string) {
	v := c.s.Ver
	switch p {
	case "/", "/index.jsp":
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>Apache Tomcat/%[1]s</title>
        <link href="favicon.ico" rel="icon" type="image/x-icon" />
        <link href="tomcat.css" rel="stylesheet" type="text/css" />
    </head>
    <body>
        <div id="wrapper">
            <div id="navigation" class="curved container">
                <span id="nav-home"><a href="https://tomcat.apache.org/">Home</a></span>
                <span id="nav-docs"><a href="/docs/">Documentation</a></span>
                <br class="separator" />
            </div>
            <div id="asf-box"><h1>Apache Tomcat/%[1]s</h1></div>
            <div id="upper" class="curved container">
                <div id="congrats" class="curved container"><h2>If you're seeing this, you've successfully installed Tomcat. Congratulations!</h2></div>
                <div id="actions">
                    <div class="button"><a class="container shadow" href="/manager/status"><span>Server Status</span></a></div>
                    <div class="button"><a class="container shadow" href="/manager/html"><span>Manager App</span></a></div>
                    <div class="button"><a class="container shadow" href="/host-manager/html"><span>Host Manager</span></a></div>
                </div>
            </div>
            <p class="copyright">Copyright &copy;1999-2024 Apache Software Foundation.  All Rights Reserved</p>
        </div>
    </body>
</html>
`, v))
	case "/manager/html", "/manager/status", "/host-manager/html":
		realm := "Tomcat Manager Application"
		if strings.HasPrefix(p, "/host") {
			realm = "Tomcat Host Manager Application"
		}
		c.set("Cache-Control", "private", "Expires", "Thu, 01 Jan 1970 00:00:00 GMT", "WWW-Authenticate", `Basic realm="`+realm+`"`)
		c.html(401, "<!doctype html><html lang=\"en\"><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1><p>You are not authorized to view this page. If you have not changed any configuration files, please examine the file <tt>conf/tomcat-users.xml</tt> in your installation.</p></body></html>")
	case "/manager", "/manager/":
		c.redirect(302, "/manager/html")
	case "/favicon.ico":
		c.favicon("tomcat")
	default:
		c.html(404, fmt.Sprintf("<!doctype html><html lang=\"en\"><head><title>HTTP Status 404 – Not Found</title><style type=\"text/css\">body {font-family:Tahoma,Arial,sans-serif;}</style></head><body><h1>HTTP Status 404 – Not Found</h1><hr class=\"line\" /><p><b>Type</b> Status Report</p><p><b>Description</b> The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.</p><hr class=\"line\" /><h3>Apache Tomcat/%s</h3></body></html>", v))
	}
}

func appIISDefault(c *reqCtx, p string) {
	c.server()
	c.set("X-Powered-By", "ASP.NET")
	switch p {
	case "/", "/iisstart.htm":
		c.set("Last-Modified", "Sat, 14 Oct 2023 08:21:53 GMT", "Accept-Ranges", "bytes", "ETag", `"6d1a3d3a85fed91:0"`)
		c.html(200, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n<head>\r\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\" />\r\n<title>IIS Windows Server</title>\r\n<style type=\"text/css\">\r\n<!--\r\nbody {\r\n\tcolor:#000000;\r\n\tbackground-color:#0072C6;\r\n\tmargin:0;\r\n}\r\n-->\r\n</style>\r\n</head>\r\n<body>\r\n<div id=\"container\">\r\n<a href=\"http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409\"><img src=\"iisstart.png\" alt=\"IIS\" width=\"960\" height=\"600\" /></a>\r\n</div>\r\n</body>\r\n</html>")
	case "/favicon.ico":
		c.notFound()
	default:
		c.notFound()
	}
}

func appIISAspNet(c *reqCtx, p string) {
	c.server()
	c.set("X-AspNetMvc-Version", "5.2", "X-AspNet-Version", "4.0.30319", "X-Powered-By", "ASP.NET", "Cache-Control", "private")
	sess := func() {
		c.add("Set-Cookie", cookie("ASP.NET_SessionId", randAlnum(24), "path=/", "HttpOnly", "SameSite=Lax"))
	}
	lp := strings.ToLower(p)
	switch {
	case lp == "/" || lp == "/home" || lp == "/home/index":
		sess()
		c.w.Header().Set("Location", "/Account/Login?ReturnUrl=%2f")
		c.html(302, "<html><head><title>Object moved</title></head><body>\r\n<h2>Object moved to <a href=\"/Account/Login?ReturnUrl=%2f\">here</a>.</h2>\r\n</body></html>\r\n")
	case lp == "/admin" || strings.HasPrefix(lp, "/admin/"):
		c.w.Header().Set("Location", "/Account/Login?ReturnUrl=%2fadmin")
		c.html(302, "<html><head><title>Object moved</title></head><body>\r\n<h2>Object moved to <a href=\"/Account/Login?ReturnUrl=%2fadmin\">here</a>.</h2>\r\n</body></html>\r\n")
	case lp == "/account/login" || lp == "/login":
		if lp == "/login" {
			c.notFound()
			return
		}
		sess()
		c.add("Set-Cookie", cookie("__RequestVerificationToken", randAlnum(92), "path=/", "HttpOnly"))
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logowanie - %[1]s</title>
    <link href="/Content/bootstrap.css" rel="stylesheet"/>
    <script src="/Scripts/modernizr-2.8.3.js"></script>
</head>
<body>
    <div class="navbar navbar-inverse navbar-fixed-top"><div class="container"><a class="navbar-brand" href="/">%[1]s AGH</a></div></div>
    <div class="container body-content">
        <h2>Logowanie</h2>
        <form action="/Account/Login?ReturnUrl=%%2F" class="form-horizontal" method="post" role="form"><input name="__RequestVerificationToken" type="hidden" value="%[2]s" />
        <input class="form-control" id="Email" name="Email" type="text" value="" />
        <input class="form-control" id="Password" name="Password" type="password" />
        <input type="submit" value="Zaloguj" class="btn btn-default" />
        </form>
        <hr />
        <footer><p>&copy; 2024 - %[1]s AGH, wersja 3.4.1.0</p></footer>
    </div>
</body>
</html>
`, c.s.Site, randAlnum(92)))
	case lp == "/favicon.ico":
		c.favicon("aspnet-mvc")
	default:
		c.notFound()
	}
}

// ---------------------------------------------------------------- appliances

func appSynology(c *reqCtx, p string) {
	c.set("Server", "nginx", "X-Content-Type-Options", "nosniff", "X-XSS-Protection", "1; mode=block", "X-Frame-Options", "SAMEORIGIN",
		"Cache-control", "no-store", "P3P", `CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"`)
	dsm7 := strings.HasPrefix(c.s.Ver, "7")
	switch p {
	case "/", "/index.cgi", "/webman/index.cgi":
		title := strings.ToUpper(c.h.Hostname) + " - Synology DiskStation"
		if dsm7 {
			title = strings.ToUpper(c.h.Hostname) + " - Synology NAS"
		}
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html class="img-no-dragging">
<head>
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="description" content="DiskStation provides a full-featured network attached storage (NAS) solution to help you manage, backup and share data among Windows, Mac and Linux easily." />
<meta name="apple-itunes-app" content="app-id=1440331425">
<title>%s</title>
<link rel="shortcut icon" href="webman/favicon.ico?v=%d" />
<link rel="stylesheet" type="text/css" href="webman/resources/css/desktop.css?v=%d" />
<script type="text/javascript" src="webman/sso/synoSSO-1.0.0.js?v=%d"></script>
<script type="text/javascript" src="webapi/entry.cgi?api=SYNO.Core.Desktop.Defs&version=1&method=getjs&v=%d"></script>
</head>
<body><div id="sds-login-vue-inst"></div><noscript><div class="syno-noscript">JavaScript must be enabled</div></noscript></body>
</html>
`, title, 69057, 69057, 69057, 69057))
	case "/webapi/query.cgi":
		c.text(200, "application/json; charset=\"UTF-8\"", `{"data":{"SYNO.API.Auth":{"maxVersion":7,"minVersion":1,"path":"entry.cgi"}},"success":true}`)
	case "/favicon.ico", "/webman/favicon.ico":
		c.favicon("synology")
	default:
		c.notFound()
	}
}

func appMikroTik(c *reqCtx, p string) {
	v := c.s.Ver
	switch p {
	case "/":
		if strings.HasPrefix(v, "7") {
			c.html(200, fmt.Sprintf("<!doctype html>\n<html lang=en>\n<head>\n<title>RouterOS router configuration page</title>\n<meta charset=\"utf-8\">\n<link rel=\"icon\" href=\"/favicon.png\">\n<link rel=\"stylesheet\" href=\"/webfig/styles.css\">\n</head>\n<body>\n<div class=\"top\"><a href=\"https://mikrotik.com\"><img src=\"/mikrotik_logo.png\" alt=\"mikrotik\"></a></div>\n<div class=\"box\"><h1>RouterOS v%s</h1>\n<p>You have connected to a router. Administrative access only.</p>\n<a href=\"/webfig/\" class=\"button\">WebFig</a></div>\n</body>\n</html>\n", v))
			return
		}
		c.html(200, fmt.Sprintf("<html>\n<head>\n<title>RouterOS router configuration page</title>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n<link rel=\"stylesheet\" type=\"text/css\" href=\"/style.css\">\n<script src=\"/webfig/login.js\"></script>\n</head>\n<body>\n<div id=\"logo\"><img src=\"/mikrotik_logo.png\" alt=\"mikrotik\" border=\"0\"></div>\n<div class=\"box\"><h1>RouterOS v%s</h1>\n<p>You have connected to a router. Administrative access only. If this device is not in your possession, please contact your local network administrator.</p>\n<div class=\"login\"><form name=\"loginForm\" action=\"/webfig/\"><input type=\"text\" name=\"name\" value=\"admin\"><input type=\"password\" name=\"password\"><input type=\"submit\" value=\"Login\"></form></div>\n</div>\n<div class=\"footer\">&copy; mikrotik</div>\n</body>\n</html>\n", v))
	case "/webfig/", "/webfig":
		c.html(200, "<html><head><title>RouterOS</title><script src=\"/webfig/engine.js\"></script></head><body></body></html>")
	case "/favicon.ico", "/favicon.png":
		c.favicon("mikrotik")
	default:
		c.html(404, "<html><head><title>Error 404: Not Found</title></head><body><h1>Error 404: Not Found</h1></body></html>")
	}
}

func appHPPrinter(c *reqCtx, p string) {
	model := c.s.Model
	c.set("Server", "HP HTTP Server; "+model+" - W1A79A; Serial Number: CNBRM"+strings.ToUpper(randAlnum(5))+"; Built: Mon Nov 07, 2022 08:35:17PM {TETONXXXXN002.2244A.00}",
		"Cache-Control", "must-revalidate, max-age=0", "Pragma", "no-cache", "X-Frame-Options", "SAMEORIGIN", "X-XSS-Protection", "1;mode=block", "X-Content-Type-Options", "nosniff")
	switch p {
	case "/":
		c.w.Header().Set("Location", "/hp/device/info_deviceStatus.html?tab=Home&menu=DevStatus")
		c.html(302, "")
	case "/hp/device/info_deviceStatus.html", "/hp/device/DeviceStatus/Index":
		c.html(200, fmt.Sprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"pl-PL\" lang=\"pl-PL\">\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n<title>%s&nbsp;&nbsp;&nbsp;%s</title>\n<link rel=\"stylesheet\" type=\"text/css\" href=\"/hp/device/webAccess/hpStyle.css\" />\n</head>\n<body>\n<div id=\"pgHeader\"><span id=\"HomeDeviceName\">%s</span><span id=\"HomeDeviceIp\">%s</span></div>\n<div id=\"pgContent\"><h1 id=\"PageTitle\">Stan urządzenia</h1><p id=\"SupplyPLR0\">Kaseta czarna: 43%%</p></div>\n<div id=\"pgFooter\">&copy; Copyright 2022 HP Development Company, L.P.</div>\n</body>\n</html>\n", model, c.h.Hostname, model, c.ip))
	case "/favicon.ico":
		c.favicon("hp-ews")
	default:
		c.html(404, "<html><head><title>404 Not Found</title></head><body><h1>Nie znaleziono</h1></body></html>")
	}
}

func appBrother(c *reqCtx, p string) {
	c.set("Server", "debut/1.30", "Cache-Control", "no-cache", "Pragma", "no-cache")
	switch p {
	case "/":
		c.w.Header().Set("Location", "/general/status.html")
		c.html(301, "<html><head><title>301 Moved Permanently</title></head><body>Moved</body></html>")
	case "/general/status.html":
		c.add("Set-Cookie", cookie("AuthCookie", "", "path=/"))
		c.html(200, fmt.Sprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"pl\" lang=\"pl\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /><meta http-equiv=\"Content-Script-Type\" content=\"text/javascript\" /><title>Brother %s series</title><link type=\"text/css\" rel=\"stylesheet\" href=\"../common/css/common.css\" /></head><body><div id=\"frameBack\"><div id=\"header\"><h1 id=\"modelName\">%s series</h1><div id=\"login\"><form action=\"/general/status.html\" method=\"post\"><input type=\"password\" id=\"LogBox\" name=\"B12a\" /><input type=\"submit\" value=\"&gt;\" /></form></div></div><div id=\"mainContent\"><h2>Stan</h2><dl><dt>Stan urządzenia</dt><dd>Gotowa</dd></dl></div><div id=\"footer\">Copyright(C) 2000-2023 Brother Industries, Ltd. All Rights Reserved.</div></div></body></html>\n", c.s.Model, c.s.Model))
	case "/favicon.ico":
		c.favicon("brother")
	default:
		c.html(404, "<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>")
	}
}

func appHikvision(c *reqCtx, p string) {
	c.set("Server", "webserver", "X-Frame-Options", "SAMEORIGIN", "X-XSS-Protection", "1; mode=block", "X-Content-Type-Options", "nosniff", "Cache-Control", "no-cache")
	switch p {
	case "/", "/index.asp":
		c.html(200, "<!DOCTYPE html>\n<html>\n<head>\n<title></title>\n<meta http-equiv=\"Pragma\" content=\"no-cache\">\n<meta http-equiv=\"Cache-Control\" content=\"no-cache\">\n<meta http-equiv=\"Expires\" content=\"0\">\n</head>\n<body>\n<script>\nwindow.location.href = \"/doc/page/login.asp?_\" + (new Date()).getTime();\n</script>\n</body>\n</html>\n")
	case "/doc/page/login.asp":
		c.html(200, "<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n<title></title>\n<link rel=\"stylesheet\" type=\"text/css\" href=\"../css/ui.css\">\n<script type=\"text/javascript\" src=\"../script/lib/require/require.js\" data-main=\"../script/login\"></script>\n</head>\n<body>\n<div id=\"login\" class=\"login\"><div class=\"login-logo\"></div><input type=\"text\" id=\"username\" ng-model=\"username\"><input type=\"password\" id=\"password\" ng-model=\"password\"><button class=\"btn\">Login</button></div>\n</body>\n</html>\n")
	case "/ISAPI/Security/userCheck":
		c.text(401, "application/xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<userCheck><statusValue>401</statusValue><statusString>Unauthorized</statusString></userCheck>")
	case "/SDK/webLanguage":
		c.text(200, "application/xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Language><type>en</type></Language>")
	case "/favicon.ico":
		c.favicon("hikvision")
	default:
		c.html(404, "<!DOCTYPE html><html><head><title>Document Error: Page not found</title></head><body><h2>Access Error: 404 -- Not Found</h2><p>Can't locate document: "+p+"</p></body></html>")
	}
}

// ---------------------------------------------------------------- identity, VCS, observability

func appGitLab(c *reqCtx, p string) {
	c.set("Server", "nginx", "X-Content-Type-Options", "nosniff", "X-Frame-Options", "SAMEORIGIN", "X-Xss-Protection", "1; mode=block",
		"X-Download-Options", "noopen", "X-Permitted-Cross-Domain-Policies", "none", "Referrer-Policy", "strict-origin-when-cross-origin",
		"X-Request-Id", strings.ToUpper(randAlnum(26)), "X-Runtime", "0.0"+fmt.Sprint(10+len(p)%80),
		"X-Gitlab-Meta", fmt.Sprintf(`{"correlation_id":"%s","version":"1"}`, strings.ToUpper(randAlnum(26))), "Cache-Control", "no-cache",
		"Strict-Transport-Security", "max-age=63072000", "Permissions-Policy", "interest-cohort=()")
	sess := func() {
		attrs := []string{"path=/", "HttpOnly"}
		if c.scheme == "https" {
			attrs = append(attrs, "secure")
		}
		c.add("Set-Cookie", cookie("_gitlab_session", randHex(32), attrs...))
	}
	switch p {
	case "/":
		c.w.Header().Set("Location", c.base()+"/users/sign_in")
		c.html(302, "<html><body>You are being <a href=\""+c.base()+"/users/sign_in\">redirected</a>.</body></html>")
	case "/users/sign_in":
		sess()
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html class="gl-light ui-neutral with-header" lang="en">
<head prefix="og: http://ogp.me/ns#">
<meta charset="utf-8">
<meta content="IE=edge" http-equiv="X-UA-Compatible">
<meta content="width=device-width, initial-scale=1" name="viewport">
<title>Sign in · GitLab</title>
<script>
//<![CDATA[
window.gon={};gon.api_version="v4";gon.default_avatar_url="%[1]s/assets/no_avatar-849f9c04a3a0d0cea2424ae97b27447dc64a7dbfae83c036c45b403392f0e8ba.png";gon.relative_url_root="";gon.gitlab_url="%[1]s";gon.revision="%[2]s";gon.feature_category="system_access";
//]]>
</script>
<meta content="GitLab" property="og:site_name">
<meta content="Sign in · GitLab" property="og:title">
<meta content="GitLab Community Edition" property="og:description">
<link rel="stylesheet" href="%[1]s/assets/application-%[3]s.css" media="all" />
<meta name="csrf-param" content="authenticity_token" />
<meta name="csrf-token" content="%[4]s" />
</head>
<body class="login-page navless" data-page="sessions:new" data-qa-selector="login_page">
<div class="page-wrap"><div class="container"><h1 class="gl-mt-5">GitLab Community Edition</h1>
<form class="gl-show-field-errors" id="new_user" action="/users/sign_in" accept-charset="UTF-8" method="post"><input type="text" name="user[login]" id="user_login"><input type="password" name="user[password]" id="user_password"><button type="submit">Sign in</button></form>
</div></div>
</body>
</html>
`, c.base(), randHex(11), randHex(64), randAlnum(64)))
	case "/help":
		sess()
		c.html(200, "<!DOCTYPE html><html><head><title>Help · GitLab</title></head><body><h1>GitLab Community Edition</h1></body></html>")
	case "/api/v4/version":
		c.text(401, "application/json", `{"message":"401 Unauthorized"}`)
	case "/robots.txt":
		c.text(200, "text/plain", "# See http://www.robotstxt.org/robotstxt.html for documentation on how to use the robots.txt file\nUser-Agent: *\nDisallow: /autocomplete/users\nDisallow: /search\nDisallow: /admin\nDisallow: /profile\nDisallow: /dashboard\nDisallow: /users\n")
	case "/favicon.ico":
		c.favicon("gitlab")
	default:
		c.w.Header().Set("Location", c.base()+"/users/sign_in")
		c.html(302, "<html><body>You are being <a href=\""+c.base()+"/users/sign_in\">redirected</a>.</body></html>")
	}
}

func appKeycloak(c *reqCtx, p string) {
	c.set("Referrer-Policy", "no-referrer", "X-Frame-Options", "SAMEORIGIN", "X-Content-Type-Options", "nosniff",
		"X-Robots-Tag", "none", "X-XSS-Protection", "1; mode=block", "Content-Security-Policy", "frame-src 'self'; frame-ancestors 'self'; object-src 'none';")
	if c.scheme == "https" {
		c.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	res := randAlnum(5)
	switch p {
	case "/":
		c.html(200, fmt.Sprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<html>\n<head>\n    <title>Welcome to Keycloak</title>\n    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n    <meta name=\"robots\" content=\"noindex, nofollow\">\n    <link rel=\"shortcut icon\" href=\"/resources/%s/welcome/keycloak/img/favicon.ico\">\n    <link rel=\"StyleSheet\" href=\"/resources/%s/welcome/keycloak/css/welcome.css\" type=\"text/css\">\n</head>\n<body>\n<div class=\"container-fluid\">\n  <div class=\"row\">\n    <div class=\"col-sm-10 col-sm-offset-1 col-md-8 col-md-offset-2\">\n      <div class=\"welcome-header\"><img src=\"/resources/%s/welcome/keycloak/logo.png\" alt=\"Keycloak\" border=\"0\" /><h1>Welcome to <strong>Keycloak</strong></h1></div>\n      <div class=\"row\"><div class=\"col-xs-12 col-sm-4\"><div class=\"card-pf h-l\"><h3><a href=\"/admin/\"><img src=\"welcome-content/user.png\">Administration Console <i class=\"fa fa-angle-right link\" aria-hidden=\"true\"></i></a></h3><div class=\"description\">Centrally manage all aspects of the Keycloak server</div></div></div></div>\n    </div>\n  </div>\n</div>\n</body>\n</html>\n", res, res, res))
	case "/admin", "/admin/":
		c.redirect(302, c.base()+"/admin/master/console/")
	case "/admin/master/console/":
		c.html(200, "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<link rel=\"icon\" type=\"image/svg+xml\" href=\"/resources/"+res+"/admin/keycloak.v2/favicon.svg\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<meta name=\"description\" content=\"Web site to manage keycloak\">\n<title>Keycloak Administration UI</title>\n</head>\n<body><div id=\"app\"></div><noscript>JavaScript is required to use the Keycloak Administration UI.</noscript></body>\n</html>\n")
	case "/realms/master", "/auth/realms/master":
		c.text(200, "application/json", fmt.Sprintf(`{"realm":"master","public_key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA%s","token-service":"%s/realms/master/protocol/openid-connect","account-service":"%s/realms/master/account","tokens-not-before":0}`, randAlnum(48), c.base(), c.base()))
	case "/favicon.ico":
		c.favicon("keycloak")
	default:
		c.html(404, "<!DOCTYPE html><html><head><title>Keycloak</title></head><body><p>Resource not found.</p></body></html>")
	}
}

func appKibana(c *reqCtx, p string) {
	c.set("kbn-name", c.h.Hostname, "kbn-license-sig", randHex(64), "X-Content-Type-Options", "nosniff",
		"Referrer-Policy", "no-referrer-when-downgrade", "Cache-Control", "private, no-cache, no-store, must-revalidate",
		"Content-Security-Policy", "script-src 'unsafe-eval' 'self'; worker-src blob: 'self'; style-src 'unsafe-inline' 'self'")
	ver := c.s.Ver
	switch p {
	case "/":
		c.w.Header().Set("Location", "/app/home")
		c.html(302, "")
	case "/app/home", "/app/kibana", "/login":
		c.html(200, fmt.Sprintf(`<!DOCTYPE html><html lang="en"><head><meta charSet="utf-8"/><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/><meta name="viewport" content="width=device-width"/><title>Elastic</title><link rel="icon" type="image/png" href="/ui/favicons/favicon.png"/><meta name="theme-color" content="#ffffff"/><meta name="color-scheme" content="light dark"/></head><body><kbn-csp data="{&quot;strictCsp&quot;:false}"></kbn-csp><kbn-injected-metadata data="{&quot;version&quot;:&quot;%[1]s&quot;,&quot;buildNumber&quot;:%[2]d,&quot;branch&quot;:&quot;%[3]s&quot;,&quot;basePath&quot;:&quot;&quot;,&quot;serverBasePath&quot;:&quot;&quot;,&quot;env&quot;:{&quot;mode&quot;:{&quot;name&quot;:&quot;production&quot;,&quot;dev&quot;:false,&quot;prod&quot;:true},&quot;packageInfo&quot;:{&quot;branch&quot;:&quot;%[3]s&quot;,&quot;buildNum&quot;:%[2]d,&quot;version&quot;:&quot;%[1]s&quot;,&quot;dist&quot;:true}}}"></kbn-injected-metadata><div class="kbnWelcomeView" id="kbn_loading_message"><div class="kbnWelcomeText">Please upgrade your browser</div></div><div id="kibana-body" data-test-subj="kibanaBody"></div><script src="/bootstrap.js"></script></body></html>`, ver, 46534, ver[:strings.LastIndex(ver, ".")]))
	case "/api/status":
		c.text(200, "application/json; charset=utf-8", fmt.Sprintf(`{"name":"%s","uuid":"%s","version":{"number":"%s","build_hash":"%s","build_number":46534,"build_snapshot":false},"status":{"overall":{"level":"available","summary":"All services are available"}}}`, c.h.Hostname, randHex(32), ver, randHex(40)))
	case "/favicon.ico", "/ui/favicons/favicon.png":
		c.favicon("kibana")
	default:
		c.text(404, "application/json; charset=utf-8", `{"statusCode":404,"error":"Not Found","message":"Not Found"}`)
	}
}

func appElasticsearch(c *reqCtx, p string) {
	ver := c.s.Ver
	c.set("X-elastic-product", "Elasticsearch")
	if strings.HasPrefix(ver, "8") {
		c.set("WWW-Authenticate", `Basic realm="security" charset="UTF-8"`, "WWW-Authenticate", `ApiKey`)
		c.text(401, "application/json; charset=UTF-8", `{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication credentials for REST request [`+p+`]","header":{"WWW-Authenticate":["Basic realm=\"security\" charset=\"UTF-8\"","ApiKey"]}}],"type":"security_exception","reason":"missing authentication credentials for REST request [`+p+`]"},"status":401}`)
		return
	}
	switch p {
	case "/":
		c.text(200, "application/json; charset=UTF-8", fmt.Sprintf(`{
  "name" : "%s",
  "cluster_name" : "agh-logs",
  "cluster_uuid" : "%s",
  "version" : {
    "number" : "%s",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "%s",
    "build_date" : "2023-01-31T05:34:43.305517834Z",
    "build_snapshot" : false,
    "lucene_version" : "8.11.1",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
`, c.h.Hostname, randAlnum(22), ver, randHex(40)))
	default:
		c.text(400, "application/json; charset=UTF-8", `{"error":"no handler found for uri [`+p+`] and method [GET]"}`)
	}
}

func appPrometheus(c *reqCtx, p string) {
	switch p {
	case "/":
		c.w.Header().Set("Location", "/graph")
		c.html(302, "<a href=\"/graph\">Found</a>.\n\n")
	case "/graph":
		c.html(200, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"./favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta name=\"theme-color\" content=\"#000000\"/><script>const GLOBAL_CONSOLES_LINK=\"\",GLOBAL_AGENT_MODE=\"false\",GLOBAL_READY=\"true\"</script><link rel=\"manifest\" href=\"./manifest.json\" crossorigin=\"use-credentials\"/><title>Prometheus Time Series Collection and Processing Server</title><script defer=\"defer\" src=\"./static/js/main."+randHex(8)+".js\"></script></head><body class=\"bootstrap\"><noscript>You need to enable JavaScript to run this app.</noscript><div id=\"root\"></div></body></html>")
	case "/metrics":
		c.text(200, "text/plain; version=0.0.4; charset=utf-8", fmt.Sprintf("# HELP prometheus_build_info A metric with a constant '1' value labeled by version, revision, branch, goversion from which prometheus was built, and the goos and goarch for the build.\n# TYPE prometheus_build_info gauge\nprometheus_build_info{branch=\"HEAD\",goarch=\"amd64\",goos=\"linux\",goversion=\"go1.20.5\",revision=\"%s\",tags=\"netgo,builtinassets,stringlabels\",version=\"%s\"} 1\n", randHex(40), c.s.Ver))
	case "/api/v1/status/buildinfo":
		c.text(200, "application/json", fmt.Sprintf(`{"status":"success","data":{"version":"%s","revision":"%s","branch":"HEAD","buildUser":"root@buildhost","buildDate":"20230623-15:09:49","goVersion":"go1.20.5"}}`, c.s.Ver, randHex(40)))
	case "/favicon.ico":
		c.favicon("prometheus")
	default:
		c.text(404, "text/plain; charset=utf-8", "404 page not found\n")
	}
}

func appZabbix(c *reqCtx, p string) {
	c.server()
	c.poweredByPHP()
	switch p {
	case "/", "/index.php", "/zabbix/", "/zabbix/index.php":
		c.add("Set-Cookie", cookie("zbx_session", randAlnum(120)+"%3D%3D", "expires="+time.Now().Add(30*24*time.Hour).UTC().Format(http.TimeFormat), "Max-Age=2592000", "path=/", "HttpOnly"))
		c.set("X-Content-Type-Options", "nosniff", "X-XSS-Protection", "1; mode=block", "X-Frame-Options", "SAMEORIGIN")
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html lang="pl">
	<head>
		<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<meta name="Author" content="Zabbix SIA" />
		<title>%s: Zabbix</title>
		<link rel="icon" href="favicon.ico">
		<link rel="apple-touch-icon-precomposed" sizes="76x76" href="assets/img/apple-touch-icon-76x76-precomposed.png">
		<link rel="stylesheet" type="text/css" href="assets/styles/blue-theme.css?1700000000" />
	</head>
	<body>
<div class="wrapper"><main><div class="signin-container"><div class="signin-logo"></div><form method="post" action="index.php" accept-charset="utf-8"><ul><li><label for="name">Nazwa użytkownika</label><input type="text" id="name" name="name" value="" maxlength="255" autofocus="autofocus"></li><li><label for="password">Hasło</label><input type="password" id="password" name="password" value="" maxlength="255"></li><li><button type="submit" id="enter" name="enter" value="Sign in">Zaloguj</button></li></ul></form></div><div class="signin-links"><a target="_blank" class="grey link-alt" href="https://www.zabbix.com/documentation/%s/">Pomoc</a>&nbsp;&nbsp;•&nbsp;&nbsp;<a target="_blank" class="grey link-alt" href="https://www.zabbix.com/support">Wsparcie</a></div></main><footer role="contentinfo">&copy; 2001&ndash;2023, <a class="grey link-alt" target="_blank" rel="noopener noreferrer" href="https://www.zabbix.com/">Zabbix SIA</a></footer></div></body></html>
`, "Monitoring CBI", c.s.Ver))
	case "/favicon.ico":
		c.favicon("zabbix")
	default:
		c.notFound()
	}
}

func appRoundcube(c *reqCtx, p string) {
	c.server()
	c.poweredByPHP()
	rv := strings.ReplaceAll(c.s.Ver, ".", "0")
	switch p {
	case "/", "/index.php", "/?_task=login":
		attrs := []string{"path=/", "HttpOnly"}
		if c.scheme == "https" {
			attrs = append(attrs, "secure")
		}
		c.add("Set-Cookie", cookie("roundcube_sessid", randAlnum(26), attrs...))
		c.set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT", "Last-Modified", time.Now().UTC().Format(http.TimeFormat),
			"Cache-Control", "private, no-cache, no-store, must-revalidate, post-check=0, pre-check=0", "Pragma", "no-cache",
			"X-Frame-Options", "sameorigin", "Content-Language", "pl")
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="utf-8">
<meta name="viewport" content="" id="viewport">
<link rel="shortcut icon" href="skins/elastic/images/favicon.ico">
<link rel="stylesheet" href="skins/elastic/deps/bootstrap.min.css?s=1700000000">
<title>Poczta CBI AGH :: Witamy w Poczta CBI AGH</title>
<script src="program/js/jquery.min.js?s=1700000000"></script>
<script>
var rcmail = new rcube_webmail();
rcmail.set_env({"task":"login","standard_windows":false,"locale":"pl_PL","devel_mode":null,"rcversion":%s,"cookie_domain":"","cookie_path":"/","cookie_secure":%t,"skin":"elastic","refresh_interval":60,"session_lifetime":600,"action":"","comm_path":"./?_task=login","compose_extwin":false,"date_format":"yy-mm-dd","request_token":"%s"});
</script>
</head>
<body class="task-login action-none">
<div id="layout"><h1 class="voice">Poczta CBI AGH Logowanie</h1><div id="layout-content" class="selected no-navbar" role="main"><img src="skins/elastic/images/logo.svg" id="logo" alt="Logo"><form id="login-form" name="login-form" method="post" class="propform" action="./?_task=login"><input type="hidden" name="_task" value="login"><input name="_user" id="rcmloginuser" required size="40" autocapitalize="off" autocomplete="off" type="text"><input name="_pass" id="rcmloginpwd" required size="40" autocapitalize="off" autocomplete="off" type="password"><button type="submit" id="rcmloginsubmit" class="button mainaction submit">Zaloguj</button></form></div><div id="login-footer" role="contentinfo">Poczta CBI AGH</div></div>
</body>
</html>
`, rv, c.scheme == "https", randAlnum(32)))
	case "/favicon.ico":
		c.favicon("roundcube")
	default:
		c.notFound()
	}
}

// ---------------------------------------------------------------- app frameworks / staging

func appExpress(c *reqCtx, p string) {
	c.set("X-Powered-By", "Express")
	sess := func() {
		c.add("Set-Cookie", cookie("connect.sid", "s%3A"+randAlnum(32)+"."+randAlnum(43), "Path=/", "HttpOnly"))
	}
	title := c.s.Site + " [STAGING]"
	switch p {
	case "/":
		sess()
		c.set("ETag", `W/"`+randHex(4)+`-`+randAlnum(27)+`"`)
		c.html(200, fmt.Sprintf(`<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <title>%[1]s</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/stylesheets/style.css">
</head>
<body>
  <div class="env-banner" style="background:#f0ad4e">ŚRODOWISKO TESTOWE (staging) – dane nieprodukcyjne, build 1.12.0-rc.3</div>
  <h1>%[2]s</h1>
  <p><a href="/login">Zaloguj się</a></p>
  <footer>%[2]s staging &middot; api: http://staging-api.lab.agh.local:4000 &middot; v1.12.0-rc.3</footer>
</body>
</html>
`, title, c.s.Site))
	case "/login":
		sess()
		c.html(200, "<!DOCTYPE html><html><head><title>Logowanie - "+title+"</title></head><body><div class=\"env-banner\">ŚRODOWISKO TESTOWE</div><form method=\"post\" action=\"/login\"><input name=\"username\"><input type=\"password\" name=\"password\"><button>Zaloguj</button></form><!-- TODO: remove test account test/test123 before prod --></body></html>")
	case "/admin":
		c.w.Header().Set("Location", "/login")
		c.text(302, "text/plain; charset=utf-8", "Found. Redirecting to /login")
	case "/health":
		c.text(200, "application/json; charset=utf-8", `{"status":"ok","env":"staging","uptime":`+fmt.Sprint(3600+len(c.ip)*37)+`}`)
	case "/api/version", "/version":
		c.text(200, "application/json; charset=utf-8", `{"version":"1.12.0-rc.3","commit":"`+randHex(7)+`","env":"staging","node":"v18.19.0"}`)
	default:
		c.set("Content-Security-Policy", "default-src 'none'", "X-Content-Type-Options", "nosniff")
		c.html(404, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot GET "+p+"</pre>\n</body>\n</html>\n")
	}
}

func appSpring(c *reqCtx, p string) {
	wantsHTML := strings.Contains(c.r.Header.Get("Accept"), "text/html")
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000+00:00")
	switch p {
	case "/actuator", "/actuator/":
		c.text(200, "application/vnd.spring-boot.actuator.v3+json", fmt.Sprintf(`{"_links":{"self":{"href":"%[1]s/actuator","templated":false},"health":{"href":"%[1]s/actuator/health","templated":false},"info":{"href":"%[1]s/actuator/info","templated":false}}}`, c.base()))
	case "/actuator/health":
		c.text(200, "application/vnd.spring-boot.actuator.v3+json", `{"status":"UP"}`)
	case "/actuator/info":
		prof := "prod"
		if c.s.Staging {
			prof = "dev"
		}
		c.text(200, "application/vnd.spring-boot.actuator.v3+json", fmt.Sprintf(`{"app":{"name":"%s","version":"%s","profile":"%s"},"build":{"artifact":"%s","group":"pl.edu.agh","version":"%s"}}`, c.s.Site, c.s.Ver, prof, c.s.Site, c.s.Ver))
	default:
		c.set("Vary", "Origin", "Vary", "Access-Control-Request-Method")
		if wantsHTML {
			c.html(404, fmt.Sprintf("<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p><div id='created'>%s</div><div>There was an unexpected error (type=Not Found, status=404).</div></body></html>", time.Now().Format(time.UnixDate)))
			return
		}
		c.text(404, "application/json", fmt.Sprintf(`{"timestamp":"%s","status":404,"error":"Not Found","path":"%s"}`, ts, p))
	}
}

func appDjango(c *reqCtx, p string) {
	c.server()
	c.set("X-Frame-Options", "DENY", "X-Content-Type-Options", "nosniff", "Referrer-Policy", "same-origin", "Cross-Origin-Opener-Policy", "same-origin", "Vary", "Cookie")
	switch p {
	case "/":
		c.html(200, "<!doctype html>\n<html lang=\"en-us\" dir=\"ltr\">\n    <head>\n        <meta charset=\"utf-8\">\n        <title>The install worked successfully! Congratulations!</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n    </head>\n    <body>\n        <header class=\"u-clearfix\"><div class=\"logo\"><a href=\"https://www.djangoproject.com/\" target=\"_blank\" rel=\"noopener\"></a></div><div class=\"release-notes\"><p>View <a href=\"https://docs.djangoproject.com/en/4.2/releases/\" target=\"_blank\" rel=\"noopener\">release notes</a> for Django 4.2</p></div></header>\n        <main><h1>The install worked successfully! Congratulations!</h1><p>You are seeing this page because <a href=\"https://docs.djangoproject.com/en/4.2/ref/settings/#debug\" target=\"_blank\" rel=\"noopener\">DEBUG=True</a> is in your settings file and you have not configured any URLs.</p></main>\n    </body>\n</html>\n")
	case "/admin", "/admin/":
		if p == "/admin" {
			c.redirect(301, "/admin/")
			return
		}
		c.w.Header().Set("Location", "/admin/login/?next=/admin/")
		c.set("Expires", time.Now().UTC().Format(http.TimeFormat), "Cache-Control", "max-age=0, no-cache, no-store, must-revalidate, private")
		c.html(302, "")
	case "/admin/login/":
		c.add("Set-Cookie", cookie("csrftoken", randAlnum(32), "expires="+time.Now().Add(365*24*time.Hour).UTC().Format(http.TimeFormat), "Max-Age=31449600", "Path=/", "SameSite=Lax"))
		c.html(200, "<!DOCTYPE html>\n<html lang=\"en-us\" dir=\"ltr\">\n<head>\n<title>Log in | Django site admin</title>\n<link rel=\"stylesheet\" href=\"/static/admin/css/base.css\">\n<meta name=\"robots\" content=\"NONE,NOARCHIVE\">\n</head>\n<body class=\" login\" data-admin-utc-offset=\"0\">\n<div id=\"container\"><div id=\"header\"><div id=\"branding\"><div id=\"site-name\"><a href=\"/admin/\">Django administration</a></div></div></div>\n<div id=\"content\" class=\"colM\"><form action=\"/admin/login/?next=/admin/\" method=\"post\" id=\"login-form\"><input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\""+randAlnum(64)+"\"><input type=\"text\" name=\"username\" autofocus autocapitalize=\"none\" autocomplete=\"username\" maxlength=\"150\" required id=\"id_username\"><input type=\"password\" name=\"password\" autocomplete=\"current-password\" required id=\"id_password\"><input type=\"submit\" value=\"Log in\"></form></div></div>\n</body>\n</html>\n")
	default:
		c.html(404, fmt.Sprintf("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\">\n  <title>Page not found at %s</title>\n  <meta name=\"robots\" content=\"NONE,NOARCHIVE\">\n</head>\n<body>\n  <div id=\"summary\">\n    <h1>Page not found <span>(404)</span></h1>\n    <table class=\"meta\"><tr><th>Request Method:</th><td>GET</td></tr><tr><th>Request URL:</th><td>%s%s</td></tr></table>\n  </div>\n  <div id=\"info\">\n    <p>Using the URLconf defined in <code>config.urls</code>, Django tried these URL patterns, in this order:</p>\n    <ol><li>admin/</li><li>api/</li></ol>\n    <p>The current path, <code>%s</code>, didn’t match any of these.</p>\n  </div>\n  <div id=\"explanation\"><p>You’re seeing this error because you have <code>DEBUG = True</code> in your Django settings file. Change that to <code>False</code>, and Django will display a standard 404 page.</p></div>\n</body>\n</html>\n", p, c.base(), p, strings.TrimPrefix(p, "/")))
	}
}

func appCustomAdmin(c *reqCtx, p string) {
	c.server()
	c.set("X-Powered-By", "PHP/7.4.3")
	sess := func() { c.add("Set-Cookie", cookie("PHPSESSID", randAlnum(26), "path=/")) }
	switch p {
	case "/", "/index.php":
		sess()
		c.set("Expires", "Thu, 19 Nov 1981 08:52:00 GMT", "Cache-Control", "no-store, no-cache, must-revalidate", "Pragma", "no-cache")
		c.html(200, fmt.Sprintf("<!DOCTYPE html>\n<html lang=\"pl\">\n<head><meta charset=\"utf-8\"><title>%[1]s</title><link rel=\"stylesheet\" href=\"/assets/css/app.css?v=%[2]s\"></head>\n<body>\n<nav><a href=\"/\">Start</a> | <a href=\"/admin\">Administracja</a></nav>\n<h1>%[1]s</h1>\n<p>System wewnętrzny CBI AGH. Dostęp wyłącznie dla upoważnionych pracowników.</p>\n<footer>%[1]s v%[2]s &copy; 2024 CBI AGH</footer>\n</body>\n</html>\n", c.s.Site, c.s.Ver))
	case "/admin", "/admin/", "/login", "/admin/login.php":
		sess()
		c.html(200, fmt.Sprintf("<!DOCTYPE html>\n<html lang=\"pl\">\n<head><meta charset=\"utf-8\"><title>Panel administracyjny – %[1]s</title></head>\n<body class=\"login\">\n<h1>Panel administracyjny</h1>\n<form method=\"post\" action=\"/admin/login.php\"><label>Login <input name=\"login\"></label><label>Hasło <input type=\"password\" name=\"haslo\"></label><button type=\"submit\">Zaloguj</button></form>\n<footer>%[1]s v%[2]s</footer>\n</body>\n</html>\n", c.s.Site, c.s.Ver))
	case "/favicon.ico":
		c.favicon("agh-custom-admin")
	default:
		c.notFound()
	}
}

func appTestApache(c *reqCtx, p string) {
	c.server()
	c.poweredByPHP()
	switch p {
	case "/", "/index.php":
		c.add("Set-Cookie", cookie("PHPSESSID", randAlnum(26), "path=/"))
		c.html(200, fmt.Sprintf("<!DOCTYPE html>\n<html lang=\"pl\">\n<head><meta charset=\"utf-8\"><title>TEST - %[1]s</title></head>\n<body>\n<div style=\"background:red;color:white;padding:4px\">UWAGA: Środowisko testowe. Dane mogą być usuwane bez ostrzeżenia.</div>\n<h1>%[1]s (wersja testowa)</h1>\n<p><a href=\"/login\">Logowanie</a></p>\n<!-- db: test-db01.lab.agh.local user=app_test -->\n</body>\n</html>\n", c.s.Site))
	case "/login":
		c.add("Set-Cookie", cookie("PHPSESSID", randAlnum(26), "path=/"))
		c.html(200, "<!DOCTYPE html><html lang=\"pl\"><head><title>TEST - Logowanie</title></head><body><form method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pass\"></form></body></html>")
	case "/phpinfo.php":
		c.html(200, "<!DOCTYPE html><html><head><title>PHP 7.4.33 - phpinfo()</title></head><body><h1 class=\"p\">PHP Version 7.4.33</h1></body></html>")
	default:
		c.notFound()
	}
}

func appCUPS(c *reqCtx, p string) {
	v := c.s.Ver
	c.set("Server", "CUPS/"+v+" IPP/2.1", "X-Frame-Options", "DENY", "Content-Security-Policy", "frame-ancestors 'none'", "Content-Language", "en_US",
		"Cache-Control", "no-cache", "Accept-Encoding", "gzip, deflate, identity")
	switch p {
	case "/":
		c.html(200, fmt.Sprintf("<!DOCTYPE HTML>\n<html>\n  <head>\n    <link rel=\"stylesheet\" href=\"/cups.css\" type=\"text/css\">\n    <link rel=\"shortcut icon\" href=\"/apple-touch-icon.png\" type=\"image/png\">\n    <meta charset=\"utf-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n    <title>Home - CUPS %s.2</title>\n  </head>\n  <body>\n    <div class=\"header\">\n      <ul>\n\t<li><a href=\"http://www.cups.org/\" target=\"_blank\">CUPS.org</a></li>\n\t<li><a class=\"active\" href=\"/\">Home</a></li>\n\t<li><a href=\"/admin\">Administration</a></li>\n\t<li><a href=\"/classes/\">Classes</a></li>\n\t<li><a href=\"/printers/\">Printers</a></li>\n      </ul>\n    </div>\n    <div class=\"body\">\n      <div class=\"row\"><h1>CUPS %s.2</h1><p>CUPS is the standards-based, open source printing system developed by <a href=\"https://www.apple.com/\">Apple Inc.</a> for macOS<sup>&reg;</sup> and other UNIX<sup>&reg;</sup>-like operating systems.</p></div>\n    </div>\n    <div class=\"footer\">Copyright &copy; 2021-2023 OpenPrinting. All rights reserved.</div>\n  </body>\n</html>\n", v, v))
	case "/admin", "/admin/":
		c.html(403, "<!DOCTYPE HTML>\n<html>\n  <head>\n    <title>Forbidden - CUPS "+v+".2</title>\n  </head>\n  <body>\n    <h1>Forbidden</h1>\n  </body>\n</html>\n")
	default:
		c.html(404, "<!DOCTYPE HTML>\n<html><head><title>Not Found - CUPS "+v+".2</title></head><body><h1>Not Found</h1></body></html>\n")
	}
}

func appIDRAC(c *reqCtx, p string) {
	c.set("X-Frame-Options", "SAMEORIGIN", "Strict-Transport-Security", "max-age=63072000", "X-Content-Type-Options", "nosniff",
		"X-XSS-Protection", "1; mode=block", "Cache-Control", "no-store,no-cache")
	start := "/restgui/start.html"
	title := "iDRAC9"
	if c.s.Ver == "8" {
		start, title = "/start.html", "Integrated Remote Access Controller 8"
	}
	switch p {
	case "/":
		c.w.Header().Set("Location", start)
		c.html(302, "")
	case "/restgui/start.html", "/start.html", "/login.html":
		c.html(200, "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>"+title+"</title>\n<link rel=\"shortcut icon\" href=\"/images/favicon.ico\">\n</head>\n<body ng-app=\"loginapp\"><div class=\"login-header\">Integrated Dell Remote Access Controller "+c.s.Ver+"</div><div class=\"login-form\"><input id=\"username\"><input id=\"password\" type=\"password\"></div></body>\n</html>\n")
	case "/favicon.ico", "/images/favicon.ico":
		c.favicon("idrac")
	default:
		c.html(404, "<html><head><title>404 - Not Found</title></head><body><h1>404 - Not Found</h1></body></html>")
	}
}
