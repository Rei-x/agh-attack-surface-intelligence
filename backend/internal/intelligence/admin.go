package intelligence

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

// An admin panel is an unauthenticated management console or the login page of an admin
// tool reachable over HTTP: CMS back-ends (wp-login.php, Joomla /administrator/), dev/ops
// consoles (Jenkins, Grafana, Kibana, Zabbix, phpMyAdmin, Adminer, Portainer, Tomcat
// manager, Keycloak admin console), device management UIs of routers, NAS and BMCs, and
// custom /admin consoles. A login form on its own is not an admin panel: GitLab, Roundcube,
// Moodle, Drupal /user/login and ASP.NET /Account/Login are end-user logins, and almost
// every app redirects /admin to its generic login, so redirects never count either. Only
// evidence the console itself put on the wire decides.

const minAdminToolConfidence = 50

// adminTools are technologies (canonical names from the built-in signatures) whose
// web UI is a management console by definition.
var adminTools = map[string]bool{
	"jenkins":                           true,
	"grafana":                           true,
	"kibana":                            true,
	"zabbix":                            true,
	"phpmyadmin":                        true,
	"adminer":                           true,
	"portainer":                         true,
	"mikrotik routeros":                 true, // router configuration (WebFig)
	"synology dsm":                      true, // NAS management (DSM)
	"server bmc (dell idrac / hpe ilo)": true, // out-of-band server management
	"exposed docker engine api":         true,
	"unfinished web installer":          true, // whoever opens it first becomes the administrator
	"rabbitmq management":               true,
	"nginx proxy manager":               true,
	"traefik dashboard / api":           true,
	"toxiproxy api":                     true,
}

var (
	reAdminTitle      = regexp.MustCompile(`(?i)\b(admin\w*|management console|control panel|backoffice|back-office|webmin|cpanel|plesk|router configuration|configuration utility|panel administracyjny|panel sterowania|zarządzanie)\b`)
	reAdminRealm      = regexp.MustCompile(`(?i)realm\s*=\s*"[^"]*(admin|manager|management|console|router|configuration|webmin)`)
	reKeycloakConsole = regexp.MustCompile(`(?i)Welcome to Keycloak|Keycloak Administration|Administration Console`)
	adminPaths        = map[string]bool{"/admin": true, "/admin/": true, "/administrator": true, "/administrator/": true, "/admin/login": true, "/admin/login.php": true}
)

// AdminPanelEvidence returns why a service is an admin panel ("" = it is not).
func AdminPanelEvidence(obs domain.ObservedService, techs []domain.DetectedTechnology) string {
	fp := obs.HTTP
	if fp == nil {
		return ""
	}
	has := func(name string) bool {
		for _, t := range techs {
			if strings.EqualFold(t.Name, name) && t.Confidence >= minAdminToolConfidence {
				return true
			}
		}
		return false
	}
	hit := func(path string, codes ...int) *domain.SafePathHit {
		for i := range fp.SafePathHits {
			h := &fp.SafePathHits[i]
			if !strings.EqualFold(strings.TrimRight(h.Path, "/"), strings.TrimRight(path, "/")) {
				continue
			}
			for _, c := range codes {
				if h.StatusCode == c {
					return h
				}
			}
		}
		return nil
	}

	// 1. Admin tools identified by their own UI.
	for _, t := range techs {
		if adminTools[strings.ToLower(t.Name)] && t.Confidence >= minAdminToolConfidence {
			return "admin tool: " + t.Name
		}
	}

	// 2. Tools whose console sits at a well-known path: require the console response.
	if has("Apache Tomcat") {
		if h := hit("/manager/html", 401, 200); h != nil {
			return "Tomcat manager reachable (/manager/html " + strconv.Itoa(h.StatusCode) + ")"
		}
	}
	if has("WordPress") {
		if h := hit("/wp-login.php", 200); h != nil && (h.LoginForm || strings.Contains(strings.ToLower(h.Title), "wordpress")) {
			return "WordPress login (/wp-login.php)"
		}
		if strings.Contains(strings.ToLower(fp.URL), "/wp-login.php") && fp.LoginForm {
			return "WordPress login (/wp-login.php)"
		}
	}
	if has("Joomla") {
		if h := hit("/administrator/", 200); h != nil && h.LoginForm {
			return "Joomla administrator login (/administrator/)"
		}
	}
	if has("Keycloak") {
		if fp.StatusCode == 200 && reKeycloakConsole.MatchString(fp.Title+"\n"+fp.BodySnippet) {
			return "Keycloak admin console linked from welcome page"
		}
		if h := hit("/admin", 200, 301, 302); h != nil && strings.Contains(h.Snippet, "/admin/master/console") {
			return "Keycloak admin console (/admin)"
		}
	}

	// 3. Generic consoles.
	if fp.StatusCode == 200 && reAdminTitle.MatchString(fp.Title) {
		return "admin page title: " + fp.Title
	}
	for _, h := range fp.SafePathHits {
		switch {
		case h.StatusCode == 200 && reAdminTitle.MatchString(h.Title):
			return "admin page title at " + h.Path + ": " + h.Title
		case h.StatusCode == 200 && h.LoginForm && adminPaths[strings.ToLower(h.Path)]:
			return "login form served at " + h.Path
		case h.StatusCode == 401 && h.AuthChallenge != "" && (adminPaths[strings.ToLower(h.Path)] || reAdminRealm.MatchString(h.AuthChallenge)):
			return "HTTP auth protected admin area " + h.Path + " (" + h.AuthChallenge + ")"
		}
	}
	if fp.StatusCode == 401 {
		if ch := headerCI(fp.Headers, "WWW-Authenticate"); ch != "" && reAdminRealm.MatchString(ch) {
			return "HTTP auth protected admin console (" + ch + ")"
		}
	}
	return ""
}

var (
	// JSON health/version/info endpoints that state a non-production environment:
	// {"env":"staging"}, {"profile":"dev"}, {"spring.profiles.active":"test"}, NODE_ENV=development
	reEnvJSON = regexp.MustCompile(`(?i)"(env|environment|profile|profiles|spring\.profiles\.active|node_env|app_env|rails_env|stage)"\s*:\s*\[?\s*"(staging|stage|dev|develop|development|test|testing|qa|uat|sandbox|preprod|pre-prod)"`)
	// Debug pages only a development configuration renders.
	reDebugPage = regexp.MustCompile(`(?i)DEBUG\s*=\s*True|Werkzeug Debugger|Traceback \(most recent call last\)|Symfony Profiler|Whoops! There was an error|sf-toolbar`)
	// Development servers that must not face a network: Django runserver (wsgiref
	// "WSGIServer/0.2 CPython/3.x"), Flask/Werkzeug dev server, webpack/vite dev servers.
	reDevServer = regexp.MustCompile(`(?i)^(WSGIServer/|Werkzeug/|webpack-dev-server|vite)`)
)

// StagingEvidence returns why a service looks like a non-production (staging / dev /
// test / debug) environment beyond the title/URL signatures ("" = no extra evidence).
func StagingEvidence(obs domain.ObservedService) string {
	fp := obs.HTTP
	if fp == nil {
		return ""
	}
	if reDevServer.MatchString(fp.ServerHeader) {
		return "development server: " + fp.ServerHeader
	}
	if reDebugPage.MatchString(fp.BodySnippet) {
		return "debug page"
	}
	if m := reEnvJSON.FindString(fp.BodySnippet); m != "" {
		return "environment disclosed: " + m
	}
	for _, h := range fp.SafePathHits {
		if h.StatusCode != 200 {
			continue
		}
		if m := reEnvJSON.FindString(h.Snippet); m != "" {
			return "environment disclosed at " + h.Path + ": " + m
		}
	}
	return ""
}

// Stock web-server welcome pages call themselves "Test Page" ("Apache HTTP Server Test Page
// powered by CentOS", "Test Page for the Nginx HTTP Server on Fedora"); that is a default
// install, not a test environment.
var reDefaultTestPage = regexp.MustCompile(`(?i)\btest page\b`)

// dropDefaultTestPageStaging removes a staging match whose only evidence is the title of a
// stock "Test Page".
func dropDefaultTestPageStaging(matches []signatures.MatchResult, obs domain.ObservedService) []signatures.MatchResult {
	if obs.HTTP == nil || !reDefaultTestPage.MatchString(obs.HTTP.Title) {
		return matches
	}
	out := matches[:0]
	for _, m := range matches {
		if m.Matched && m.Signature.Category == "staging" && len(m.Evidence) == 1 && strings.HasPrefix(m.Evidence[0].Detail, "title") {
			continue
		}
		out = append(out, m)
	}
	return out
}
