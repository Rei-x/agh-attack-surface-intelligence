package intelligence

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

func enrich(obs domain.ObservedService) domain.Service {
	svc := domain.Service{Port: obs.Port, ServiceName: obs.ServiceName, Product: obs.Product, HTTP: obs.HTTP}
	EnrichService(&svc, obs, signatures.NewEngine(nil), 1)
	return svc
}

func httpSvc(port int, fp *domain.HTTPFingerprint) domain.ObservedService {
	return domain.ObservedService{Port: port, Protocol: "tcp", State: "open", ServiceName: "http", HTTP: fp}
}

// Fixtures below reproduce what the real products send (titles, headers, cookies,
// status codes of the probed paths).
func TestAdminPanelRealProducts(t *testing.T) {
	cases := []struct {
		name  string
		obs   domain.ObservedService
		admin bool
	}{
		{"WordPress with reachable wp-login.php", httpSvc(80, &domain.HTTPFingerprint{
			StatusCode: 200, Title: "Wydział IET – Akademia Górniczo-Hutnicza", MetaGenerator: "WordPress 6.4.3",
			ServerHeader: "Apache/2.4.57 (Debian)",
			BodySnippet:  `<link rel='stylesheet' href='/wp-content/themes/twentytwentyfour/style.css?ver=1.0' />`,
			SafePathHits: []domain.SafePathHit{
				{Path: "/admin", StatusCode: 302, Snippet: "Location: http://10.0.0.5/wp-admin/"},
				{Path: "/login", StatusCode: 302, Snippet: "Location: http://10.0.0.5/wp-login.php"},
				{Path: "/wp-login.php", StatusCode: 200, Title: "Zaloguj się ‹ Wydział IET — WordPress", LoginForm: true},
			},
		}), true},
		{"Joomla administrator login", httpSvc(80, &domain.HTTPFingerprint{
			StatusCode: 200, Title: "Strona główna - Koło naukowe", MetaGenerator: "Joomla! - Open Source Content Management",
			SafePathHits: []domain.SafePathHit{{Path: "/administrator/", StatusCode: 200, Title: "Koło naukowe - Administracja", LoginForm: true}},
		}), true},
		{"Jenkins 403 + X-Jenkins", httpSvc(8080, &domain.HTTPFingerprint{
			StatusCode: 403, ServerHeader: "Jetty(10.0.18)",
			Headers: map[string]string{"X-Jenkins": "2.426.3", "X-Hudson": "1.395", "X-Required-Permission": "hudson.model.Hudson.Read"},
		}), true},
		{"Grafana login", httpSvc(3000, &domain.HTTPFingerprint{
			StatusCode: 200, URL: "http://10.0.0.7:3000/login", Title: "Grafana",
			BodySnippet: `<script nonce="">window.grafanaBootData = {settings: {"buildInfo":{"version":"10.2.3"}}}</script>`,
		}), true},
		{"Tomcat manager behind Basic auth", httpSvc(8080, &domain.HTTPFingerprint{
			StatusCode: 200, Title: "Apache Tomcat/9.0.83",
			SafePathHits: []domain.SafePathHit{{Path: "/manager/html", StatusCode: 401, Title: "401 Unauthorized",
				AuthChallenge: `Basic realm="Tomcat Manager Application"`}},
		}), true},
		{"Tomcat with manager restricted to localhost (403)", httpSvc(8080, &domain.HTTPFingerprint{
			StatusCode: 200, Title: "Apache Tomcat/9.0.83",
			SafePathHits: []domain.SafePathHit{{Path: "/manager/html", StatusCode: 403, Title: "403 Access Denied"}},
		}), false},
		{"Keycloak welcome page", httpSvc(8080, &domain.HTTPFingerprint{
			StatusCode: 200, Title: "Welcome to Keycloak",
			BodySnippet: `<h3><a href="/admin/">Administration Console</a></h3><div class="description">Centrally manage all aspects of the Keycloak server</div>`,
		}), true},
		{"custom PHP admin at /admin", httpSvc(80, &domain.HTTPFingerprint{
			StatusCode: 200, Title: "System Rezerwacji Sal", ServerHeader: "Apache/2.4.41 (Ubuntu)",
			SafePathHits: []domain.SafePathHit{{Path: "/admin", StatusCode: 200, Title: "Panel administracyjny – System Rezerwacji Sal", LoginForm: true}},
		}), true},
		{"MikroTik WebFig", httpSvc(80, &domain.HTTPFingerprint{StatusCode: 200, Title: "RouterOS router configuration page"}), true},
		{"Synology DSM 7", httpSvc(5000, &domain.HTTPFingerprint{StatusCode: 200, Title: "NAS01 - Synology NAS",
			BodySnippet: `<script type="text/javascript" src="webman/sso/synoSSO-1.0.0.js?v=69057"></script>`}), true},
		{"iDRAC 8", httpSvc(443, &domain.HTTPFingerprint{StatusCode: 200, Title: "Integrated Remote Access Controller 8",
			BodySnippet: `<div class="login-header">Integrated Dell Remote Access Controller 8</div>`}), true},

		// Not admin panels.
		{"GitLab sign-in (end-user login)", httpSvc(80, &domain.HTTPFingerprint{
			StatusCode: 200, URL: "http://10.0.0.9/users/sign_in", Title: "Sign in · GitLab", LoginForm: true,
			Cookies: []domain.CookieInfo{{Name: "_gitlab_session", HttpOnly: true}},
		}), false},
		{"ASP.NET app login, /admin redirects to it", httpSvc(80, &domain.HTTPFingerprint{
			StatusCode: 200, URL: "http://10.0.0.10/Account/Login?ReturnUrl=%2f", Title: "Logowanie - Dziekanat", LoginForm: true,
			ServerHeader: "Microsoft-IIS/10.0", Headers: map[string]string{"X-AspNet-Version": "4.0.30319", "X-Powered-By": "ASP.NET"},
			SafePathHits: []domain.SafePathHit{{Path: "/admin", StatusCode: 302, Snippet: "Location: /Account/Login?ReturnUrl=%2fadmin"}},
		}), false},
		{"Moodle (/admin -> login)", httpSvc(80, &domain.HTTPFingerprint{
			StatusCode: 200, Title: "UPeL - Platforma e-Learningowa AGH",
			Cookies:      []domain.CookieInfo{{Name: "MoodleSession"}},
			SafePathHits: []domain.SafePathHit{{Path: "/admin", StatusCode: 303}, {Path: "/login", StatusCode: 303}},
		}), false},
		{"CUPS /admin forbidden", httpSvc(631, &domain.HTTPFingerprint{
			StatusCode: 200, Title: "Home - CUPS 2.4.2", ServerHeader: "CUPS/2.4 IPP/2.1",
			SafePathHits: []domain.SafePathHit{{Path: "/admin", StatusCode: 403, Title: "Forbidden - CUPS 2.4.2"}},
		}), false},
		{"Express staging app login at /login", httpSvc(3000, &domain.HTTPFingerprint{
			StatusCode: 200, Title: "Rekrutacja [STAGING]", Headers: map[string]string{"X-Powered-By": "Express"},
			SafePathHits: []domain.SafePathHit{
				{Path: "/admin", StatusCode: 302, Snippet: "Found. Redirecting to /login"},
				{Path: "/login", StatusCode: 200, Title: "Logowanie - Rekrutacja [STAGING]", LoginForm: true},
			},
		}), false},
		{"Elasticsearch 8 Basic challenge", httpSvc(9200, &domain.HTTPFingerprint{
			StatusCode: 401, Headers: map[string]string{"WWW-Authenticate": `Basic realm="security" charset="UTF-8"`, "X-Elastic-Product": "Elasticsearch"},
		}), false},
		{"nginx default page", httpSvc(80, &domain.HTTPFingerprint{StatusCode: 200, Title: "Welcome to nginx!", ServerHeader: "nginx/1.24.0"}), false},
		{"MySQL port", domain.ObservedService{Port: 3306, ServiceName: "mysql", Product: "MySQL", Version: "8.0.36"}, false},
	}
	for _, c := range cases {
		svc := enrich(c.obs)
		if svc.IsAdminPanel != c.admin {
			t.Errorf("%s: IsAdminPanel=%v want %v (evidence: %q, techs: %v)", c.name, svc.IsAdminPanel, c.admin,
				AdminPanelEvidence(c.obs, svc.Technologies), techNames(svc.Technologies))
		}
	}
}

func techNames(ts []domain.DetectedTechnology) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func TestCustomAdminSignatureStillFlags(t *testing.T) {
	custom := domain.Signature{ID: "c1", Name: "Our intranet console", Category: "admin_panel", MatchMode: "any",
		ConfidenceWeight: 0.8, Enabled: true,
		Matchers: []domain.SignatureMatcher{{Type: "title", Pattern: "Intranet Ops"}}}
	obs := httpSvc(80, &domain.HTTPFingerprint{StatusCode: 200, Title: "Intranet Ops"})
	svc := domain.Service{Port: 80, HTTP: obs.HTTP}
	EnrichService(&svc, obs, signatures.NewEngine([]domain.Signature{custom}), 1)
	if !svc.IsAdminPanel {
		t.Fatal("analyst-defined admin_panel signature must still raise the flag")
	}
}

func TestStagingEvidenceRealDevSetups(t *testing.T) {
	cases := []struct {
		name    string
		obs     domain.ObservedService
		staging bool
	}{
		{"Django runserver", httpSvc(8000, &domain.HTTPFingerprint{StatusCode: 200, ServerHeader: "WSGIServer/0.2 CPython/3.10.12",
			Title: "The install worked successfully! Congratulations!"}), true},
		{"Flask dev server", httpSvc(5000, &domain.HTTPFingerprint{StatusCode: 200, ServerHeader: "Werkzeug/2.3.7 Python/3.11.4"}), true},
		{"Spring Boot actuator with dev profile", httpSvc(8080, &domain.HTTPFingerprint{StatusCode: 404,
			BodySnippet: "<h1>Whitelabel Error Page</h1>",
			SafePathHits: []domain.SafePathHit{{Path: "/actuator/info", StatusCode: 200,
				Snippet: `{"app":{"name":"usos-sync","version":"2.3.1","profile":"dev"},"build":{"artifact":"usos-sync"}}`}}}), true},
		{"Spring Boot actuator prod", httpSvc(8080, &domain.HTTPFingerprint{StatusCode: 404,
			SafePathHits: []domain.SafePathHit{{Path: "/actuator/info", StatusCode: 200,
				Snippet: `{"app":{"name":"usos-sync","version":"2.3.1","profile":"prod"}}`}}}), false},
		{"Node /health env staging", httpSvc(3000, &domain.HTTPFingerprint{StatusCode: 200, Title: "Panel",
			SafePathHits: []domain.SafePathHit{{Path: "/health", StatusCode: 200, Snippet: `{"status":"ok","env":"staging","uptime":4013}`}}}), true},
		{"CentOS stock Apache test page", httpSvc(80, &domain.HTTPFingerprint{StatusCode: 403, ServerHeader: "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.33",
			Title: "Apache HTTP Server Test Page powered by CentOS"}), false},
		{"TEST app", httpSvc(80, &domain.HTTPFingerprint{StatusCode: 200, Title: "TEST - Elektroniczny Dziennik"}), true},
		{"gunicorn production", httpSvc(8000, &domain.HTTPFingerprint{StatusCode: 200, ServerHeader: "gunicorn", Title: "Portal"}), false},
	}
	for _, c := range cases {
		svc := enrich(c.obs)
		if svc.IsStagingEnv != c.staging {
			t.Errorf("%s: IsStagingEnv=%v want %v", c.name, svc.IsStagingEnv, c.staging)
		}
	}
}
