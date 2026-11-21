package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Fixtures recorded from the jury lab template (docker-compose-*.yml) on the rehearsal VM.
// Each case checks the identified technology, its version and the admin panel flag.
func TestJuryLabIdentification(t *testing.T) {
	a := NewIntelligenceAnalyzer()
	http := func(port int, title, body string, hits ...domain.SafePathHit) domain.ObservedService {
		return domain.ObservedService{Port: port, Protocol: "tcp", ServiceName: "http", State: "open",
			HTTP: &domain.HTTPFingerprint{StatusCode: 200, Title: title, BodySnippet: body, SafePathHits: hits}}
	}
	cases := []struct {
		name     string
		svc      domain.ObservedService
		tech     string
		version  string
		admin    bool
		notTechs []string
	}{
		{"wordpress 4.7 installer", http(8088, "WordPress › Installation",
			`<title>WordPress &rsaquo; Installation</title><link rel='stylesheet' id='buttons-css' href='http://127.0.0.1:8088/wp-includes/css/buttons.min.css?ver=4.7.5' type='text/css' media='all' />`),
			"WordPress", "4.7.5", true, nil},
		{"phpmyadmin", http(8081, "phpMyAdmin",
			`<link rel="stylesheet" type="text/css" href="./themes/pmahomme/jquery/jquery-ui.css?v=5.2.3"><title>phpMyAdmin</title>`),
			"phpMyAdmin", "5.2.3", true, nil},
		{"adminer", http(8089, "Login - Adminer",
			`<h1><a href='https://www.adminer.org/' target="_blank" rel="noreferrer noopener" id='h1'>Adminer</a> <span class='version'>6.3.0 <a href='https://www.adminer.org/#download'`),
			"Adminer", "6.3.0", true, nil},
		{"dvwa", http(8090, "Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*", ""),
			"DVWA (Damn Vulnerable Web Application)", "1.10", false, nil},
		{"gitea installer", http(3001, "Installation - Gitea: Git with a cup of tea", `<html lang="en-US" data-theme="gitea-auto">`,
			domain.SafePathHit{Path: "/api/v1/version", StatusCode: 200, Snippet: `{"version":"1.24.6"}`}),
			"Gitea", "1.24.6", true, nil},
		{"rabbitmq management", http(15673, "RabbitMQ Management", ""), "RabbitMQ Management", "", true, nil},
		{"nginx proxy manager", http(81, "Nginx Proxy Manager", "",
			domain.SafePathHit{Path: "/api/", StatusCode: 200, Snippet: `{"status":"OK","setup":false,"version":{"major":2,"minor":17,"revision":1}}`}),
			"Nginx Proxy Manager", "2.17.1", true, nil},
		{"traefik dashboard", http(8086, "Traefik", "",
			domain.SafePathHit{Path: "/api/version", StatusCode: 200, Snippet: `{"Version":"3.1.7","Codename":"comte","startDate":"2026-11-21T23:13:00Z"}`}),
			"Traefik Dashboard / API", "3.1.7", true, nil},
		{"toxiproxy api", domain.ObservedService{Port: 8474, Protocol: "tcp", ServiceName: "http", State: "open",
			HTTP: &domain.HTTPFingerprint{StatusCode: 404, BodySnippet: "404 page not found", SafePathHits: []domain.SafePathHit{
				{Path: "/version", StatusCode: 200, Snippet: `{"version": "2.12.0"}`},
				{Path: "/proxies", StatusCode: 200, Snippet: `{"wordpress":{"name":"wordpress","listen":"[::]:8666","upstream":"wordpress:80","enabled":true,"Logger":{},"toxics":[]}}`},
			}}}, "Toxiproxy API", "2.12.0", true, nil},
		{"httpbin", http(8888, "httpbin.org", `<p>A simple HTTP Request &amp; Response Service.</p>`), "httpbin", "", false, nil},
		{"nginx default", http(8787, "Welcome to nginx!", ""), "Default Web Server Page", "", false, []string{"Unfinished Web Installer"}},
		{"wordpress installed is no installer", func() domain.ObservedService {
			s := http(8080, "My blog", `<link href="/wp-content/themes/x/style.css?ver=1.2">`)
			s.HTTP.MetaGenerator = "WordPress 7.1.5"
			return s
		}(),
			"WordPress", "7.1.5", false, []string{"Unfinished Web Installer"}},
		{"generic json version is no toxiproxy", domain.ObservedService{Port: 9000, Protocol: "tcp", ServiceName: "http", State: "open",
			HTTP: &domain.HTTPFingerprint{StatusCode: 200, Title: "App", SafePathHits: []domain.SafePathHit{
				{Path: "/version", StatusCode: 200, Snippet: `{"version":"1.0.0","build":"abc"}`}}}},
			"", "", false, []string{"Toxiproxy API", "Traefik Dashboard / API", "Gitea"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := c.svc
			res := a.AnalyzeService(&svc, nil)
			var names []string
			found := false
			for _, tech := range res.Technologies {
				names = append(names, fmt.Sprintf("%s %s (%d%%)", tech.Name, tech.Version, tech.Confidence))
				if tech.Name == c.tech {
					found = true
					if c.version != "" && tech.Version != c.version {
						t.Errorf("%s version %q, want %q", tech.Name, tech.Version, c.version)
					}
				}
				for _, nt := range c.notTechs {
					if tech.Name == nt {
						t.Errorf("unexpected technology %s", nt)
					}
				}
			}
			if c.tech != "" && !found {
				t.Errorf("technology %q not found in [%s]", c.tech, strings.Join(names, ", "))
			}
			if res.IsAdminPanel != c.admin {
				t.Errorf("admin panel = %v, want %v (techs %v)", res.IsAdminPanel, c.admin, names)
			}
		})
	}
}

func TestJuryLabProtocolFindings(t *testing.T) {
	a := NewIntelligenceAnalyzer()
	redis := domain.ObservedService{Port: 6379, Protocol: "tcp", ServiceName: "redis", Product: "Redis key-value store", Version: "7.4.12",
		Banner: "redis: no authentication (PING answered +PONG)", Tags: []string{"redis-no-auth"}, State: "open"}
	res := a.AnalyzeService(&redis, nil)
	if !hasReason(res.InterestingFactors, "Redis without authentication") || !hasTech(res.Technologies, "Exposed Database Service") {
		t.Errorf("redis: factors %v", res.InterestingFactors)
	}
	pg := domain.ObservedService{Port: 15432, Protocol: "tcp", ServiceName: "postgresql", Product: "PostgreSQL", State: "open"}
	res = a.AnalyzeService(&pg, nil)
	if !hasTech(res.Technologies, "Exposed Database Service") || !hasReason(res.InterestingFactors, "PostgreSQL database port exposed") {
		t.Errorf("postgres on 15432: techs %v factors %v", res.Technologies, res.InterestingFactors)
	}
	ftp := domain.ObservedService{Port: 21, Protocol: "tcp", ServiceName: "ftp", Product: "vsftpd", Version: "3.0.2", State: "open"}
	res = a.AnalyzeService(&ftp, nil)
	if !hasReason(res.InterestingFactors, "FTP: cleartext") {
		t.Errorf("ftp: factors %v", res.InterestingFactors)
	}
	ftp.Banner = "ftp: anonymous login allowed"
	res = a.AnalyzeService(&ftp, nil)
	if !hasReason(res.InterestingFactors, "anonymous") {
		t.Errorf("anonymous ftp: factors %v", res.InterestingFactors)
	}
}

func hasReason(fs []domain.InterestingnessFactor, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f.Reason, sub) {
			return true
		}
	}
	return false
}

func hasTech(ts []domain.DetectedTechnology, name string) bool {
	for _, t := range ts {
		if t.Name == name {
			return true
		}
	}
	return false
}
