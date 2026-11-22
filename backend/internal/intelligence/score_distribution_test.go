package intelligence_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/intelligence"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb"
)

var scoreNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// svcScore scores one service the way ingest does: base factors, then EOL / CVE annotators
// (embedded NVD/KEV/EPSS snapshot). verified adds a confirmed finding of that weight.
func svcScore(s domain.Service, verified int) domain.Service {
	s.State = "open"
	s.Protocol = "tcp"
	s.Interestingness, s.InterestingFactors = intelligence.ScoreService(&s, nil)
	if verified > 0 {
		s.InterestingFactors = append(s.InterestingFactors, domain.InterestingnessFactor{Reason: "Verified exposure: test", Weight: verified})
	}
	eol.ApplyScore(&s, scoreNow)
	return s
}

func hostScore(state string, svcs ...domain.Service) domain.Host {
	h := domain.Host{IP: "10.0.0.1", LifecycleState: state, Services: svcs}
	h.Interestingness, h.InterestingFactors = intelligence.ScoreHost(&h, svcs, nil)
	return h
}

func web(port int, server, product, version string, opts ...func(*domain.Service)) domain.Service {
	s := domain.Service{Port: port, ServiceName: "http", Product: product, Version: version, VersionSource: "nmap",
		HTTP: &domain.HTTPFingerprint{Scheme: "http", ServerHeader: server, StatusCode: 200,
			MissingSecHeaders: []string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "Referrer-Policy"}}}
	if port == 443 || port == 8443 {
		s.ServiceName, s.HTTP.Scheme = "https", "https"
	}
	for _, o := range opts {
		o(&s)
	}
	return s
}

var (
	admin      = func(s *domain.Service) { s.IsAdminPanel = true }
	selfSigned = func(s *domain.Service) {
		s.HTTP.TLS = &domain.TLSInfo{IsSelfSigned: true, DaysToExpiry: 200}
	}
	badCookie = func(s *domain.Service) {
		s.HTTP.Cookies = []domain.CookieInfo{{Name: "PHPSESSID", Flags: []string{"missing_httponly", "missing_secure"}}}
	}
	http2 = func(state string) func(*domain.Service) {
		return func(s *domain.Service) {
			s.HTTP.Protocols = &domain.ProtocolSupport{HTTP2: state, HTTP2Evidence: "test", CheckedAt: scoreNow}
		}
	}
	ssh = func(v string) domain.Service {
		return domain.Service{Port: 22, ServiceName: "ssh", Product: "OpenSSH", Version: v, VersionSource: "nmap"}
	}
	plain = func(port int, name string) domain.Service { return domain.Service{Port: port, ServiceName: name} }
)

// population builds a network shaped like the jury lab and a typical campus range: mostly
// SSH-only Linux boxes and web servers with hygiene gaps, a minority of exposed admin
// panels, databases, Windows file servers, printers, legacy cleartext gear, a few
// unauthenticated control ports and a handful of confirmed (verified) exposures.
func population(r *rand.Rand) []domain.Host {
	sshVersions := []string{"8.9p1 Ubuntu 3ubuntu0.10", "8.2p1 Ubuntu 4ubuntu0.11", "9.6p1 Ubuntu 3ubuntu13.5", "9.2p1 Debian 2+deb12u3", "7.6p1 Ubuntu 4ubuntu0.7"}
	webs := []struct{ server, product, version string }{
		{"nginx/1.18.0", "nginx", "1.18.0"}, {"nginx/1.24.0", "nginx", "1.24.0"}, {"nginx/1.20.1", "nginx", "1.20.1"},
		{"Apache/2.4.52 (Ubuntu)", "Apache httpd", "2.4.52"}, {"Apache/2.4.57 (Debian)", "Apache httpd", "2.4.57"}, {"Apache/2.4.62", "Apache httpd", "2.4.62"},
	}
	pick := func(n int) int { return r.Intn(n) }
	sshv := func() domain.Service { return svcScore(ssh(sshVersions[pick(len(sshVersions))]), 0) }
	h2 := func() func(*domain.Service) {
		return http2([]string{domain.ProtoNo, domain.ProtoNo, domain.ProtoYes, domain.ProtoUnknown}[pick(4)])
	}
	var hosts []domain.Host
	add := func(n int, mk func() domain.Host) {
		for i := 0; i < n; i++ {
			h := mk()
			h.IP = fmt.Sprintf("10.66.%d.%d", len(hosts)/250, len(hosts)%250+1)
			hosts = append(hosts, h)
		}
	}
	state := func() string {
		return []string{domain.HostStateNew, domain.HostStateActive, domain.HostStateActive, domain.HostStateActive}[pick(4)]
	}
	add(150, func() domain.Host { return hostScore(state(), sshv()) })
	add(120, func() domain.Host { // web servers, hygiene gaps
		w := webs[pick(len(webs))]
		return hostScore(state(), sshv(), svcScore(web(80, w.server, w.product, w.version, h2()), 0),
			svcScore(web(443, w.server, w.product, w.version, h2(), badCookie), 0))
	})
	add(60, func() domain.Host { // web app with an admin login
		w := webs[pick(len(webs))]
		return hostScore(state(), sshv(), svcScore(web(443, w.server, w.product, w.version, admin, h2(), badCookie), 0))
	})
	add(50, func() domain.Host { // database servers
		db := []domain.Service{
			{Port: 3306, ServiceName: "mysql", Product: "MySQL", Version: "8.0.36"},
			{Port: 5432, ServiceName: "postgresql", Product: "PostgreSQL DB", Version: "14.11"},
		}[pick(2)]
		return hostScore(state(), sshv(), svcScore(db, 0))
	})
	add(40, func() domain.Host { // Windows file servers
		return hostScore(state(), svcScore(plain(3389, "ms-wbt-server"), 0), svcScore(plain(445, "microsoft-ds"), 0),
			svcScore(web(80, "Microsoft-IIS/10.0", "Microsoft IIS httpd", "10.0"), 0))
	})
	add(30, func() domain.Host { // printers, cameras
		s := web(80, "HP HTTP Server", "", "", selfSigned)
		s.IsIoT = true
		return hostScore(state(), svcScore(s, 0))
	})
	add(25, func() domain.Host { // legacy cleartext management
		return hostScore(state(), svcScore(plain(23, "telnet"), 0), svcScore(plain(21, "ftp"), 0))
	})
	add(25, func() domain.Host { // dev / staging
		s := web(8080, "nginx/1.24.0", "nginx", "1.24.0", h2())
		s.IsStagingEnv = true
		return hostScore(state(), sshv(), svcScore(s, 0))
	})
	add(15, func() domain.Host { // BMCs
		s := web(443, "", "", "", selfSigned)
		s.Technologies = []domain.DetectedTechnology{{Name: "Dell iDRAC", Category: "bmc"}}
		s.IsIoT = true
		return hostScore(state(), svcScore(s, 0))
	})
	add(10, func() domain.Host { // unauthenticated control ports
		s := []domain.Service{
			{Port: 2375, ServiceName: "docker"},
			{Port: 6379, ServiceName: "redis", Banner: "redis: no authentication"},
		}[pick(2)]
		return hostScore(state(), sshv(), svcScore(s, 0))
	})
	add(10, func() domain.Host { // confirmed by Verify
		return hostScore(state(), sshv(), svcScore(web(15672, "", "", "", admin), 85))
	})
	add(65, func() domain.Host { // HTTPS appliances with only hygiene findings
		return hostScore(state(), svcScore(web(443, "", "", "", selfSigned, badCookie), 0))
	})
	return hosts
}

// TestScoreDistributionIsSpread: on a realistic population the host score must separate
// the few hosts to fix today from the many that are merely untidy. Before the
// recalibration (additive points capped at 100) the jury lab had 40% of hosts at 90 or more
// and every /22 block at 100.
func TestScoreDistributionIsSpread(t *testing.T) {
	hosts := population(rand.New(rand.NewSource(7)))
	var scores []int
	for _, h := range hosts {
		scores = append(scores, h.Interestingness)
		sum := 0
		for _, f := range h.InterestingFactors {
			sum += f.Points
		}
		if sum != h.Interestingness {
			t.Fatalf("%s: factor points add up to %d, score %d: %+v", h.IP, sum, h.Interestingness, h.InterestingFactors)
		}
	}
	d := distOf(scores)
	t.Logf("synthetic population:\n%s", d)
	if pctOf(d.ge90, d.n) > 10 {
		t.Errorf("%.1f%% of hosts score >= 90, want at most 10%%", pctOf(d.ge90, d.n))
	}
	if d.median > 50 {
		t.Errorf("median %d, want <= 50", d.median)
	}
	if d.eq100 > 0 {
		t.Errorf("%d hosts at 100", d.eq100)
	}
	bands := 0
	for _, c := range d.hist {
		if c > 0 {
			bands++
		}
	}
	if bands < 6 {
		t.Errorf("scores fall in only %d deciles, want a spread distribution", bands)
	}
}

// The ordering a security engineer expects, independent of the exact numbers.
func TestScoreOrderingSignals(t *testing.T) {
	hygieneOnly := hostScore(domain.HostStateActive, svcScore(web(443, "", "", "", selfSigned, badCookie), 0))
	sshOnly := hostScore(domain.HostStateActive, svcScore(ssh("9.6p1 Ubuntu 3ubuntu13.5"), 0))
	adminPanel := hostScore(domain.HostStateActive, svcScore(web(443, "nginx", "", "", admin), 0))
	telnet := hostScore(domain.HostStateActive, svcScore(plain(23, "telnet"), 0))
	docker := hostScore(domain.HostStateActive, svcScore(domain.Service{Port: 2375, ServiceName: "docker"}, 0))
	verified := hostScore(domain.HostStateActive, svcScore(web(15672, "", "", "", admin), 85))

	if hygieneOnly.Interestingness >= 25 {
		t.Errorf("hygiene findings alone scored %d, want the lowest band (< 25)", hygieneOnly.Interestingness)
	}
	if sshOnly.Interestingness >= 25 {
		t.Errorf("an up-to-date SSH server scored %d", sshOnly.Interestingness)
	}
	if !(hygieneOnly.Interestingness < adminPanel.Interestingness && adminPanel.Interestingness < telnet.Interestingness &&
		telnet.Interestingness < docker.Interestingness && docker.Interestingness < verified.Interestingness) {
		t.Errorf("ordering hygiene %d < admin %d < telnet %d < docker API %d < verified %d broken",
			hygieneOnly.Interestingness, adminPanel.Interestingness, telnet.Interestingness, docker.Interestingness, verified.Interestingness)
	}
	if verified.Interestingness < 90 {
		t.Errorf("a verified critical exposure scored %d, want the critical band", verified.Interestingness)
	}

	// The lab false positive: nginx 1.20.1 on plain HTTP. With HTTP/2 off the Rapid Reset
	// KEV match no longer drives the score.
	off := svcScore(web(80, "nginx/1.20.1", "nginx", "1.20.1", http2(domain.ProtoNo)), 0)
	unknown := svcScore(web(80, "nginx/1.20.1", "nginx", "1.20.1", http2(domain.ProtoUnknown)), 0)
	for _, f := range off.InterestingFactors {
		if strings.HasPrefix(f.Reason, vulndb.FactorKEV) && strings.Contains(f.Reason, "CVE-2023-44487") {
			t.Errorf("HTTP/2 off still scores Rapid Reset: %+v", f)
		}
	}
	if off.Interestingness >= unknown.Interestingness {
		t.Errorf("HTTP/2 off scored %d, unverified %d: suppression should lower the score", off.Interestingness, unknown.Interestingness)
	}
	t.Logf("hygiene %d, ssh %d, admin %d, telnet %d, docker %d, verified %d; nginx 1.20.1 http2 off %d / unknown %d",
		hygieneOnly.Interestingness, sshOnly.Interestingness, adminPanel.Interestingness, telnet.Interestingness,
		docker.Interestingness, verified.Interestingness, off.Interestingness, unknown.Interestingness)
}
