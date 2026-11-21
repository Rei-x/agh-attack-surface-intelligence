package verify

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func loadChecks(t *testing.T) []*Check {
	t.Helper()
	cs, err := LoadBuiltinChecks()
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func only(t *testing.T, id string) []*Check {
	t.Helper()
	for _, c := range loadChecks(t) {
		if c.ID == id {
			return []*Check{c}
		}
	}
	t.Fatalf("check %s not found", id)
	return nil
}

func allScope(string) bool { return true }

// tcpServer serves each connection with handle and counts connections.
func tcpServer(t *testing.T, handle func(c net.Conn)) (int, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&n, 1)
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				handle(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, &n
}

func httpTarget(t *testing.T, srv *httptest.Server, svc domain.Service) Target {
	t.Helper()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://"))
	svc.Port, _ = strconv.Atoi(port)
	svc.State = "open"
	scheme := "http"
	if strings.HasPrefix(srv.URL, "https") {
		scheme = "https"
	}
	if svc.HTTP == nil {
		svc.HTTP = &domain.HTTPFingerprint{Scheme: scheme}
	}
	if svc.ServiceName == "" {
		svc.ServiceName = "http"
	}
	if svc.ID == "" {
		svc.ID = "svc-1"
	}
	return Target{Service: svc, HostIP: "127.0.0.1"}
}

func run(t *testing.T, checks []*Check, targets []Target, opt Options) ([]domain.VerifiedFinding, Stats) {
	t.Helper()
	if opt.InScope == nil {
		opt.InScope = allScope
	}
	e := &Engine{Checks: checks, Timeout: 2 * time.Second}
	return e.Run(context.Background(), targets, opt)
}

func TestBuiltinChecksParse(t *testing.T) {
	cs := loadChecks(t)
	if len(cs) < 18 {
		t.Fatalf("only %d checks", len(cs))
	}
	for _, c := range cs {
		if c.Info.Remediation == "" || c.Info.Description == "" {
			t.Errorf("%s: description and remediation are required", c.ID)
		}
		for _, r := range c.HTTP {
			if r.Method != "GET" && r.Method != "POST" && r.Method != "HEAD" {
				t.Errorf("%s: method %s", c.ID, r.Method)
			}
		}
	}
}

func TestUnsafeChecksRejected(t *testing.T) {
	bad := map[string]string{
		"delete method": "id: x\ninfo: {name: x, severity: low}\nhttp:\n  - method: DELETE\n    path: ['{{BaseURL}}/']\n    matchers: [{type: status, status: [200]}]\n",
		"creds ungated": "id: x\ninfo: {name: x, severity: low}\nhttp:\n  - path: ['{{BaseURL}}/']\n    basic-auth: 'admin:admin'\n    matchers: [{type: status, status: [200]}]\n",
		"no matchers":   "id: x\ninfo: {name: x, severity: low}\nhttp:\n  - path: ['{{BaseURL}}/']\n",
		"dsl matcher":   "id: x\ninfo: {name: x, severity: low}\nhttp:\n  - path: ['{{BaseURL}}/']\n    matchers: [{type: dsl, dsl: ['true']}]\n",
		"bad severity":  "id: x\ninfo: {name: x, severity: urgent}\nbuiltin: tls-protocols\n",
	}
	for name, src := range bad {
		if _, err := ParseCheck([]byte(src), name); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A plain Nuclei-style template (requests:, reference as string) is accepted.
	nuclei := "id: n\ninfo:\n  name: N\n  severity: info\n  reference: https://example.invalid\nrequests:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/x\"\n    matchers:\n      - type: word\n        words: [\"ok\"]\n"
	c, err := ParseCheck([]byte(nuclei), "nuclei")
	if err != nil || c.Kind() != "http" || len(c.Info.Reference) != 1 {
		t.Fatalf("nuclei template: %v %+v", err, c)
	}
}

func TestFTPAnonymous(t *testing.T) {
	ftp := func(allow bool) func(net.Conn) {
		return func(c net.Conn) {
			r := bufio.NewReader(c)
			c.Write([]byte("220 (vsFTPd 3.0.3)\r\n"))
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				switch {
				case strings.HasPrefix(line, "USER"):
					c.Write([]byte("331 Please specify the password.\r\n"))
				case strings.HasPrefix(line, "PASS") && allow:
					c.Write([]byte("230 Login successful.\r\n"))
				case strings.HasPrefix(line, "PASS"):
					c.Write([]byte("530 Login incorrect.\r\n"))
				case strings.HasPrefix(line, "QUIT"):
					c.Write([]byte("221 Goodbye.\r\n"))
					return
				}
			}
		}
	}
	for _, allow := range []bool{true, false} {
		port, _ := tcpServer(t, ftp(allow))
		f, _ := run(t, only(t, "ftp-anonymous"), []Target{{HostIP: "127.0.0.1", Service: domain.Service{ID: "s", Port: port, ServiceName: "ftp", State: "open"}}}, Options{})
		if (len(f) == 1) != allow {
			t.Fatalf("allow=%v: findings %+v", allow, f)
		}
		if allow && (!strings.Contains(f[0].Evidence, "230 Login successful") || !strings.Contains(f[0].Request, "USER anonymous")) {
			t.Fatalf("evidence: %+v", f[0])
		}
	}
}

func lineServer(reply func(req string) string) func(net.Conn) {
	return func(c net.Conn) {
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		c.Write([]byte(reply(string(buf[:n]))))
	}
}

func TestRedisUnauth(t *testing.T) {
	open, _ := tcpServer(t, lineServer(func(req string) string {
		if !strings.HasPrefix(req, "INFO") {
			return "-ERR\r\n"
		}
		return "$120\r\n# Server\r\nredis_version:4.0.14\r\nredis_mode:standalone\r\nos:Linux\r\n"
	}))
	locked, _ := tcpServer(t, lineServer(func(string) string { return "-NOAUTH Authentication required.\r\n" }))
	chk := only(t, "redis-unauth")
	f, _ := run(t, chk, []Target{
		{HostIP: "127.0.0.1", Service: domain.Service{ID: "a", Port: open, ServiceName: "redis", State: "open"}},
		{HostIP: "127.0.0.1", Service: domain.Service{ID: "b", Port: locked, ServiceName: "redis", State: "open"}},
	}, Options{})
	if len(f) != 1 || f[0].ServiceID != "a" || !strings.Contains(f[0].Evidence, "redis_version=4.0.14") {
		t.Fatalf("findings: %+v", f)
	}
}

func TestMongoAndMemcached(t *testing.T) {
	var gotOpMsg atomic.Bool
	mongo, _ := tcpServer(t, func(c net.Conn) {
		buf := make([]byte, 512)
		n, _ := c.Read(buf)
		if n >= 16 && buf[12] == 0xdd && buf[13] == 0x07 { // opcode 2013 OP_MSG
			gotOpMsg.Store(true)
		}
		c.Write([]byte("\x00\x00\x00\x00databases\x00\x02name\x00admin\x00totalSize\x00\x01ok"))
	})
	mongoAuth, _ := tcpServer(t, lineServer(func(string) string {
		return "....errmsg\x00command listDatabases requires authentication\x00codeName\x00Unauthorized"
	}))
	mc, _ := tcpServer(t, lineServer(func(string) string { return "STAT pid 1\r\nSTAT version 1.6.21\r\nEND\r\n" }))
	checks := append(only(t, "mongodb-unauth"), only(t, "memcached-unauth")...)
	f, _ := run(t, checks, []Target{
		{HostIP: "127.0.0.1", Service: domain.Service{ID: "m", Port: mongo, ServiceName: "mongodb", State: "open"}},
		{HostIP: "127.0.0.1", Service: domain.Service{ID: "ma", Port: mongoAuth, ServiceName: "mongodb", State: "open"}},
		{HostIP: "127.0.0.1", Service: domain.Service{ID: "c", Port: mc, ServiceName: "memcache", State: "open"}},
	}, Options{})
	if len(f) != 2 || !gotOpMsg.Load() {
		t.Fatalf("findings %+v (OP_MSG sent: %v)", f, gotOpMsg.Load())
	}
	ids := f[0].CheckID + "," + f[1].CheckID
	if !strings.Contains(ids, "mongodb-unauth") || !strings.Contains(ids, "memcached-unauth") {
		t.Fatalf("ids %s", ids)
	}
	for _, x := range f {
		if x.CheckID == "mongodb-unauth" && strings.ContainsAny(x.Evidence, "\x00\x01") {
			t.Fatalf("binary evidence not made printable: %q", x.Evidence)
		}
	}
}

// webApp is a fake vulnerable (or hardened) web application.
func webApp(vulnerable bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && !vulnerable {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/":
			if vulnerable {
				w.Write([]byte("<html><head><title>Index of /</title></head><body><a href=\"backup.zip\">backup.zip</a></body></html>"))
			} else {
				w.Write([]byte("<html><head><title>Welcome</title></head></html>"))
			}
		case "/.git/HEAD":
			w.Write([]byte("ref: refs/heads/main\n"))
		case "/.env":
			w.Write([]byte("APP_NAME=shop\nAPP_KEY=base64:c2VjcmV0c2VjcmV0c2VjcmV0\nDB_PASSWORD=Sup3rS3cret!\nDB_HOST=10.0.0.9\n"))
		case "/server-status":
			w.Write([]byte("<html><h1>Apache Server Status for 10.0.0.5 (via 10.0.0.5)</h1></html>"))
		case "/phpinfo.php":
			w.Write([]byte("<title>PHP 7.1.33 - phpinfo()</title><h1 class=\"p\">PHP Version 7.1.33</h1><tr><td>MYSQL_PASSWORD</td><td>hunter2hunter2</td></tr>"))
		case "/xmlrpc.php":
			if r.Method != http.MethodPost {
				w.Write([]byte("XML-RPC server accepts POST requests only."))
				return
			}
			w.Write([]byte("<?xml version=\"1.0\"?><methodResponse><params><param><value><array><data><value><string>pingback.ping</string></value><value><string>system.multicall</string></value></data></array></value></param></params></methodResponse>"))
		case "/wp-json/wp/v2/users":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id":1,"name":"admin","slug":"admin","link":"http://x/author/admin/"}]`))
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

func TestWebExposureChecks(t *testing.T) {
	ids := []string{"git-head-exposed", "dotenv-exposed", "apache-server-status", "phpinfo-exposed", "directory-listing", "wordpress-xmlrpc", "wordpress-user-enum"}
	var checks []*Check
	for _, id := range ids {
		checks = append(checks, only(t, id)...)
	}
	wp := []domain.DetectedTechnology{{Name: "WordPress", Version: "4.7"}}
	vuln := httptest.NewServer(webApp(true))
	defer vuln.Close()
	safe := httptest.NewServer(webApp(false))
	defer safe.Close()

	f, st := run(t, checks, []Target{httpTarget(t, vuln, domain.Service{ID: "v", Technologies: wp})}, Options{})
	got := map[string]domain.VerifiedFinding{}
	for _, x := range f {
		got[x.CheckID] = x
	}
	for _, id := range ids {
		if _, ok := got[id]; !ok {
			t.Errorf("%s not confirmed on the vulnerable app (stats %+v)", id, st)
		}
	}
	// Redaction: secrets from .env and phpinfo never reach the evidence.
	for _, x := range f {
		for _, secret := range []string{"Sup3rS3cret", "c2VjcmV0c2VjcmV0", "hunter2hunter2"} {
			if strings.Contains(x.Evidence, secret) {
				t.Errorf("%s evidence leaks %q: %s", x.CheckID, secret, x.Evidence)
			}
		}
	}
	if ev := got["dotenv-exposed"].Evidence; !strings.Contains(ev, "DB_PASSWORD=Su[redacted]") || !strings.Contains(ev, "DB_HOST=10.0.0.9") {
		t.Errorf("dotenv evidence: %s", ev)
	}
	if ev := got["wordpress-user-enum"].Evidence; !strings.Contains(ev, "user=admin") {
		t.Errorf("user enum evidence: %s", ev)
	}
	if got["wordpress-xmlrpc"].Request == "" || !strings.HasPrefix(got["wordpress-xmlrpc"].Request, "POST ") {
		t.Errorf("xmlrpc request: %q", got["wordpress-xmlrpc"].Request)
	}

	f, _ = run(t, checks, []Target{httpTarget(t, safe, domain.Service{ID: "s", Technologies: wp})}, Options{})
	if len(f) != 0 {
		t.Fatalf("hardened app produced findings: %+v", f)
	}
	// WordPress checks do not run on a non-WordPress service.
	f, _ = run(t, only(t, "wordpress-xmlrpc"), []Target{httpTarget(t, vuln, domain.Service{ID: "n"})}, Options{})
	if len(f) != 0 {
		t.Fatal("wordpress check ran without WordPress")
	}
}

func TestServiceAPIChecks(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Platform":{"Name":"Docker Engine"},"Version":"24.0.7","ApiVersion":"1.43","KernelVersion":"6.1.0"}`))
	})
	mux.HandleFunc("/_cluster/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"cluster_name":"docker-cluster","status":"yellow"}`))
	})
	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"http":{"routers":{"total":5},"services":{"total":6}},"features":{"tracing":""}}`))
	})
	mux.HandleFunc("/user/sign_up", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<form><input id="user_name" name="user_name"><input name="password"><input name="retype"></form>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<script>window.grafanaBootData = {"settings":{"disableUserSignUp":false}}</script>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	locked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/sign_up":
			w.Write([]byte(`<div class="ui negative message">Registration is disabled. Please contact your site administrator.</div>`))
		case "/login":
			w.Write([]byte(`{"settings":{"disableUserSignUp":true}}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
		}
	}))
	defer locked.Close()

	cases := []struct {
		id  string
		svc domain.Service
	}{
		{"docker-api-unauth", domain.Service{ServiceName: "docker"}},
		{"elasticsearch-unauth", domain.Service{Technologies: []domain.DetectedTechnology{{Name: "Elasticsearch"}}}},
		{"traefik-api-open", domain.Service{Technologies: []domain.DetectedTechnology{{Name: "Traefik"}}}},
		{"gitea-open-registration", domain.Service{Technologies: []domain.DetectedTechnology{{Name: "Gitea"}}}},
		{"grafana-signup-enabled", domain.Service{Technologies: []domain.DetectedTechnology{{Name: "Grafana"}}}},
	}
	for _, c := range cases {
		f, _ := run(t, only(t, c.id), []Target{httpTarget(t, srv, c.svc)}, Options{})
		if len(f) != 1 {
			t.Errorf("%s: not confirmed on the open service", c.id)
		}
		f, _ = run(t, only(t, c.id), []Target{httpTarget(t, locked, c.svc)}, Options{})
		if len(f) != 0 {
			t.Errorf("%s: confirmed on the locked service: %+v", c.id, f)
		}
	}
}

func TestDefaultCredsOptIn(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		if r.Header.Get("Authorization") == "Basic "+base64.StdEncoding.EncodeToString([]byte("guest:guest")) {
			w.Write([]byte(`{"name":"guest","tags":["administrator"]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	target := httpTarget(t, srv, domain.Service{Technologies: []domain.DetectedTechnology{{Name: "RabbitMQ"}}})
	chk := only(t, "rabbitmq-default-guest")

	// Off by default: nothing is sent.
	f, st := run(t, chk, []Target{target}, Options{})
	if len(f) != 0 || st.SkippedCreds != 1 || atomic.LoadInt32(&attempts) != 0 {
		t.Fatalf("default creds tried without opt-in: %+v %+v attempts=%d", f, st, attempts)
	}
	var mu sync.Mutex
	var audit []domain.AuditLog
	e := &Engine{Checks: chk, Timeout: 2 * time.Second, Audit: func(_ context.Context, a *domain.AuditLog) {
		mu.Lock()
		audit = append(audit, *a)
		mu.Unlock()
	}}
	f, st = e.Run(context.Background(), []Target{target}, Options{DefaultCreds: true, InScope: allScope, ProfileID: "p1"})
	if len(f) != 1 || !f[0].DefaultCreds || st.DefaultCredsTried != 1 {
		t.Fatalf("opt-in: %+v %+v", f, st)
	}
	if strings.Contains(f[0].Request, "Z3Vlc3Q6Z3Vlc3Q") || strings.Contains(f[0].Request, "guest:guest") {
		t.Fatalf("credential leaked into the request evidence: %s", f[0].Request)
	}
	if len(audit) != 1 || audit[0].Action != "verify.default_credentials" || audit[0].Details["user"] != "guest" {
		t.Fatalf("audit: %+v", audit)
	}
}

func TestScopeGate(t *testing.T) {
	port, conns := tcpServer(t, lineServer(func(string) string { return "redis_version:7.0.0\r\n" }))
	f, st := run(t, only(t, "redis-unauth"), []Target{{HostIP: "127.0.0.1", Service: domain.Service{ID: "x", Port: port, ServiceName: "redis", State: "open"}}},
		Options{InScope: func(ip string) bool { return ip == "10.0.0.5" }})
	time.Sleep(50 * time.Millisecond)
	if len(f) != 0 || st.OutOfScope != 1 || atomic.LoadInt32(conns) != 0 {
		t.Fatalf("out-of-scope host contacted: %+v %+v conns=%d", f, st, atomic.LoadInt32(conns))
	}
	// No scope function at all: nothing runs.
	e := &Engine{Checks: only(t, "redis-unauth")}
	if _, st := e.Run(context.Background(), []Target{{HostIP: "127.0.0.1", Service: domain.Service{Port: port, ServiceName: "redis"}}}, Options{}); st.OutOfScope != 1 {
		t.Fatal("missing scope must block")
	}
}

type countingLimiter struct{ n int32 }

func (l *countingLimiter) Wait(context.Context, string) error { atomic.AddInt32(&l.n, 1); return nil }

func TestGovernorUsedPerRequest(t *testing.T) {
	srv := httptest.NewServer(webApp(false))
	defer srv.Close()
	lim := &countingLimiter{}
	e := &Engine{Checks: only(t, "phpinfo-exposed"), Limiter: lim, Timeout: 2 * time.Second}
	e.Run(context.Background(), []Target{httpTarget(t, srv, domain.Service{})}, Options{InScope: allScope})
	if atomic.LoadInt32(&lim.n) != 2 { // two paths
		t.Fatalf("limiter calls = %d, want 2", lim.n)
	}
}

func TestTLSChecks(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	checks := append(only(t, "tls-weak-protocols"), only(t, "tls-certificate")...)
	f, _ := run(t, checks, []Target{httpTarget(t, srv, domain.Service{ServiceName: "https"})}, Options{})
	got := map[string]string{}
	for _, x := range f {
		got[x.CheckID] = x.Evidence
	}
	if !strings.Contains(got["tls-weak-protocols"], "TLS 1.0 accepted") {
		t.Errorf("weak protocol not confirmed: %+v", f)
	}
	if !strings.Contains(got["tls-certificate"], "self-signed") && !strings.Contains(got["tls-certificate"], "expired") {
		t.Errorf("certificate issue not confirmed: %+v", f)
	}

	modern := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	modern.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	modern.StartTLS()
	defer modern.Close()
	f, _ = run(t, only(t, "tls-weak-protocols"), []Target{httpTarget(t, modern, domain.Service{ServiceName: "https"})}, Options{})
	if len(f) != 0 {
		t.Errorf("TLS 1.2+ server flagged: %+v", f)
	}
}

func TestRedact(t *testing.T) {
	cases := map[string][]string{
		"DB_PASSWORD=Sup3rS3cret!":                                               {"Sup3rS3cret"},
		`{"api_key": "abcd1234efgh5678"}`:                                        {"1234efgh5678"},
		"Authorization: Bearer abc.def.ghi":                                      {"abc.def.ghi"},
		"mysql://root:toor1234@10.0.0.2:3306/app":                                {"toor1234"},
		"key AKIAIOSFODNN7EXAMPLE end":                                           {"IOSFODNN7EXAMPLE"},
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----": {"MIIEow"},
		"requirepass s3cr3tpass":                                                 {},
		"token=ghp_abcdefghijklmnopqrstuvwxyz0123456789":                         {"abcdefghijklmnop"},
	}
	for in, secrets := range cases {
		out := Redact(in)
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("Redact(%q) = %q leaks %q", in, out, s)
			}
		}
	}
	if got := Redact("DB_HOST=10.0.0.9 APP_NAME=shop"); got != "DB_HOST=10.0.0.9 APP_NAME=shop" {
		t.Errorf("non-secret changed: %q", got)
	}
}
