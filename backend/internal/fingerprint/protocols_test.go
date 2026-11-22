package fingerprint

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func probeOpts(limits *atomic.Int32) Options {
	o := DefaultOptions()
	o.ProbeSafePaths = false
	o.DisableJARM = true
	o.Timeout = 2 * time.Second
	o.RateLimiter = func(context.Context, string) error { limits.Add(1); return nil }
	return o
}

func probeURL(t *testing.T, rawURL string, scheme string, limits *atomic.Int32) *domain.HTTPFingerprint {
	t.Helper()
	host, port := hostPort(t, strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://"))
	o := probeOpts(limits)
	o.Scheme = scheme
	fp, err := New(o).Probe(context.Background(), host, port, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp.Protocols == nil {
		t.Fatal("no protocol probe result")
	}
	return fp
}

// A plain HTTP/1.1 server (the nginx "Welcome" case): the preface is rejected with an
// HTTP/1.x error and the Upgrade header ignored, so HTTP/2 is "no" with both answers quoted.
func TestProtocolProbeCleartextHTTP1IsNo(t *testing.T) {
	var upgrades atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "h2c" {
			upgrades.Add(1)
			if r.Method != http.MethodGet {
				t.Errorf("upgrade probe used %s", r.Method)
			}
		}
		w.Header().Set("Server", "nginx/1.20.1")
		_, _ = io.WriteString(w, "<title>Welcome to nginx!</title>")
	}))
	defer srv.Close()
	var limits atomic.Int32
	fp := probeURL(t, srv.URL, "http", &limits)
	ps := fp.Protocols
	if ps.HTTP2 != domain.ProtoNo {
		t.Fatalf("http2 = %q (%s), want no", ps.HTTP2, ps.HTTP2Evidence)
	}
	if !strings.Contains(ps.HTTP2Evidence, "connection preface: answered HTTP/1.1 ") || !strings.Contains(ps.HTTP2Evidence, "Upgrade: h2c: not switched, answered HTTP/1.1 200") {
		t.Fatalf("evidence does not quote both answers: %s", ps.HTTP2Evidence)
	}
	if upgrades.Load() != 1 {
		t.Fatalf("upgrade probes = %d, want 1", upgrades.Load())
	}
	if ps.HTTP3 != domain.ProtoUnknown || ps.CheckedAt.IsZero() {
		t.Fatalf("http3 %q checked_at %v", ps.HTTP3, ps.CheckedAt)
	}
	// root GET + favicon + 2 probe connections, all through the rate limiter
	if limits.Load() < 4 {
		t.Fatalf("rate limiter called %d times, want every probe connection to wait", limits.Load())
	}
}

// An h2c server with prior knowledge (nginx "listen 80 http2", Go, Node) answers SETTINGS.
func TestProtocolProbeCleartextPriorKnowledgeIsYes(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	defer srv.Close()
	var limits atomic.Int32
	ps := probeURL(t, srv.URL, "http", &limits).Protocols
	if ps.HTTP2 != domain.ProtoYes || ps.HTTP2Method != "h2c-prior-knowledge" {
		t.Fatalf("http2 = %q via %q (%s), want yes via prior knowledge", ps.HTTP2, ps.HTTP2Method, ps.HTTP2Evidence)
	}
}

// fakeUpgradeServer rejects the preface like an HTTP/1 server but switches to h2c on an
// Upgrade request (Tomcat / Jetty style).
func fakeUpgradeServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				switch {
				case req.Method == "PRI":
					_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				case req.Header.Get("Upgrade") == "h2c" && req.Header.Get("HTTP2-Settings") != "":
					_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
					_, _ = c.Write(emptySettingsFrame)
				default:
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestProtocolProbeCleartextUpgradeIsYes(t *testing.T) {
	addr, stop := fakeUpgradeServer(t)
	defer stop()
	var limits atomic.Int32
	ps := probeURL(t, "http://"+addr, "http", &limits).Protocols
	if ps.HTTP2 != domain.ProtoYes || ps.HTTP2Method != "h2c-upgrade" {
		t.Fatalf("http2 = %q via %q (%s), want yes via upgrade", ps.HTTP2, ps.HTTP2Method, ps.HTTP2Evidence)
	}
}

// Silence is not a "no": a server that never answers the preface stays unknown.
func TestProtocolProbeSilentServerIsUnknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { time.Sleep(2 * time.Second); c.Close() }(c)
		}
	}()
	host, port := hostPort(t, ln.Addr().String())
	got, _, ev := probeH2C(context.Background(), net.JoinHostPort(host, strconv.Itoa(port)), host, host, "", 300*time.Millisecond, nil)
	if got != domain.ProtoUnknown {
		t.Fatalf("silent server: http2 = %q (%s), want unknown", got, ev)
	}
}

func TestProtocolProbeTLSALPN(t *testing.T) {
	h1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer h1.Close()
	var limits atomic.Int32
	ps := probeURL(t, h1.URL, "https", &limits).Protocols
	if ps.HTTP2 != domain.ProtoNo || ps.HTTP2Method != "alpn" || !strings.Contains(ps.HTTP2Evidence, "http/1.1") {
		t.Fatalf("TLS HTTP/1.1 server: http2 = %q via %q (%s), want no via alpn", ps.HTTP2, ps.HTTP2Method, ps.HTTP2Evidence)
	}

	h2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400, h3-29=":443"`)
		_, _ = io.WriteString(w, "ok")
	}))
	h2.EnableHTTP2 = true
	h2.StartTLS()
	defer h2.Close()
	ps = probeURL(t, h2.URL, "https", &limits).Protocols
	if ps.HTTP2 != domain.ProtoYes || !strings.Contains(ps.HTTP2Evidence, "negotiated h2") {
		t.Fatalf("TLS h2 server: http2 = %q (%s), want yes", ps.HTTP2, ps.HTTP2Evidence)
	}
	if ps.HTTP3 != domain.ProtoYes || ps.HTTP3Evidence != `Alt-Svc: h3=":443", h3-29=":443"` {
		t.Fatalf("http3 = %q (%s), want yes from Alt-Svc", ps.HTTP3, ps.HTTP3Evidence)
	}
}

func TestProtocolProbeCanBeDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			t.Error("probe ran although disabled")
		}
	}))
	defer srv.Close()
	host, port := hostPort(t, strings.TrimPrefix(srv.URL, "http://"))
	var limits atomic.Int32
	o := probeOpts(&limits)
	o.DisableProtocolProbe = true
	fp, err := New(o).Probe(context.Background(), host, port, "", nil)
	if err != nil || fp.Protocols != nil {
		t.Fatalf("fp.Protocols = %+v err %v, want nil", fp.Protocols, err)
	}
}
