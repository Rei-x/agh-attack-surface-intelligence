package fingerprint

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// HTTP version capability probe. It answers one question per endpoint, "does it speak
// HTTP/2?", so version-matched CVEs that only exist in the HTTP/2 code (Rapid Reset,
// CVE-2019-9511..9518, mod_http2 bugs) can be marked not applicable when it does not. It is a
// protocol negotiation, not an exploit: no request is sent beyond what any HTTP/2 client
// sends first, every connection goes through the scan's rate limiter, and it is closed right
// after the server's first answer.
//
//   - TLS: one handshake offering ALPN "h2, http/1.1". The server picks; "h2" = HTTP/2.
//   - Cleartext: the HTTP/2 connection preface with an empty SETTINGS frame ("prior
//     knowledge", how nginx and Node serve h2c). An HTTP/2 server answers with SETTINGS, an
//     HTTP/1 server with an HTTP/1.x error. If that is not a yes, one GET / with
//     "Upgrade: h2c" (how Tomcat, Jetty and Apache negotiate h2c); 101 = HTTP/2.
//
// "no" needs a definite HTTP/1 answer to every attempt; timeouts and resets stay "unknown".

// DefaultProtocolProbeTimeout bounds each probe connection.
const DefaultProtocolProbeTimeout = 3 * time.Second

const (
	h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	// http2SettingsB64 is the HTTP2-Settings header value: base64url of one SETTINGS
	// parameter, SETTINGS_MAX_CONCURRENT_STREAMS = 100 (the header may not be empty).
	http2SettingsB64 = "AAMAAABk"
	frameSettings    = 0x4
	frameGoAway      = 0x7
	flagAck          = 0x1
)

// emptySettingsFrame is a SETTINGS frame with no parameters (length 0, stream 0).
var emptySettingsFrame = []byte{0, 0, 0, frameSettings, 0, 0, 0, 0, 0}

// goAwayFrame tells the server we are done (last stream 0, NO_ERROR).
var goAwayFrame = []byte{0, 0, 8, frameGoAway, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func (f *Fingerprinter) probeProtocols(ctx context.Context, fp *domain.HTTPFingerprint, scheme, ip string, port int, sni, hostHeader string, hdr http.Header, opts Options) {
	if fp == nil || opts.DisableProtocolProbe {
		return
	}
	ps := &domain.ProtocolSupport{HTTP2: domain.ProtoUnknown, HTTP3: domain.ProtoUnknown, CheckedAt: opts.Now()}
	if alt := altSvcH3(hdr); alt != "" {
		ps.HTTP3, ps.HTTP3Evidence = domain.ProtoYes, "Alt-Svc: "+alt
	} else {
		ps.HTTP3Evidence = "not advertised (no h3 in Alt-Svc)"
	}
	timeout := opts.Timeout
	if timeout <= 0 || timeout > DefaultProtocolProbeTimeout {
		timeout = DefaultProtocolProbeTimeout
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	if scheme == "https" {
		ps.HTTP2, ps.HTTP2Method, ps.HTTP2Evidence = probeALPN(ctx, addr, ip, sni, timeout, opts.RateLimiter)
	} else {
		ps.HTTP2, ps.HTTP2Method, ps.HTTP2Evidence = probeH2C(ctx, addr, ip, hostHeader, opts.UserAgent, timeout, opts.RateLimiter)
	}
	fp.Protocols = ps
}

// altSvcH3 returns the h3 entries of the Alt-Svc header ("" when none).
func altSvcH3(hdr http.Header) string {
	var out []string
	for _, v := range hdr.Values("Alt-Svc") {
		for _, part := range strings.Split(v, ",") {
			p := strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(p), "h3") {
				if i := strings.IndexByte(p, ';'); i > 0 {
					p = p[:i]
				}
				out = append(out, p)
			}
		}
	}
	return strings.Join(out, ", ")
}

func dialProbe(ctx context.Context, addr, ip string, timeout time.Duration, limiter func(context.Context, string) error) (net.Conn, error) {
	if limiter != nil {
		if err := limiter(ctx, ip); err != nil {
			return nil, err
		}
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// probeALPN offers h2 and http/1.1 in a TLS handshake and reports what the server picked.
func probeALPN(ctx context.Context, addr, ip, sni string, timeout time.Duration, limiter func(context.Context, string) error) (string, string, string) {
	conn, err := dialProbe(ctx, addr, ip, timeout, limiter)
	if err != nil {
		return domain.ProtoUnknown, "alpn", "connect failed: " + shortErr(err)
	}
	defer conn.Close()
	cfg := &tls.Config{
		InsecureSkipVerify: true, // capability probe only, the certificate is inspected elsewhere
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS10,
	}
	noSNI := sni == "" || net.ParseIP(sni) != nil
	if !noSNI {
		cfg.ServerName = sni
	}
	tc := tls.Client(conn, cfg)
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		return domain.ProtoUnknown, "alpn", "TLS handshake failed: " + shortErr(err)
	}
	where := ""
	if noSNI {
		where = "; no SNI, so the default virtual host"
	}
	switch p := tc.ConnectionState().NegotiatedProtocol; p {
	case "h2":
		return domain.ProtoYes, "alpn", "TLS ALPN negotiated h2" + where
	case "":
		return domain.ProtoNo, "alpn", "TLS server selected no ALPN protocol although h2 was offered" + where
	default:
		return domain.ProtoNo, "alpn", fmt.Sprintf("TLS ALPN selected %s although h2 was offered%s", p, where)
	}
}

type h2cAnswer int

const (
	h2cInconclusive h2cAnswer = iota // timeout, reset, garbage
	h2cHTTP1                         // a definite HTTP/1.x answer (or a clean close)
	h2cHTTP2                         // HTTP/2 spoken
)

// probeH2C tries HTTP/2 prior knowledge, then the h2c Upgrade, on a cleartext port.
func probeH2C(ctx context.Context, addr, ip, hostHeader, ua string, timeout time.Duration, limiter func(context.Context, string) error) (string, string, string) {
	pk, pkEv := probePriorKnowledge(ctx, addr, ip, timeout, limiter)
	if pk == h2cHTTP2 {
		return domain.ProtoYes, "h2c-prior-knowledge", pkEv
	}
	if ctx.Err() != nil {
		return domain.ProtoUnknown, "h2c-prior-knowledge", pkEv
	}
	up, upEv := probeUpgrade(ctx, addr, ip, hostHeader, ua, timeout, limiter)
	ev := "connection preface: " + pkEv + "; Upgrade: h2c: " + upEv
	switch {
	case up == h2cHTTP2:
		return domain.ProtoYes, "h2c-upgrade", upEv
	case pk == h2cHTTP1 && up == h2cHTTP1:
		return domain.ProtoNo, "h2c-prior-knowledge", ev
	}
	return domain.ProtoUnknown, "h2c-prior-knowledge", ev
}

func probePriorKnowledge(ctx context.Context, addr, ip string, timeout time.Duration, limiter func(context.Context, string) error) (h2cAnswer, string) {
	conn, err := dialProbe(ctx, addr, ip, timeout, limiter)
	if err != nil {
		return h2cInconclusive, "connect failed: " + shortErr(err)
	}
	defer conn.Close()
	if _, err := conn.Write(append([]byte(h2Preface), emptySettingsFrame...)); err != nil {
		return h2cInconclusive, "write failed: " + shortErr(err)
	}
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for len(buf) < 9 {
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
		if bytes.HasPrefix(buf, []byte("HTTP/")) && bytes.IndexByte(buf, '\n') > 0 {
			break
		}
	}
	if len(buf) >= 9 && buf[3] == frameSettings && buf[4]&flagAck == 0 && streamID(buf) == 0 {
		_, _ = conn.Write(goAwayFrame)
		return h2cHTTP2, "server answered the HTTP/2 connection preface with SETTINGS"
	}
	if bytes.HasPrefix(buf, []byte("HTTP/1.")) {
		return h2cHTTP1, "answered " + statusLine(buf) + " instead of SETTINGS"
	}
	if len(buf) == 0 {
		// A clean close (FIN) is an HTTP/1 server dropping an unparsable request; a timeout or
		// reset says nothing.
		if _, err := conn.Read(tmp); errors.Is(err, io.EOF) {
			return h2cHTTP1, "connection closed without an HTTP/2 answer"
		}
		return h2cInconclusive, "no answer"
	}
	return h2cInconclusive, fmt.Sprintf("unrecognised answer (%d bytes)", len(buf))
}

func probeUpgrade(ctx context.Context, addr, ip, hostHeader, ua string, timeout time.Duration, limiter func(context.Context, string) error) (h2cAnswer, string) {
	conn, err := dialProbe(ctx, addr, ip, timeout, limiter)
	if err != nil {
		return h2cInconclusive, "connect failed: " + shortErr(err)
	}
	defer conn.Close()
	if ua == "" {
		ua = DefaultUserAgent
	}
	req := "GET / HTTP/1.1\r\nHost: " + hostHeader + "\r\nUser-Agent: " + ua +
		"\r\nAccept: */*\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: " + http2SettingsB64 + "\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return h2cInconclusive, "write failed: " + shortErr(err)
	}
	resp, err := http.ReadResponse(bufio.NewReaderSize(io.LimitReader(conn, 16<<10), 4096), nil)
	if err != nil {
		return h2cInconclusive, "no HTTP answer: " + shortErr(err)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols && strings.EqualFold(strings.TrimSpace(resp.Header.Get("Upgrade")), "h2c") {
		return h2cHTTP2, "server accepted Upgrade: h2c (101 Switching Protocols)"
	}
	return h2cHTTP1, "not switched, answered " + resp.Proto + " " + resp.Status
}

func streamID(frame []byte) uint32 {
	return (uint32(frame[5])<<24 | uint32(frame[6])<<16 | uint32(frame[7])<<8 | uint32(frame[8])) & 0x7fffffff
}

func statusLine(b []byte) string {
	if i := bytes.IndexAny(b, "\r\n"); i > 0 {
		b = b[:i]
	}
	if len(b) > 64 {
		b = b[:64]
	}
	return strings.ToValidUTF8(string(b), "?")
}

func shortErr(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		s = s[i+2:]
	}
	return s
}
