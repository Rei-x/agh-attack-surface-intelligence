package verify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Limiter is the scan governor (scanner.Governor satisfies it): one token per request.
type Limiter interface {
	Wait(ctx context.Context, host string) error
}

// Auditor records an audit-log entry (default-credential attempts).
type Auditor func(ctx context.Context, entry *domain.AuditLog)

// Target is one service to verify.
type Target struct {
	Service domain.Service
	HostIP  string
}

// Options control one run.
type Options struct {
	// DefaultCreds enables checks marked `requires: default-creds` (profile opt-in).
	DefaultCreds bool
	UserAgent    string
	ScanRunID    string
	ProfileID    string
	// InScope must approve every host before a packet is sent (profile targets).
	InScope func(ip string) bool
}

// Engine runs checks.
type Engine struct {
	Checks  []*Check
	Limiter Limiter
	Audit   Auditor
	Timeout time.Duration // per request (default 6 s)
	Now     func() time.Time
}

// Stats summarises a run.
type Stats struct {
	Targets           int `json:"targets"`
	ChecksRun         int `json:"checks_run"`
	Findings          int `json:"findings"`
	SkippedCreds      int `json:"skipped_default_creds"`
	OutOfScope        int `json:"out_of_scope"`
	Errors            int `json:"errors"`
	DefaultCredsTried int `json:"default_creds_tried"`
}

const (
	defaultMaxBody   = 64 << 10
	defaultUserAgent = "Dzieciol-Verify/1 (safe verification, read-only)"
	snippetMax       = 600
)

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) timeout() time.Duration {
	if e.Timeout > 0 {
		return e.Timeout
	}
	return 6 * time.Second
}

// Applicable lists the checks that apply to a service.
func (e *Engine) Applicable(svc *domain.Service) []*Check {
	var out []*Check
	for _, c := range e.Checks {
		if applies(c, svc) {
			out = append(out, c)
		}
	}
	return out
}

// Run verifies targets one service at a time (the limiter spaces requests per host) and
// returns the confirmed findings sorted by severity.
func (e *Engine) Run(ctx context.Context, targets []Target, opt Options) ([]domain.VerifiedFinding, Stats) {
	var out []domain.VerifiedFinding
	st := Stats{Targets: len(targets)}
	for i := range targets {
		t := &targets[i]
		if opt.InScope == nil || !opt.InScope(t.HostIP) {
			st.OutOfScope++
			continue
		}
		e.probeHTTP(ctx, t)
		for _, c := range e.Applicable(&t.Service) {
			if ctx.Err() != nil {
				return sortFindings(out), st
			}
			if c.DefaultCreds() && !opt.DefaultCreds {
				st.SkippedCreds++
				continue
			}
			st.ChecksRun++
			if c.DefaultCreds() {
				st.DefaultCredsTried++
			}
			f, err := e.runCheck(ctx, c, t, opt)
			if err != nil {
				st.Errors++
				continue
			}
			if f != nil {
				out = append(out, *f)
				st.Findings++
			}
		}
	}
	return sortFindings(out), st
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func sortFindings(f []domain.VerifiedFinding) []domain.VerifiedFinding {
	sort.SliceStable(f, func(i, j int) bool {
		if sevRank[f[i].Severity] != sevRank[f[j].Severity] {
			return sevRank[f[i].Severity] < sevRank[f[j].Severity]
		}
		if f[i].HostIP != f[j].HostIP {
			return f[i].HostIP < f[j].HostIP
		}
		if f[i].Port != f[j].Port {
			return f[i].Port < f[j].Port
		}
		return f[i].CheckID < f[j].CheckID
	})
	return f
}

func (e *Engine) runCheck(ctx context.Context, c *Check, t *Target, opt Options) (*domain.VerifiedFinding, error) {
	var (
		ok            bool
		request, evid string
		err           error
	)
	switch c.Kind() {
	case "builtin":
		ok, request, evid, err = e.runBuiltin(ctx, c, t)
	case "network":
		ok, request, evid, err = e.runNetwork(ctx, c, t)
	default:
		ok, request, evid, err = e.runHTTP(ctx, c, t, opt)
	}
	if err != nil || !ok {
		return nil, err
	}
	return &domain.VerifiedFinding{
		CheckID:      c.ID,
		Name:         c.Info.Name,
		Severity:     c.Info.Severity,
		ServiceID:    t.Service.ID,
		HostIP:       t.HostIP,
		Port:         t.Service.Port,
		Request:      Redact(request),
		Evidence:     evid,
		Remediation:  strings.TrimSpace(c.Info.Remediation),
		References:   c.Info.Reference,
		DefaultCreds: c.DefaultCreds(),
		CheckedAt:    e.now(),
		ScanRunID:    opt.ScanRunID,
	}, nil
}

func (e *Engine) wait(ctx context.Context, host string) error {
	if e.Limiter == nil {
		return nil
	}
	return e.Limiter.Wait(ctx, host)
}

// ---- applicability ---------------------------------------------------------------------

func isHTTP(s *domain.Service) bool {
	if s.HTTP != nil {
		return true
	}
	n := strings.ToLower(s.ServiceName)
	return strings.Contains(n, "http") || n == "https-alt"
}

func isTLS(s *domain.Service) bool {
	if s.HTTP != nil && (s.HTTP.TLS != nil || strings.EqualFold(s.HTTP.Scheme, "https")) {
		return true
	}
	n := strings.ToLower(s.ServiceName)
	if strings.Contains(n, "ssl") || strings.Contains(n, "https") || strings.Contains(n, "tls") {
		return true
	}
	switch s.Port {
	case 443, 8443, 993, 995, 465, 636, 9443:
		return true
	}
	return false
}

func applies(c *Check, s *domain.Service) bool {
	if s.State != "" && s.State != "open" {
		return false
	}
	switch c.Kind() {
	case "http":
		if !isHTTP(s) {
			return false
		}
		if c.Match.AnyHTTP {
			return true
		}
	case "builtin":
		if strings.HasPrefix(c.Builtin, "tls-") && !isTLS(s) {
			return false
		}
		if len(c.Match.Ports) == 0 && len(c.Match.Services) == 0 && len(c.Match.Products) == 0 && len(c.Match.Techs) == 0 {
			return true
		}
	}
	for _, p := range c.Match.Ports {
		if p == s.Port {
			return true
		}
	}
	svcName := strings.ToLower(s.ServiceName)
	for _, n := range c.Match.Services {
		if n = strings.ToLower(n); n != "" && strings.Contains(svcName, n) {
			return true
		}
	}
	prod := strings.ToLower(s.Product)
	for _, n := range c.Match.Products {
		if n = strings.ToLower(n); n != "" && strings.Contains(prod, n) {
			return true
		}
	}
	if len(c.Match.Techs) > 0 {
		names := make([]string, 0, len(s.Technologies)+len(s.MatchedSignatures)+1)
		for _, t := range s.Technologies {
			names = append(names, strings.ToLower(t.Name))
		}
		for _, m := range s.MatchedSignatures {
			names = append(names, strings.ToLower(m))
		}
		if s.HTTP != nil {
			names = append(names, strings.ToLower(s.HTTP.Title))
		}
		for _, want := range c.Match.Techs {
			want = strings.ToLower(want)
			for _, n := range names {
				if want != "" && strings.Contains(n, want) {
					return true
				}
			}
		}
	}
	return false
}

// probeHTTP: a port nmap could not identify (no product, banner or HTTP evidence, e.g.
// "tcpwrapped" or a bare port-table guess) gets one GET / over http, then https. When it
// answers HTTP, the target is treated as a web service for this run (its Server header and
// title join the technology names checks are gated on).
func (e *Engine) probeHTTP(ctx context.Context, t *Target) {
	s := &t.Service
	if s.HTTP != nil || s.Product != "" || s.Banner != "" || isHTTP(s) {
		return
	}
	client := e.httpClient()
	client.Timeout = 3 * time.Second
	host := t.HostIP
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	for _, scheme := range []string{"http", "https"} {
		if err := e.wait(ctx, t.HostIP); err != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+":"+strconv.Itoa(s.Port)+"/", nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", defaultUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		fp := &domain.HTTPFingerprint{Scheme: scheme, StatusCode: resp.StatusCode, ServerHeader: resp.Header.Get("Server")}
		if m := reTitle.FindSubmatch(raw); m != nil {
			fp.Title = strings.TrimSpace(string(m[1]))
		}
		s.HTTP = fp
		if fp.ServerHeader != "" {
			s.Technologies = append(s.Technologies, domain.DetectedTechnology{Name: fp.ServerHeader})
		}
		return
	}
}

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// ---- http ------------------------------------------------------------------------------

func baseURL(t *Target) (string, string) {
	scheme := "http"
	s := &t.Service
	if s.HTTP != nil && s.HTTP.Scheme != "" {
		scheme = strings.ToLower(s.HTTP.Scheme)
	} else if isTLS(s) {
		scheme = "https"
	}
	host := t.HostIP
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	hostPort := host + ":" + strconv.Itoa(s.Port)
	return scheme + "://" + hostPort, hostPort
}

func expand(tpl string, t *Target) string {
	base, hostPort := baseURL(t)
	r := strings.NewReplacer(
		"{{BaseURL}}", base,
		"{{RootURL}}", base,
		"{{Hostname}}", hostPort,
		"{{Host}}", t.HostIP,
		"{{Port}}", strconv.Itoa(t.Service.Port),
	)
	return r.Replace(tpl)
}

func (e *Engine) httpClient() *http.Client {
	return &http.Client{
		Timeout: e.timeout(),
		Transport: &http.Transport{
			// Verification, not trust: self-signed lab and appliance certificates are the norm.
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, //nolint:gosec
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: e.timeout(),
			Proxy:                 nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (e *Engine) runHTTP(ctx context.Context, c *Check, t *Target, opt Options) (bool, string, string, error) {
	client := e.httpClient()
	ua := opt.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	var lastErr error
	for _, r := range c.HTTP {
		for _, p := range r.Path {
			u := expand(p, t)
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				base, _ := baseURL(t)
				u = base + "/" + strings.TrimPrefix(u, "/")
			}
			if err := e.wait(ctx, t.HostIP); err != nil {
				return false, "", "", err
			}
			var body io.Reader
			if r.Body != "" {
				body = strings.NewReader(expand(r.Body, t))
			}
			req, err := http.NewRequestWithContext(ctx, r.Method, u, body)
			if err != nil {
				return false, "", "", err
			}
			req.Header.Set("User-Agent", ua)
			for k, v := range r.Headers {
				req.Header.Set(k, expand(v, t))
			}
			reqLine := r.Method + " " + u
			if r.BasicAuth != "" {
				user, pass, _ := strings.Cut(r.BasicAuth, ":")
				req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
				reqLine += fmt.Sprintf("\nAuthorization: Basic (user %q with the vendor default password)", user)
				if e.Audit != nil {
					e.Audit(ctx, &domain.AuditLog{
						Username: "system", Action: "verify.default_credentials", Resource: "service", ResourceID: t.Service.ID,
						Status: "success", CreatedAt: e.now(),
						Details: map[string]any{"check": c.ID, "target": u, "user": user, "profile_id": opt.ProfileID, "scan_run_id": opt.ScanRunID},
					})
				}
			}
			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				continue
			}
			max := r.MaxSize
			if max <= 0 || max > defaultMaxBody {
				max = defaultMaxBody
			}
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, int64(max)))
			resp.Body.Close()
			hdr := headerText(resp)
			ok, at := evaluate(r.MatchersCondition, r.Matchers, resp.StatusCode, hdr, string(raw))
			if !ok {
				continue
			}
			var ev strings.Builder
			fmt.Fprintf(&ev, "%s %s\n", resp.Proto, resp.Status)
			for _, k := range []string{"Server", "Content-Type", "WWW-Authenticate", "X-Powered-By"} {
				if v := resp.Header.Get(k); v != "" {
					fmt.Fprintf(&ev, "%s: %s\n", k, v)
				}
			}
			if r.Method != "HEAD" && len(raw) > 0 {
				ev.WriteString("\n")
				ev.WriteString(snippet(string(raw), at, snippetMax))
			}
			if x := extract(r.Extractors, hdr, string(raw)); x != "" {
				ev.WriteString("\n\nExtracted: " + Redact(x))
			}
			return true, reqLine, strings.TrimSpace(ev.String()), nil
		}
	}
	return false, "", "", lastErr
}

func headerText(resp *http.Response) string {
	var b strings.Builder
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	return b.String()
}

// ---- matchers --------------------------------------------------------------------------

// evaluate applies the matchers (Nuclei semantics: matchers-condition or by default) and
// returns whether they matched plus the body offset of the first positive word/regex hit.
func evaluate(cond string, ms []Matcher, status int, header, body string) (bool, int) {
	and := strings.EqualFold(cond, "and")
	at := -1
	for i := range ms {
		ok, pos := matchOne(&ms[i], status, header, body)
		if ms[i].Negative {
			ok = !ok
		} else if ok && pos >= 0 && at < 0 {
			at = pos
		}
		if and && !ok {
			return false, -1
		}
		if !and && ok {
			return true, at
		}
	}
	return and, at
}

func matchOne(m *Matcher, status int, header, body string) (bool, int) {
	var text string
	bodyOffset := 0
	switch strings.ToLower(m.Part) {
	case "header", "headers":
		text, bodyOffset = header, -1
	case "all", "raw", "response":
		text = header + "\n" + body
		bodyOffset = len(header) + 1
	default:
		text = body
	}
	pos := func(p int) int {
		if bodyOffset < 0 || p < bodyOffset {
			return -1
		}
		return p - bodyOffset
	}
	and := strings.EqualFold(m.Condition, "and")
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if s == status {
				return true, -1
			}
		}
		return false, -1
	case "word":
		hay := text
		if m.CaseInsensitive {
			hay = strings.ToLower(text)
		}
		first := -1
		for _, w := range m.Words {
			if m.CaseInsensitive {
				w = strings.ToLower(w)
			}
			i := strings.Index(hay, w)
			if i >= 0 && first < 0 {
				first = i
			}
			if and && i < 0 {
				return false, -1
			}
			if !and && i >= 0 {
				return true, pos(i)
			}
		}
		return and, pos(first)
	case "regex":
		first := -1
		for _, re := range m.res {
			loc := re.FindStringIndex(text)
			if loc != nil && first < 0 {
				first = loc[0]
			}
			if and && loc == nil {
				return false, -1
			}
			if !and && loc != nil {
				return true, pos(loc[0])
			}
		}
		return and, pos(first)
	}
	return false, -1
}

func extract(xs []Extractor, header, body string) string {
	var vals []string
	for _, x := range xs {
		text := body
		if strings.EqualFold(x.Part, "header") {
			text = header
		}
		for _, re := range x.res {
			for _, m := range re.FindAllStringSubmatch(text, 5) {
				v := m[0]
				if x.Group > 0 && x.Group < len(m) {
					v = m[x.Group]
				}
				if v = strings.TrimSpace(v); v != "" {
					if x.Name != "" {
						v = x.Name + "=" + v
					}
					vals = appendUniq(vals, v)
				}
			}
		}
	}
	return strings.Join(vals, ", ")
}

func appendUniq(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// ---- network ---------------------------------------------------------------------------

func (e *Engine) runNetwork(ctx context.Context, c *Check, t *Target) (bool, string, string, error) {
	_, hostPort := baseURL(t)
	var lastErr error
	for _, r := range c.Network {
		if err := e.wait(ctx, t.HostIP); err != nil {
			return false, "", "", err
		}
		data, sent, err := e.converse(ctx, hostPort, &r)
		if err != nil && len(data) == 0 {
			lastErr = err
			continue
		}
		ok, at := evaluate(r.MatchersCondition, r.Matchers, 0, "", string(data))
		if !ok {
			continue
		}
		ev := snippet(string(data), at, snippetMax)
		if x := extract(r.Extractors, "", string(data)); x != "" {
			ev += "\n\nExtracted: " + Redact(x)
		}
		return true, "tcp://" + hostPort + "\n" + strings.Join(sent, "\n"), ev, nil
	}
	return false, "", "", lastErr
}

// converse sends the inputs and returns everything read, plus a printable transcript of
// what was sent.
func (e *Engine) converse(ctx context.Context, hostPort string, r *NetRequest) ([]byte, []string, error) {
	d := &net.Dialer{Timeout: e.timeout()}
	conn, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, nil, err
	}
	if r.TLS {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, nil, err
		}
		conn = tc
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * e.timeout()))
	var buf bytes.Buffer
	var sent []string
	for _, in := range r.Inputs {
		if len(in.raw) > 0 {
			if _, err := conn.Write(in.raw); err != nil {
				return buf.Bytes(), sent, err
			}
			if strings.EqualFold(in.Type, "hex") {
				sent = append(sent, fmt.Sprintf("> [%d bytes binary request]", len(in.raw)))
			} else {
				sent = append(sent, "> "+strings.TrimSpace(printable(string(in.raw))))
			}
		}
		if in.Read > 0 {
			b, err := readSome(conn, in.Read, e.timeout())
			buf.Write(b)
			if err != nil && len(b) == 0 && !isTimeout(err) {
				return buf.Bytes(), sent, err
			}
		}
	}
	if r.ReadSize > 0 {
		b, err := readSome(conn, r.ReadSize, e.timeout())
		buf.Write(b)
		if err != nil && len(b) == 0 && !isTimeout(err) && !errors.Is(err, io.EOF) {
			return buf.Bytes(), sent, err
		}
	}
	return buf.Bytes(), sent, nil
}

// readSome reads up to n bytes: it waits up to timeout for the first byte, then keeps reading
// while more arrives within a short idle gap.
func readSome(conn net.Conn, n int, timeout time.Duration) ([]byte, error) {
	if n > defaultMaxBody {
		n = defaultMaxBody
	}
	out := make([]byte, 0, n)
	tmp := make([]byte, n)
	deadline := time.Now().Add(timeout)
	for len(out) < n {
		_ = conn.SetReadDeadline(deadline)
		k, err := conn.Read(tmp[:n-len(out)])
		out = append(out, tmp[:k]...)
		if err != nil {
			if len(out) > 0 && (isTimeout(err) || errors.Is(err, io.EOF)) {
				return out, nil
			}
			return out, err
		}
		deadline = time.Now().Add(400 * time.Millisecond)
	}
	return out, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
