package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Protocol probes: short, read-only handshakes that name services nmap's light version scan
// (--version-intensity 2) leaves unidentified or only generic, and check two well-known weak
// configurations. Each probe is one TCP connection, sends at most a protocol greeting and
// closes; nothing is written, created or brute-forced:
//
//	AMQP        protocol header -> Connection.Start server properties (product, version)
//	PostgreSQL  SSLRequest (8 bytes) -> single 'S' or 'N' byte
//	Redis       PING -> +PONG (no authentication) or -NOAUTH (password set)
//	FTP         USER anonymous / PASS -> 230 means anonymous login is allowed; then QUIT
//
// Tags set here: "redis-no-auth", "ftp-anonymous".

const protocolProbeTimeout = 3 * time.Second

// probeDialer is replaceable in tests.
var probeDialer = func(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: protocolProbeTimeout}
	return d.DialContext(ctx, "tcp", addr)
}

// isUnidentified reports whether nmap could not name the service from its answers.
func isUnidentified(s domain.ObservedService, guessed bool) bool {
	if guessed {
		return true
	}
	switch strings.ToLower(s.ServiceName) {
	case "", "unknown", "tcp", "tcpwrapped":
		return true
	}
	return false
}

// protocolProbeStage runs the protocol probes and updates svcMap in place. Probes go through
// the Governor like HTTP requests. With unknownPhase false it probes services nmap named
// (AMQP product/version, Redis auth, FTP anonymous); with true it tries to name services
// that are still unidentified and did not answer HTTP (run after the HTTP stage, so a web
// app on an odd port costs one HTTP request, not three protocol probes).
func (e *Engine) protocolProbeStage(ctx context.Context, activeIPs []string, svcMap map[string][]domain.ObservedService, guessed map[string]bool, gov *Governor, mu *sync.Mutex, unknownPhase bool) {
	type job struct {
		ip  string
		idx int
	}
	var jobs []job
	for _, ip := range activeIPs {
		for idx, s := range svcMap[ip] {
			g := guessed[ip+":"+strconv.Itoa(s.Port)]
			if !wantsProtocolProbe(s, g) {
				continue
			}
			if unknownPhase != isUnidentified(s, g) || (unknownPhase && s.HTTP != nil) {
				continue
			}
			jobs = append(jobs, job{ip, idx})
		}
	}
	if len(jobs) == 0 {
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			mu.Lock()
			svc := svcMap[j.ip][j.idx]
			mu.Unlock()
			wait := func(c context.Context) error {
				if gov == nil {
					return nil
				}
				return gov.Wait(c, j.ip)
			}
			if probeService(ctx, j.ip, &svc, guessed[j.ip+":"+strconv.Itoa(svc.Port)], wait) {
				mu.Lock()
				svcMap[j.ip][j.idx] = svc
				mu.Unlock()
			}
		}(j)
	}
	wg.Wait()
}

func wantsProtocolProbe(s domain.ObservedService, guessed bool) bool {
	if s.Protocol != "" && s.Protocol != "tcp" {
		return false
	}
	sn := strings.ToLower(s.ServiceName)
	if isUnidentified(s, guessed) {
		return true
	}
	switch {
	case strings.Contains(sn, "amqp"), sn == "redis", sn == "ftp", strings.HasPrefix(sn, "postgres"):
		return true
	}
	return false
}

// probeService runs the probes that fit s and reports whether s was changed.
func probeService(ctx context.Context, ip string, s *domain.ObservedService, guessed bool, wait func(context.Context) error) bool {
	addr := net.JoinHostPort(ip, strconv.Itoa(s.Port))
	sn := strings.ToLower(s.ServiceName)
	unknown := isUnidentified(*s, guessed)
	run := func(p func(context.Context, string) (probeResult, bool)) (probeResult, bool) {
		if wait(ctx) != nil {
			return probeResult{}, false
		}
		pctx, cancel := context.WithTimeout(ctx, protocolProbeTimeout+time.Second)
		defer cancel()
		return p(pctx, addr)
	}
	apply := func(r probeResult) bool {
		if r.service != "" && (unknown || !strings.EqualFold(s.ServiceName, r.service)) {
			s.ServiceName = r.service
		}
		if r.product != "" && (s.Product == "" || unknown || genericProduct(s.Product)) {
			s.Product = r.product
		}
		if r.version != "" && s.Version == "" {
			s.Version = r.version
		}
		for _, t := range r.tags {
			s.Tags = appendUnique(s.Tags, t)
		}
		if r.note != "" && !strings.Contains(s.Banner, r.note) {
			s.Banner = strings.TrimSpace(s.Banner + " " + r.note)
		}
		return true
	}

	switch {
	case strings.Contains(sn, "amqp"):
		if r, ok := run(probeAMQP); ok {
			return apply(r)
		}
		return false
	case strings.HasPrefix(sn, "postgres") && !guessed:
		return false // nmap already named it from the server's answer
	case sn == "redis" && !guessed:
		if r, ok := run(probeRedis); ok {
			return apply(r)
		}
		return false
	case sn == "ftp" && !guessed:
		if r, ok := run(probeFTPAnonymous); ok {
			return apply(r)
		}
		return false
	}
	if !unknown {
		return false
	}
	// Unidentified: try the probes in order of how harmless a wrong guess is.
	for _, p := range []func(context.Context, string) (probeResult, bool){probePostgres, probeAMQP, probeRedis} {
		if r, ok := run(p); ok {
			return apply(r)
		}
	}
	return false
}

func genericProduct(p string) bool {
	return strings.EqualFold(p, "Advanced Message Queue Protocol")
}

type probeResult struct {
	service, product, version, note string
	tags                            []string
}

func probeExchange(ctx context.Context, addr string, send []byte, readMax int) ([]byte, error) {
	conn, err := probeDialer(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(protocolProbeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if len(send) > 0 {
		if _, err := conn.Write(send); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, readMax)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

// probePostgres sends an SSLRequest; a PostgreSQL server answers with exactly one byte.
func probePostgres(ctx context.Context, addr string) (probeResult, bool) {
	req := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	resp, err := probeExchange(ctx, addr, req, 64)
	if err != nil || len(resp) != 1 || (resp[0] != 'S' && resp[0] != 'N') {
		return probeResult{}, false
	}
	r := probeResult{service: "postgresql", product: "PostgreSQL"}
	if resp[0] == 'N' {
		r.note = "postgresql: server does not offer TLS"
	}
	return r, true
}

// probeAMQP sends the AMQP 0-9-1 protocol header and parses Connection.Start.
func probeAMQP(ctx context.Context, addr string) (probeResult, bool) {
	conn, err := probeDialer(ctx, addr)
	if err != nil {
		return probeResult{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(protocolProbeTimeout))
	if _, err := conn.Write([]byte("AMQP\x00\x00\x09\x01")); err != nil {
		return probeResult{}, false
	}
	br := bufio.NewReader(conn)
	hdr := make([]byte, 7)
	if _, err := readFull(br, hdr); err != nil {
		return probeResult{}, false
	}
	if bytes.HasPrefix(hdr, []byte("AMQP")) {
		// Server rejected our version and replied with the one it speaks.
		return probeResult{service: "amqp", product: "AMQP broker"}, true
	}
	if hdr[0] != 1 || binary.BigEndian.Uint16(hdr[1:3]) != 0 {
		return probeResult{}, false
	}
	size := binary.BigEndian.Uint32(hdr[3:7])
	if size < 4 || size > 1<<16 {
		return probeResult{}, false
	}
	payload := make([]byte, size)
	if _, err := readFull(br, payload); err != nil {
		return probeResult{}, false
	}
	props, ok := parseAMQPConnectionStart(payload)
	if !ok {
		return probeResult{}, false
	}
	r := probeResult{service: "amqp", product: props["product"], version: props["version"]}
	if r.product == "" {
		r.product = "AMQP broker"
	}
	if p := props["platform"]; p != "" {
		r.note = "platform " + p
	}
	return r, true
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// parseAMQPConnectionStart reads the server-properties table of a Connection.Start method
// frame payload (class 10, method 10) and returns its string fields.
func parseAMQPConnectionStart(p []byte) (map[string]string, bool) {
	if len(p) < 4+2+4 || binary.BigEndian.Uint16(p[0:2]) != 10 || binary.BigEndian.Uint16(p[2:4]) != 10 {
		return nil, false
	}
	p = p[6:] // class, method, version-major, version-minor
	tblLen := int(binary.BigEndian.Uint32(p[0:4]))
	p = p[4:]
	if tblLen > len(p) {
		return nil, false
	}
	tbl := p[:tblLen]
	out := map[string]string{}
	for len(tbl) > 0 {
		kl := int(tbl[0])
		if 1+kl+1 > len(tbl) {
			break
		}
		key := string(tbl[1 : 1+kl])
		typ := tbl[1+kl]
		tbl = tbl[2+kl:]
		switch typ {
		case 'S':
			if len(tbl) < 4 {
				return out, true
			}
			l := int(binary.BigEndian.Uint32(tbl[0:4]))
			if 4+l > len(tbl) {
				return out, true
			}
			out[key] = sanitizePrintable(string(tbl[4 : 4+l]))
			tbl = tbl[4+l:]
		case 'F':
			if len(tbl) < 4 {
				return out, true
			}
			l := int(binary.BigEndian.Uint32(tbl[0:4]))
			if 4+l > len(tbl) {
				return out, true
			}
			tbl = tbl[4+l:]
		case 't', 'b', 'B':
			tbl = tbl[min(1, len(tbl)):]
		case 's', 'u':
			tbl = tbl[min(2, len(tbl)):]
		case 'I', 'i', 'f':
			tbl = tbl[min(4, len(tbl)):]
		case 'l', 'L', 'd', 'T':
			tbl = tbl[min(8, len(tbl)):]
		default:
			return out, true // unknown field type: stop, keep what we have
		}
	}
	return out, true
}

// probeRedis sends PING. +PONG without AUTH means anyone can read and write the data.
func probeRedis(ctx context.Context, addr string) (probeResult, bool) {
	resp, err := probeExchange(ctx, addr, []byte("PING\r\n"), 256)
	if err != nil && len(resp) == 0 {
		return probeResult{}, false
	}
	line := strings.TrimSpace(string(resp))
	switch {
	case strings.HasPrefix(line, "+PONG"):
		return probeResult{service: "redis", product: "Redis key-value store", tags: []string{"redis-no-auth"},
			note: "redis: no authentication (PING answered +PONG)"}, true
	case strings.HasPrefix(line, "-NOAUTH"), strings.HasPrefix(line, "-DENIED"), strings.Contains(line, "Authentication required"):
		return probeResult{service: "redis", product: "Redis key-value store", note: "redis: authentication required"}, true
	}
	return probeResult{}, false
}

// probeFTPAnonymous tries the standard anonymous login (RFC 1635) and quits.
func probeFTPAnonymous(ctx context.Context, addr string) (probeResult, bool) {
	conn, err := probeDialer(ctx, addr)
	if err != nil {
		return probeResult{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * protocolProbeTimeout))
	br := bufio.NewReader(conn)
	code := func() int {
		// Multi-line replies: "230-..." continue until "230 ".
		for i := 0; i < 50; i++ {
			line, err := br.ReadString('\n')
			if len(line) >= 4 && line[3] == ' ' {
				n, _ := strconv.Atoi(line[:3])
				return n
			}
			if err != nil {
				return 0
			}
		}
		return 0
	}
	if code() != 220 {
		return probeResult{}, false
	}
	fmt.Fprintf(conn, "USER anonymous\r\n")
	c := code()
	if c == 331 {
		fmt.Fprintf(conn, "PASS dzieciol@example.invalid\r\n")
		c = code()
	}
	fmt.Fprintf(conn, "QUIT\r\n")
	if c == 230 {
		return probeResult{service: "ftp", tags: []string{"ftp-anonymous"}, note: "ftp: anonymous login allowed"}, true
	}
	return probeResult{}, false
}
