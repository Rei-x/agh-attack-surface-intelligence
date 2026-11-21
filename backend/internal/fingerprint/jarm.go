package fingerprint

// JARM active TLS server fingerprinting.
//
// Port of the reference algorithm published by Salesforce
// (https://github.com/salesforce/jarm, jarm.py v1.0, BSD-3-Clause,
// Althouse/Smart/Nunaly/Brady). Ten deliberately varied TLS ClientHello
// messages are sent; for every ServerHello we record the chosen cipher,
// the record version and the ALPN/extension list. The 62-character hash is:
//
//	10 x (2 hex chars: cipher index + 1 char: version)   = 30 chars
//	+ first 32 hex chars of SHA-256(all ALPNs + extension lists)
//
// Identical JARM means identical TLS stack + configuration (same library,
// version, cipher preference and extension order), which is useful for
// clustering ("these 40 hosts run the same appliance") and custom signatures.
//
// Safety: each probe is a single ClientHello on a fresh TCP connection. We read
// only the first server flight (≤1484 bytes, as jarm.py does), never complete a
// handshake, never send application data and close immediately. Every probe goes
// through the scanner's RateLimiter and the whole run has a hard time budget.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const (
	// JARMEmpty is the reference "no TLS answer to any probe" value.
	JARMEmpty = "00000000000000000000000000000000000000000000000000000000000000"

	// DefaultJARMProbeTimeout bounds a single probe (connect + ServerHello read).
	DefaultJARMProbeTimeout = 4 * time.Second
	// DefaultJARMBudget bounds the complete 10-probe run per service.
	DefaultJARMBudget = 15 * time.Second

	jarmRecvBytes = 1484 // jarm.py: sock.recv(1484)
)

// jarmProbe mirrors the jarm.py "jarm_details" array.
type jarmProbe struct {
	version     string // TLS_1.1, TLS_1.2, TLS_1.3
	cipherList  string // ALL, NO1.3
	cipherOrder string // FORWARD, REVERSE, TOP_HALF, BOTTOM_HALF, MIDDLE_OUT
	grease      bool
	rareALPN    bool
	support     string // 1.2_SUPPORT, NO_SUPPORT, 1.3_SUPPORT
	extOrder    string // FORWARD, REVERSE
}

// jarmProbes is the fixed probe queue from jarm.py main(), in order.
var jarmProbes = [10]jarmProbe{
	{"TLS_1.2", "ALL", "FORWARD", false, false, "1.2_SUPPORT", "REVERSE"},
	{"TLS_1.2", "ALL", "REVERSE", false, false, "1.2_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "TOP_HALF", false, false, "NO_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "BOTTOM_HALF", false, true, "NO_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "MIDDLE_OUT", true, true, "NO_SUPPORT", "REVERSE"},
	{"TLS_1.1", "ALL", "FORWARD", false, false, "NO_SUPPORT", "FORWARD"},
	{"TLS_1.3", "ALL", "FORWARD", false, false, "1.3_SUPPORT", "REVERSE"},
	{"TLS_1.3", "ALL", "REVERSE", false, false, "1.3_SUPPORT", "FORWARD"},
	{"TLS_1.3", "NO1.3", "FORWARD", false, false, "1.3_SUPPORT", "FORWARD"},
	{"TLS_1.3", "ALL", "MIDDLE_OUT", true, false, "1.3_SUPPORT", "REVERSE"},
}

func u16s(vals ...uint16) [][]byte {
	out := make([][]byte, len(vals))
	for i, v := range vals {
		out[i] = []byte{byte(v >> 8), byte(v)}
	}
	return out
}

var (
	jarmCiphersAll  = []uint16{0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304, 0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005}
	jarmCiphersNo13 = []uint16{0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005}
	// jarmCipherIndex is the ordered list used by cipher_bytes() for the fuzzy hash.
	jarmCipherIndex = []uint16{0x0004, 0x0005, 0x0007, 0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c, 0x003d, 0x0041, 0x0045, 0x0067, 0x006b, 0x0084, 0x0088, 0x009a, 0x009c, 0x009d, 0x009e, 0x009f, 0x00ba, 0x00be, 0x00c0, 0x00c4, 0xc007, 0xc008, 0xc009, 0xc00a, 0xc011, 0xc012, 0xc013, 0xc014, 0xc023, 0xc024, 0xc027, 0xc028, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xc060, 0xc061, 0xc072, 0xc073, 0xc076, 0xc077, 0xc09c, 0xc09d, 0xc09e, 0xc09f, 0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af, 0xcc13, 0xcc14, 0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305}

	jarmALPNAll = [][]byte{
		[]byte("\x08http/0.9"), []byte("\x08http/1.0"), []byte("\x08http/1.1"),
		[]byte("\x06spdy/1"), []byte("\x06spdy/2"), []byte("\x06spdy/3"),
		[]byte("\x02h2"), []byte("\x03h2c"), []byte("\x02hq"),
	}
	jarmALPNRare = [][]byte{
		[]byte("\x08http/0.9"), []byte("\x08http/1.0"),
		[]byte("\x06spdy/1"), []byte("\x06spdy/2"), []byte("\x06spdy/3"),
		[]byte("\x03h2c"), []byte("\x02hq"),
	}
)

// jarmMung reproduces jarm.py cipher_mung() (also used for ALPN/version order).
func jarmMung(items [][]byte, request string) [][]byte {
	n := len(items)
	var out [][]byte
	switch request {
	case "REVERSE":
		out = make([][]byte, n)
		for i := range items {
			out[i] = items[n-1-i]
		}
	case "BOTTOM_HALF":
		if n%2 == 1 {
			out = append(out, items[n/2+1:]...)
		} else {
			out = append(out, items[n/2:]...)
		}
	case "TOP_HALF":
		if n%2 == 1 {
			out = append(out, items[n/2])
		}
		out = append(out, jarmMung(jarmMung(items, "REVERSE"), "BOTTOM_HALF")...)
	case "MIDDLE_OUT":
		middle := n / 2
		if n%2 == 1 {
			out = append(out, items[middle])
			for i := 1; i <= middle; i++ {
				out = append(out, items[middle+i], items[middle-i])
			}
		} else {
			for i := 1; i <= middle; i++ {
				out = append(out, items[middle-1+i], items[middle-i])
			}
		}
	default:
		out = append(out, items...)
	}
	return out
}

// jarmEntropy supplies the random parts of a ClientHello. Tests inject a
// deterministic implementation to compare bytes against jarm.py.
type jarmEntropy interface {
	Random(n int) []byte
	Grease() []byte
}

type cryptoEntropy struct{}

func (cryptoEntropy) Random(n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return b
}

func (cryptoEntropy) Grease() []byte {
	v, err := rand.Int(rand.Reader, big.NewInt(16))
	g := byte(0x0a)
	if err == nil {
		g = byte(v.Int64())<<4 | 0x0a
	}
	return []byte{g, g}
}

func be16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

// buildJARMClientHello reproduces jarm.py packet_building() byte for byte.
// Entropy is consumed in the same order as jarm.py: client random, session id,
// cipher GREASE, extension GREASE, key-share GREASE, key share, version GREASE.
func buildJARMClientHello(p jarmProbe, host string, ent jarmEntropy) []byte {
	var recordVer, helloVer []byte
	switch p.version {
	case "TLS_1.3":
		recordVer, helloVer = []byte{3, 1}, []byte{3, 3}
	case "SSLv3":
		recordVer, helloVer = []byte{3, 0}, []byte{3, 0}
	case "TLS_1":
		recordVer, helloVer = []byte{3, 1}, []byte{3, 1}
	case "TLS_1.1":
		recordVer, helloVer = []byte{3, 2}, []byte{3, 2}
	default: // TLS_1.2
		recordVer, helloVer = []byte{3, 3}, []byte{3, 3}
	}

	ch := append([]byte{}, helloVer...)
	ch = append(ch, ent.Random(32)...)
	sid := ent.Random(32)
	ch = append(ch, byte(len(sid)))
	ch = append(ch, sid...)

	// Cipher suites.
	var ciphers [][]byte
	if p.cipherList == "NO1.3" {
		ciphers = u16s(jarmCiphersNo13...)
	} else {
		ciphers = u16s(jarmCiphersAll...)
	}
	if p.cipherOrder != "FORWARD" {
		ciphers = jarmMung(ciphers, p.cipherOrder)
	}
	if p.grease {
		ciphers = append([][]byte{ent.Grease()}, ciphers...)
	}
	var suites []byte
	for _, c := range ciphers {
		suites = append(suites, c...)
	}
	ch = append(ch, be16(len(suites))...)
	ch = append(ch, suites...)
	ch = append(ch, 0x01, 0x00) // one compression method: null

	ch = append(ch, jarmExtensions(p, host, ent)...)

	hs := []byte{0x01, 0x00}
	hs = append(hs, be16(len(ch))...)
	hs = append(hs, ch...)

	pkt := []byte{0x16}
	pkt = append(pkt, recordVer...)
	pkt = append(pkt, be16(len(hs))...)
	pkt = append(pkt, hs...)
	return pkt
}

func jarmExtensions(p jarmProbe, host string, ent jarmEntropy) []byte {
	var all []byte
	if p.grease {
		all = append(all, ent.Grease()...)
		all = append(all, 0x00, 0x00)
	}
	// server_name
	all = append(all, 0x00, 0x00)
	all = append(all, be16(len(host)+5)...)
	all = append(all, be16(len(host)+3)...)
	all = append(all, 0x00)
	all = append(all, be16(len(host))...)
	all = append(all, host...)

	all = append(all, 0x00, 0x17, 0x00, 0x00)                                                             // extended_master_secret
	all = append(all, 0x00, 0x01, 0x00, 0x01, 0x01)                                                       // max_fragment_length
	all = append(all, 0xff, 0x01, 0x00, 0x01, 0x00)                                                       // renegotiation_info
	all = append(all, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19) // supported_groups
	all = append(all, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)                                                 // ec_point_formats
	all = append(all, 0x00, 0x23, 0x00, 0x00)                                                             // session_ticket

	// ALPN
	alpns := jarmALPNAll
	if p.rareALPN {
		alpns = jarmALPNRare
	}
	if p.extOrder != "FORWARD" {
		alpns = jarmMung(alpns, p.extOrder)
	}
	var alpnBytes []byte
	for _, a := range alpns {
		alpnBytes = append(alpnBytes, a...)
	}
	all = append(all, 0x00, 0x10)
	all = append(all, be16(len(alpnBytes)+2)...)
	all = append(all, be16(len(alpnBytes))...)
	all = append(all, alpnBytes...)

	// signature_algorithms
	all = append(all, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01)

	// key_share (x25519, random public value as in jarm.py)
	var share []byte
	if p.grease {
		share = append(share, ent.Grease()...)
		share = append(share, 0x00, 0x01, 0x00)
	}
	share = append(share, 0x00, 0x1d, 0x00, 0x20)
	share = append(share, ent.Random(32)...)
	all = append(all, 0x00, 0x33)
	all = append(all, be16(len(share)+2)...)
	all = append(all, be16(len(share))...)
	all = append(all, share...)

	all = append(all, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01) // psk_key_exchange_modes

	if p.version == "TLS_1.3" || p.support == "1.2_SUPPORT" {
		vers := u16s(0x0301, 0x0302, 0x0303, 0x0304)
		if p.support == "1.2_SUPPORT" {
			vers = vers[:3]
		}
		if p.extOrder != "FORWARD" {
			vers = jarmMung(vers, p.extOrder)
		}
		var vb []byte
		if p.grease {
			vb = append(vb, ent.Grease()...)
		}
		for _, v := range vers {
			vb = append(vb, v...)
		}
		all = append(all, 0x00, 0x2b)
		all = append(all, be16(len(vb)+1)...)
		all = append(all, byte(len(vb)))
		all = append(all, vb...)
	}

	out := be16(len(all))
	return append(out, all...)
}

// pyBytes emulates Python slice semantics (clamped, never panics).
type pyBytes []byte

func (b pyBytes) slice(lo, hi int) []byte {
	if lo > len(b) {
		lo = len(b)
	}
	if hi > len(b) {
		hi = len(b)
	}
	if hi < lo {
		hi = lo
	}
	return b[lo:hi]
}

func beInt(b []byte) int {
	n := 0
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return n
}

var errJARMParse = errors.New("jarm parse error")

// parseJARMServerHello reproduces jarm.py read_packet(): it returns
// "cipher|version|alpn|ext-ext-..." or "|||" when no usable ServerHello came back.
// Offsets and error handling intentionally mirror the reference, quirks included,
// so that fingerprints are comparable with public JARM datasets.
func parseJARMServerHello(raw []byte) string {
	data := pyBytes(raw)
	if len(data) == 0 {
		return "|||"
	}
	if data[0] == 21 { // alert
		return "|||"
	}
	if len(data) < 6 || !(data[0] == 22 && data[5] == 2) {
		return "|||"
	}
	shLen := beInt(data.slice(3, 5))
	if len(data) <= 43 {
		return "|||"
	}
	counter := int(data[43])
	cipher := hex.EncodeToString(data.slice(counter+44, counter+46))
	version := hex.EncodeToString(data.slice(9, 11))
	ext, err := jarmExtractExtensions(data, counter, shLen)
	if err != nil {
		return "|||"
	}
	return cipher + "|" + version + "|" + ext
}

func jarmExtractExtensions(data pyBytes, counter, shLen int) (string, error) {
	if counter+47 >= len(data) { // IndexError in reference
		return "|", nil
	}
	if data[counter+47] == 11 {
		return "|", nil
	}
	if string(data.slice(counter+50, counter+53)) == "\x0e\xac\x0b" || string(data.slice(82, 85)) == "\x0f\xf0\x0b" {
		return "|", nil
	}
	if counter+42 >= shLen {
		return "|", nil
	}
	count := 49 + counter
	length := beInt(data.slice(counter+47, counter+49))
	maximum := length + (count - 1)
	var types [][]byte
	var values [][]byte
	var empty []bool
	for count < maximum {
		types = append(types, data.slice(count, count+2))
		lb := data.slice(count+2, count+4)
		if len(lb) == 0 { // int('', 16) -> ValueError in reference
			return "", errJARMParse
		}
		extLen := beInt(lb)
		if extLen == 0 {
			count += 4
			values = append(values, nil)
			empty = append(empty, true)
		} else {
			values = append(values, data.slice(count+4, count+4+extLen))
			empty = append(empty, false)
			count += extLen + 4
		}
	}
	alpn := ""
	for i, t := range types {
		if string(t) == "\x00\x10" {
			if empty[i] { // ""[3:].decode() -> AttributeError in reference
				return "", errJARMParse
			}
			v := pyBytes(values[i]).slice(3, len(values[i]))
			if !utf8.Valid(v) {
				return "", errJARMParse
			}
			alpn = string(v)
			break
		}
	}
	hexTypes := make([]string, len(types))
	for i, t := range types {
		hexTypes[i] = hex.EncodeToString(t)
	}
	return alpn + "|" + strings.Join(hexTypes, "-"), nil
}

// JARMHash reproduces jarm.py jarm_hash() from the 10 raw probe results.
func JARMHash(raw []string) string {
	allEmpty := true
	for _, r := range raw {
		if r != "|||" {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return JARMEmpty
	}
	var fuzzy strings.Builder
	var alpnExt strings.Builder
	for _, hs := range raw {
		comp := strings.Split(hs, "|")
		for len(comp) < 4 {
			comp = append(comp, "")
		}
		fuzzy.WriteString(jarmCipherByte(comp[0]))
		fuzzy.WriteString(jarmVersionByte(comp[1]))
		alpnExt.WriteString(comp[2])
		alpnExt.WriteString(comp[3])
	}
	sum := sha256.Sum256([]byte(alpnExt.String()))
	fuzzy.WriteString(hex.EncodeToString(sum[:])[:32])
	return fuzzy.String()
}

func jarmCipherByte(cipher string) string {
	if cipher == "" {
		return "00"
	}
	count := 1
	for _, c := range jarmCipherIndex {
		if cipher == hex.EncodeToString([]byte{byte(c >> 8), byte(c)}) {
			break
		}
		count++
	}
	h := strconv.FormatInt(int64(count), 16)
	if len(h) < 2 {
		h = "0" + h
	}
	return h
}

func jarmVersionByte(version string) string {
	if version == "" {
		return "0"
	}
	if len(version) < 4 {
		return "0"
	}
	n, err := strconv.Atoi(version[3:4])
	if err != nil || n < 0 || n > 5 {
		return "0"
	}
	return string("abcdef"[n])
}

// JARMOptions controls a JARM run.
type JARMOptions struct {
	ProbeTimeout time.Duration                                // per probe; default 4s
	Budget       time.Duration                                // whole run; default 15s
	RateLimiter  func(ctx context.Context, host string) error // called before every probe
	Dialer       func(ctx context.Context, network, addr string) (net.Conn, error)
}

// JARMResult carries the hash plus the pre-hash per-probe results (explainability).
type JARMResult struct {
	Hash      string
	Raw       []string
	Responses [][]byte // first server flight per probe (nil on error); for KAT/debugging
}

var errJARMTimeout = errors.New("jarm probe timeout")

// ComputeJARM fingerprints the TLS server at ip:port. sni is the value placed in
// the server_name extension (domain if known, otherwise the IP, as jarm.py does).
// A timeout on any probe aborts the run and yields JARMEmpty, matching jarm.py.
func ComputeJARM(ctx context.Context, ip string, port int, sni string, opts JARMOptions) (JARMResult, error) {
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = DefaultJARMProbeTimeout
	}
	if opts.Budget <= 0 {
		opts.Budget = DefaultJARMBudget
	}
	if sni == "" {
		sni = ip
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Budget)
	defer cancel()

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	raw := make([]string, 0, len(jarmProbes))
	resps := make([][]byte, 0, len(jarmProbes))
	ent := cryptoEntropy{}
	for _, p := range jarmProbes {
		if opts.RateLimiter != nil {
			if err := opts.RateLimiter(ctx, ip); err != nil {
				return JARMResult{}, err
			}
		}
		pkt := buildJARMClientHello(p, sni, ent)
		resp, err := jarmSend(ctx, addr, pkt, opts)
		if errors.Is(err, errJARMTimeout) {
			return JARMResult{Hash: JARMEmpty, Raw: emptyJARMRaw()}, err
		}
		if ctx.Err() != nil {
			return JARMResult{}, ctx.Err()
		}
		if err != nil {
			raw = append(raw, "|||")
			resps = append(resps, nil)
			continue
		}
		raw = append(raw, parseJARMServerHello(resp))
		resps = append(resps, resp)
	}
	return JARMResult{Hash: JARMHash(raw), Raw: raw, Responses: resps}, nil
}

func emptyJARMRaw() []string {
	out := make([]string, len(jarmProbes))
	for i := range out {
		out[i] = "|||"
	}
	return out
}

// jarmSend writes one ClientHello and reads the first server flight.
// Unlike a single recv() we keep reading until the first TLS record is complete
// (or 1484 bytes / timeout), which is more robust on segmented paths and gives
// identical results whenever jarm.py receives the full ServerHello.
func jarmSend(ctx context.Context, addr string, pkt []byte, opts JARMOptions) ([]byte, error) {
	pctx, cancel := context.WithTimeout(ctx, opts.ProbeTimeout)
	defer cancel()
	dial := opts.Dialer
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	conn, err := dial(pctx, "tcp", addr)
	if err != nil {
		if isTimeoutErr(err) && ctx.Err() == nil {
			return nil, errJARMTimeout
		}
		return nil, err
	}
	defer conn.Close()
	deadline, _ := pctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, jarmRecvBytes)
	tmp := make([]byte, jarmRecvBytes)
	for len(buf) < jarmRecvBytes {
		n, err := conn.Read(tmp[:jarmRecvBytes-len(buf)])
		buf = append(buf, tmp[:n]...)
		if len(buf) >= 5 {
			recLen := int(binary.BigEndian.Uint16(buf[3:5]))
			if len(buf) >= 5+recLen {
				break
			}
		}
		if err != nil {
			if len(buf) > 0 {
				break
			}
			if isTimeoutErr(err) && ctx.Err() == nil {
				return nil, errJARMTimeout
			}
			return nil, err
		}
	}
	return buf, nil
}

func isTimeoutErr(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// IsMeaningfulJARM reports whether a hash carries information (not empty/zero).
func IsMeaningfulJARM(h string) bool {
	return len(h) == 62 && h != JARMEmpty
}

// attachJARM is the single hook used by probeWithScheme: when the probed port
// spoke TLS it computes the JARM fingerprint with the same rate limiter and a
// bounded budget. Failures are silent (JARM is best-effort enrichment).
func (f *Fingerprinter) attachJARM(ctx context.Context, fp *domain.HTTPFingerprint, scheme, ip string, port int, sni string, opts Options) {
	if opts.DisableJARM || scheme != "https" || fp == nil || fp.TLS == nil {
		return
	}
	probeTimeout := opts.Timeout
	if probeTimeout <= 0 || probeTimeout > DefaultJARMProbeTimeout {
		probeTimeout = DefaultJARMProbeTimeout
	}
	res, err := ComputeJARM(ctx, ip, port, sni, JARMOptions{
		ProbeTimeout: probeTimeout,
		Budget:       DefaultJARMBudget,
		RateLimiter:  opts.RateLimiter,
	})
	if err != nil || !IsMeaningfulJARM(res.Hash) {
		return
	}
	fp.TLS.JARM = res.Hash
}
