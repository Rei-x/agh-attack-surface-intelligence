package fingerprint

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// katEntropy mirrors the deterministic os.urandom/random.choice patch used by
// testdata/jarm/katgen.py when it generated the golden ClientHellos from the
// reference jarm.py: urandom yields a running byte counter, choice() cycles.
type katEntropy struct {
	ctr  int
	gctr int
}

var katGreaseList = []byte{0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a, 0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa}

func (k *katEntropy) Random(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(k.ctr & 0xff)
		k.ctr++
	}
	return b
}

func (k *katEntropy) Grease() []byte {
	g := katGreaseList[k.gctr%len(katGreaseList)]
	k.gctr++
	return []byte{g, g}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// TestJARMClientHelloMatchesReference checks all 10 probes byte-for-byte against
// packet_building() from Salesforce jarm.py (same entropy stream).
func TestJARMClientHelloMatchesReference(t *testing.T) {
	golden := readLines(t, filepath.Join("testdata", "jarm", "clienthello_golden.txt"))
	if len(golden) != 10 {
		t.Fatalf("expected 10 golden ClientHellos, got %d", len(golden))
	}
	ent := &katEntropy{}
	for i, p := range jarmProbes {
		got := hex.EncodeToString(buildJARMClientHello(p, "kat.example", ent))
		if got != golden[i] {
			t.Fatalf("probe %d ClientHello differs from jarm.py\n got: %s\nwant: %s", i+1, got, golden[i])
		}
	}
}

// TestJARMParseAndHashKnownAnswers replays real server flights captured from
// OpenSSL 3.0 s_server, Go crypto/tls and nginx 1.27 (h2) and compares the
// per-probe raw strings and the final hash with jarm.py read_packet()/jarm_hash()
// evaluated on the same bytes. The same hashes were also produced by running
// `python3 jarm.py` live against those servers.
func TestJARMParseAndHashKnownAnswers(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "jarm", "*.kat"))
	if len(files) < 3 {
		t.Fatalf("expected at least 3 KAT files, got %d", len(files))
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			lines := readLines(t, f)
			if len(lines) != 21 {
				t.Fatalf("malformed KAT: %d lines", len(lines))
			}
			raws := make([]string, 10)
			for i := 0; i < 10; i++ {
				var resp []byte
				if lines[i] != "" {
					var err error
					resp, err = hex.DecodeString(lines[i])
					if err != nil {
						t.Fatal(err)
					}
				}
				raws[i] = parseJARMServerHello(resp)
				if raws[i] != lines[10+i] {
					t.Errorf("probe %d raw = %q, jarm.py = %q", i+1, raws[i], lines[10+i])
				}
			}
			if got, want := JARMHash(raws), lines[20]; got != want {
				t.Errorf("hash = %s, jarm.py = %s", got, want)
			}
		})
	}
}

func TestJARMHashEmptyAndEdgeCases(t *testing.T) {
	if got := JARMHash(emptyJARMRaw()); got != JARMEmpty {
		t.Fatalf("all-empty raw should give 62 zeros, got %s", got)
	}
	if parseJARMServerHello(nil) != "|||" || parseJARMServerHello([]byte{21, 3, 3, 0, 2, 2, 40}) != "|||" {
		t.Fatal("nil response / alert must map to |||")
	}
	if parseJARMServerHello([]byte{22, 3, 3}) != "|||" {
		t.Fatal("truncated record must map to |||")
	}
	if jarmCipherByte("c02f") != "29" || jarmCipherByte("") != "00" || jarmCipherByte("ffff") != "46" {
		t.Fatal("cipher index mapping differs from reference")
	}
	if jarmVersionByte("0303") != "d" || jarmVersionByte("0301") != "b" {
		t.Fatal("version byte mapping differs from reference")
	}
}

func splitHostPortInt(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func TestComputeJARMLiveLocalServerIsStableAndRateLimited(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // JARM probes intentionally abort handshakes
	srv.StartTLS()
	defer srv.Close()
	host, port := splitHostPortInt(t, srv.Listener.Addr().String())

	var calls int32
	opts := JARMOptions{
		ProbeTimeout: 2 * time.Second,
		RateLimiter: func(ctx context.Context, h string) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}
	a, err := ComputeJARM(context.Background(), host, port, "", opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ComputeJARM(context.Background(), host, port, "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if !IsMeaningfulJARM(a.Hash) {
		t.Fatalf("expected meaningful JARM, got %q (raw %v)", a.Hash, a.Raw)
	}
	if a.Hash != b.Hash {
		t.Fatalf("JARM not stable: %s vs %s", a.Hash, b.Hash)
	}
	if calls != 20 {
		t.Fatalf("rate limiter must be consulted once per probe, got %d calls for 2 runs", calls)
	}
	if !strings.Contains(strings.Join(a.Raw, ","), "|0303|") {
		t.Fatalf("unexpected raw: %v", a.Raw)
	}
}

func TestComputeJARMTimeoutYieldsEmpty(t *testing.T) {
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
			go func() { time.Sleep(2 * time.Second); c.Close() }() // silent server
		}
	}()
	host, port := splitHostPortInt(t, ln.Addr().String())
	start := time.Now()
	res, err := ComputeJARM(context.Background(), host, port, "", JARMOptions{ProbeTimeout: 200 * time.Millisecond})
	if err == nil || res.Hash != JARMEmpty {
		t.Fatalf("expected timeout + empty hash, got %q err=%v", res.Hash, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout must abort the run after the first silent probe (jarm.py semantics)")
	}
}

func TestComputeJARMRespectsBudget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host, port := splitHostPortInt(t, ln.Addr().String())
	start := time.Now()
	_, err = ComputeJARM(context.Background(), host, port, "", JARMOptions{ProbeTimeout: 5 * time.Second, Budget: 150 * time.Millisecond})
	if err == nil {
		t.Fatal("expected budget error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("budget not enforced")
	}
}
