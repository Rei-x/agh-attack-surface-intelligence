package scanner

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Discovery of a mostly empty range without nmap: every probe to a dead IP times out. That
// must not be read as target noise, or the global rate collapses to MinRate.
func TestPureGoDiscoveryDeadSpaceDoesNotThrottle(t *testing.T) {
	gov := NewGovernor(GovernorConfig{GlobalRatePerSec: 2000, PerHostRatePerSec: 1000, MinRatePerSec: 200})
	r := &NmapRunner{UseNmap: false, Concurrency: 16, ConnectTimeout: time.Millisecond}
	r.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		switch {
		case host == "10.9.0.7": // live host, closed port -> RST
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
		default: // dead space
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}
		}
	}
	var ips []string
	for i := 1; i <= 254; i++ {
		ips = append(ips, "10.9.0."+strconv.Itoa(i))
	}
	alive, err := r.discoverPureGo(context.Background(), ips, []int{22, 80, 443}, gov)
	if err != nil {
		t.Fatal(err)
	}
	if len(alive) != 1 || alive[0] != "10.9.0.7" {
		t.Fatalf("a refused connection proves the host is up; alive=%v", alive)
	}
	st := gov.Stats()
	if st.ThrottleCount != 0 || st.TimeoutCount != 0 || st.CurrentRate != 2000 {
		t.Fatalf("dead-space timeouts throttled the governor: %+v", st)
	}
}

// Filtered ports on a live host (firewall DROP) time out too; that is not distress either.
func TestPureGoServiceScanFilteredPortsDoNotThrottle(t *testing.T) {
	gov := NewGovernor(GovernorConfig{GlobalRatePerSec: 2000, PerHostRatePerSec: 1000, MinRatePerSec: 200})
	r := &NmapRunner{UseNmap: false, Concurrency: 8, ConnectTimeout: time.Millisecond, BannerReadTimeout: time.Millisecond}
	r.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}
	}
	if _, _, err := r.ScanServicesPureGo(context.Background(), []string{"10.9.0.7", "10.9.0.8"}, []int{21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443}, gov); err != nil {
		t.Fatal(err)
	}
	if st := gov.Stats(); st.ThrottleCount != 0 || st.CurrentRate != 2000 {
		t.Fatalf("filtered-port timeouts throttled the governor: %+v", st)
	}
	// Mid-handshake resets on a live host still count.
	r.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}
	}
	_, _, _ = r.ScanServicesPureGo(context.Background(), []string{"10.9.0.7"}, []int{21, 22, 23, 25, 80, 443}, gov)
	if st := gov.Stats(); st.RSTCount == 0 || st.ThrottleCount == 0 {
		t.Fatalf("reset burst not recorded: %+v (err text %q)", st, strings.ToLower(syscall.ECONNRESET.Error()))
	}
}

// One silent host timing out over and over backs off only that host; the same number of
// timeouts spread over several hosts backs off globally; neither slows nmap (distress = 1).
// Explicit distress (429) slows nmap shares too.
func TestGovernorTimeoutsSingleHostVsManyAndDistress(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	gov := NewGovernor(GovernorConfig{GlobalRatePerSec: 100, PerHostRatePerSec: 20, MinRatePerSec: 10,
		ErrorThreshold: 5, ErrorWindow: 10 * time.Second, Now: func() time.Time { return now }})
	for i := 0; i < 20; i++ {
		gov.RecordTimeout("10.9.0.7")
	}
	if r := gov.CurrentRate(); r != 100 {
		t.Fatalf("single silent host throttled the whole scan: rate=%.1f", r)
	}
	gov.mu.Lock()
	hostRate := gov.perHost["10.9.0.7"].rate
	gov.mu.Unlock()
	if hostRate >= 20 {
		t.Fatalf("silent host's own bucket not backed off: %.1f", hostRate)
	}
	for i := 0; i < 5; i++ {
		gov.RecordTimeout("10.9.1." + strconv.Itoa(i))
	}
	if r := gov.CurrentRate(); r != 50 {
		t.Fatalf("multi-host timeouts should halve the global rate, got %.1f", r)
	}
	if f := gov.DistressFactor(); f != 1 {
		t.Fatalf("timeouts must not slow nmap shares, distress=%.2f", f)
	}
	gov.RecordHTTPStatus("10.9.0.9", 429)
	gov.RecordHTTPStatus("10.9.0.9", 429)
	gov.RecordHTTPStatus("10.9.0.9", 429)
	if f := gov.DistressFactor(); f != 0.5 {
		t.Fatalf("explicit 429 distress should halve nmap shares, distress=%.2f", f)
	}
}

