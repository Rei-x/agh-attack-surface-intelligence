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

