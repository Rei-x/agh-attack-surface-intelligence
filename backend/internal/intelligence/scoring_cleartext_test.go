package intelligence

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// A router with telnet + FTP open must land in the high band (the change log calls these
// exposures HIGH, the score has to agree), and the host score has to explain why.
func TestCleartextAdminProtocolsScoreHigh(t *testing.T) {
	telnet := domain.Service{Port: 23, Protocol: "tcp", State: "open", ServiceName: "telnet"}
	ftp := domain.Service{Port: 21, Protocol: "tcp", State: "open", ServiceName: "ftp"}
	telnet.Interestingness, telnet.InterestingFactors = ScoreService(&telnet, nil)
	ftp.Interestingness, ftp.InterestingFactors = ScoreService(&ftp, nil)
	if telnet.Interestingness < 45 || ftp.Interestingness < 35 {
		t.Fatalf("telnet=%d ftp=%d, want >=45 / >=35", telnet.Interestingness, ftp.Interestingness)
	}
	// Service name wins over port: HTTP on 23 is not telnet, telnet on 2323 is.
	h23 := domain.Service{Port: 23, ServiceName: "http"}
	if s, _ := ScoreService(&h23, nil); s != 0 {
		t.Fatalf("http on port 23 scored %d", s)
	}
	t2323 := domain.Service{Port: 2323, ServiceName: "telnet"}
	if s, _ := ScoreService(&t2323, nil); s < 45 {
		t.Fatalf("telnet on 2323 scored %d", s)
	}
	host := &domain.Host{IP: "10.0.0.1", LifecycleState: domain.HostStateActive}
	score, factors := ScoreHost(host, []domain.Service{telnet, ftp}, nil)
	if score < 50 {
		t.Fatalf("router host score %d, want >= 50 (factors %+v)", score, factors)
	}
	if len(factors) < 2 || factors[0].Points != telnet.Interestingness {
		t.Fatalf("host factors do not explain the score: %+v", factors)
	}
}
