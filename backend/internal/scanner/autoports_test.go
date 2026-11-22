package scanner

import (
	"context"
	"testing"
)

func TestAutoPortsBySize(t *testing.T) {
	full, err := ParsePorts(AutoPorts(1))
	if err != nil || len(full) != 65535 {
		t.Fatalf("1 IP: want 65535 ports, got %d (%v)", len(full), err)
	}
	top, err := ParsePorts(AutoPorts(256))
	if err != nil {
		t.Fatal(err)
	}
	if len(top) < 1000 || len(top) > 1300 {
		t.Fatalf("/24: want top 1000 + extras, got %d ports", len(top))
	}
	set := map[int]bool{}
	for _, p := range top {
		set[p] = true
	}
	// Every port of the jury lab template must be in the /24 list too.
	for _, p := range []int{21, 80, 81, 443, 2223, 3001, 5673, 6379, 8080, 8081, 8085, 8086, 8088, 8089, 8090, 8474, 8787, 8888, 15432, 15673} {
		if !set[p] {
			t.Errorf("port %d missing from the top-1000+extras list", p)
		}
	}
	wide, err := ParsePorts(AutoPorts(16384))
	if err != nil || len(wide) > 40 {
		t.Fatalf("/18 must keep a compact list, got %d (%v)", len(wide), err)
	}
}

func TestTop1000ListParses(t *testing.T) {
	ports, err := ParsePorts(NmapTop1000TCP)
	if err != nil || len(ports) != 1000 {
		t.Fatalf("want 1000 ports, got %d (%v)", len(ports), err)
	}
}

func TestIsAutoPorts(t *testing.T) {
	for _, s := range []string{"", " auto ", "AUTO"} {
		if !IsAutoPorts(s) {
			t.Errorf("%q should be auto", s)
		}
	}
	if IsAutoPorts("22,80") {
		t.Error("explicit list is not auto")
	}
	if got := EffectivePorts("22", 1); got != "22" {
		t.Errorf("explicit list must pass through, got %q", got)
	}
}

func TestEstimateResolvesAutoPorts(t *testing.T) {
	est, res, err := EstimateTargets(context.Background(), EstimateRequest{Targets: []string{"127.0.0.1"}, Ports: "auto", MaxRatePPS: 4000})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.IPs) != 1 || est.EffectiveIPs != 1 {
		t.Fatalf("unexpected estimate %+v", est)
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupHost(_ context.Context, h string) ([]string, error) { return f[h], nil }

func TestHostnamePrefersIPv4(t *testing.T) {
	res, err := ParseAndNormalizeTargets(context.Background(), []string{"localhost"}, nil, fakeResolver{"localhost": {"::1", "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.IPs) != 1 || res.IPs[0] != "127.0.0.1" {
		t.Fatalf("want only 127.0.0.1, got %v", res.IPs)
	}
	res, _ = ParseAndNormalizeTargets(context.Background(), []string{"v6.example"}, nil, fakeResolver{"v6.example": {"::1"}})
	if len(res.IPs) != 1 || res.IPs[0] != "::1" {
		t.Fatalf("IPv6-only name must keep its address, got %v", res.IPs)
	}
}

func TestJoinPortsCollapsesRanges(t *testing.T) {
	full, _ := ParsePorts("1-65535")
	if got := joinPorts(full); got != "1-65535" {
		t.Fatalf("full range: got %q", got)
	}
	if got := joinPorts([]int{22, 80, 81, 443, 8000, 8001, 8002, 8080}); got != "22,80,81,443,8000-8002,8080" {
		t.Fatalf("got %q", got)
	}
	top, _ := ParsePorts(AutoPorts(100))
	if n := len(joinPorts(top)); n > 8000 {
		t.Fatalf("top-1000 list renders to %d bytes", n)
	}
}

func TestLocalAddressUsesConnectScan(t *testing.T) {
	if !isLocalAddress("127.0.0.1") || !anyLocalAddress([]string{"192.0.2.1", "127.0.0.1"}) {
		t.Fatal("loopback must count as local")
	}
	if isLocalAddress("192.0.2.1") || isLocalAddress("not-an-ip") {
		t.Fatal("TEST-NET address is not local")
	}
}
