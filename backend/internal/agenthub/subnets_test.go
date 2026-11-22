package agenthub

import (
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Agents report their local subnets on enroll and on every heartbeat; the server keeps only
// well-formed prefixes (they become one-click targets in the UI).
func TestLocalSubnetsReportedOnEnrollAndHeartbeat(t *testing.T) {
	f := newFixture(t)
	tok, _, err := f.c.CreateEnrollToken(f.ctx, "", "", time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	caps := domain.AgentCapabilities{
		Hostname: "laptop", AllowCIDRs: []string{"192.168.1.0/24"}, AllowFromInterfaces: true,
		LocalSubnets: []domain.LocalSubnet{
			{CIDR: "192.168.1.7/24", Address: "192.168.1.7", Interface: "en0"},
			{CIDR: "not a cidr", Address: "x"},
			{CIDR: "10.0.0.0/24", Address: "10.9.9.9", Interface: strings.Repeat("i", 100)},
		},
	}
	resp, err := f.c.Enroll(f.ctx, EnrollRequest{Token: tok, Version: "test", Capabilities: caps}, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	a, err := f.c.GetAgent(f.ctx, resp.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	got := a.Capabilities.LocalSubnets
	if len(got) != 2 || got[0].CIDR != "192.168.1.0/24" || got[0].Address != "192.168.1.7" ||
		got[1].Address != "" || len(got[1].Interface) != 32 || !a.Capabilities.AllowFromInterfaces || a.Name != "laptop" {
		t.Fatalf("enroll capabilities: %+v name=%q", a.Capabilities, a.Name)
	}

	caps.LocalSubnets = []domain.LocalSubnet{{CIDR: "172.20.0.0/16", Address: "172.20.1.1", Interface: "eth0"}}
	if _, err := f.c.Heartbeat(f.ctx, resp.AgentID, "i1", HeartbeatRequest{Version: "test", Capabilities: caps}); err != nil {
		t.Fatal(err)
	}
	a, _ = f.c.GetAgent(f.ctx, resp.AgentID)
	if len(a.Capabilities.LocalSubnets) != 1 || a.Capabilities.LocalSubnets[0].CIDR != "172.20.0.0/16" {
		t.Fatalf("heartbeat capabilities: %+v", a.Capabilities.LocalSubnets)
	}
}
