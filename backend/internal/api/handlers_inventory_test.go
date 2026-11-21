package api

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestDedupedScopeMergesOverlaps(t *testing.T) {
	sc := dedupedScope([]string{"10.66.0.0/18", "10.66.4.0/22", "10.66.0.5", "192.168.1.10-192.168.1.19"})
	if sc.IPs != 16384+10 {
		t.Fatalf("deduped ips = %d, want %d", sc.IPs, 16384+10)
	}
	if sc.RawIPs != 16384+1024+1+10 {
		t.Fatalf("raw ips = %d", sc.RawIPs)
	}
}

func TestBuildInventoryAndQueryRoundTrip(t *testing.T) {
	hosts := []domain.Host{
		{ID: "h1", IP: "10.0.0.1", LifecycleState: domain.HostStateNew, Services: []domain.Service{
			{Port: 80, Product: "Apache httpd", Version: "2.4.41", IsAdminPanel: true, Interestingness: 70,
				Technologies: []domain.DetectedTechnology{
					{Name: "Apache HTTP Server", Category: "server"},
					{Name: "WordPress", Category: "cms", Version: "6.4.3"},
					{Name: "Admin Panel / Management Console", Category: "admin_panel"},
				},
				Outdated: []domain.OutdatedComponent{{Product: "Apache HTTP Server"}}},
		}},
		{ID: "h2", IP: "10.0.0.2", Services: []domain.Service{
			{Port: 443, MatchedSignatures: []string{"Server BMC (Dell iDRAC / HPE iLO)"},
				Technologies: []domain.DetectedTechnology{{Name: "Server BMC (Dell iDRAC / HPE iLO)", Category: "iot"}}},
			{Port: 22, Product: "OpenSSH", Version: "8.9p1 Ubuntu 3ubuntu0.10"},
		}},
	}
	inv := buildInventory(hosts)
	byName := map[string]inventoryProduct{}
	for _, p := range inv {
		byName[p.Name] = p
	}
	if _, ok := byName["Admin Panel / Management Console"]; ok {
		t.Fatal("property signatures must not be listed as products")
	}
	ap := byName["Apache HTTP Server"]
	if ap.HostCount != 1 || ap.EOLCount != 1 || ap.AdminCount != 1 || ap.NewCount != 1 || len(ap.Versions) != 1 || ap.Versions[0].Version != "2.4.41" {
		t.Fatalf("apache row: %+v", ap)
	}
	if wp := byName["WordPress"]; wp.EOLCount != 0 || wp.Versions[0].Version != "6.4.3" {
		t.Fatalf("wordpress row must not inherit Apache EOL: %+v", wp)
	}
	if ssh := byName["OpenSSH"]; ssh.Versions[0].Version != "8.9p1" {
		t.Fatalf("product-only row: %+v", ssh)
	}
	// Every row's query must find the hosts it counts.
	for _, p := range inv {
		q, err := db.ParseAssetQuery(p.Query)
		if err != nil {
			t.Fatalf("%s: %v", p.Query, err)
		}
		n := 0
		for i := range hosts {
			if q.MatchHost(&hosts[i]) {
				n++
			}
		}
		if n != p.HostCount {
			t.Fatalf("%s: query matched %d hosts, row says %d", p.Query, n, p.HostCount)
		}
	}
}
