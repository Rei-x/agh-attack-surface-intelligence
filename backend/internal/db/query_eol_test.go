package db

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestQueryEOLAndVuln(t *testing.T) {
	host := &domain.Host{IP: "10.66.0.5", Services: []domain.Service{
		{Port: 80, Product: "nginx", Version: "1.14.2"},
		{Port: 22, Product: "OpenSSH", Version: "9.9p1"},
	}}
	modern := &domain.Host{IP: "10.66.0.6", Services: []domain.Service{{Port: 80, Product: "nginx", Version: "1.30.1"}}}
	for q, want := range map[string][2]bool{
		"eol:true":                {true, false},
		"outdated:yes":            {true, false},
		"eol:true port:22":        {false, false}, // same-service semantics: the EOL service is on 80
		"eol:true port:80":        {true, false},
		"-eol:true port:80":       {false, true},
		"vuln:true":               {false, false},
		"product:nginx eol:false": {false, true},
	} {
		pq, err := ParseAssetQuery(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if got := pq.MatchHost(host); got != want[0] {
			t.Errorf("%s on old host: got %v want %v", q, got, want[0])
		}
		if got := pq.MatchHost(modern); got != want[1] {
			t.Errorf("%s on modern host: got %v want %v", q, got, want[1])
		}
	}
	ssh := &domain.Service{Port: 22, Product: "OpenSSH", Version: "8.9p1"}
	if pq, _ := ParseAssetQuery("vuln:true"); !pq.MatchService(ssh) {
		t.Error("vuln:true should match OpenSSH 8.9p1 (CVE-2024-6387 hint)")
	}
	if _, err := ParseAssetQuery("eol:maybe"); err == nil {
		t.Error("eol:maybe must be rejected")
	}
}
