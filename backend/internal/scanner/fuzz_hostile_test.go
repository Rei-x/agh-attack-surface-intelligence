package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// noDNS fails every lookup instantly so fuzzing never touches the network.
type noDNS struct{}

func (noDNS) LookupHost(context.Context, string) ([]string, error) { return nil, errors.New("no dns") }

func TestValidateTargetEntry(t *testing.T) {
	ok := map[string]string{
		"10.0.0.1": "ip", " 10.0.0.0/24 ": "cidr", "10.0.0.1-10.0.0.9": "range", "10.0.0.1-9": "range",
		"2001:db8::1": "ipv6", "2001:db8::/120": "ipv6", "host.agh.edu.pl": "domain", "my-host.example": "domain",
		"https://www.agh.edu.pl/x": "domain", "zażółć.pl": "domain", "10.0.0.0/16": "cidr",
	}
	for in, kind := range ok {
		got, err := ValidateTargetEntry(in, DefaultMaxExpandedIPs)
		if err != nil || got != kind {
			t.Errorf("%q: got %q %v, want %q", in, got, err, kind)
		}
	}
	bad := []string{"", "   ", "10.0.0.0/33", "10.0.0.0/8", "0.0.0.0/0", "10.0.0.9-10.0.0.1", "300.1.1.1",
		"10.0.0.1-300", "2001:db8::/64", "foo", "a b.com", "-bad.com", "x..y", "<script>.com", strings.Repeat("a", 300) + ".com"}
	for _, in := range bad {
		if kind, err := ValidateTargetEntry(in, DefaultMaxExpandedIPs); err == nil {
			t.Errorf("%q: accepted as %q, want error", in, kind)
		}
	}
	// Exclusions have no size cap.
	if _, err := ValidateTargetEntry("10.0.0.0/8", 0); err != nil {
		t.Errorf("/8 exclusion: %v", err)
	}
}

func TestTargetsAllExcludedAndOverlapping(t *testing.T) {
	res, err := ParseAndNormalizeTargets(context.Background(),
		[]string{"10.0.0.0/24", "10.0.0.0/25", "10.0.0.5", "10.0.0.5", " 10.0.0.1-10.0.0.3 "},
		[]domain.TargetExclusion{{Value: "10.0.0.0/16"}}, noDNS{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.IPs) != 0 || res.TotalCount != 256 || res.ExcludedCount != 256 {
		t.Fatalf("overlap/exclusion accounting wrong: ips=%d total=%d excluded=%d", len(res.IPs), res.TotalCount, res.ExcludedCount)
	}
}

func TestSlash16ExpansionIsFast(t *testing.T) {
	start := time.Now()
	res, err := ParseAndNormalizeTargets(context.Background(), []string{"10.20.0.0/16"}, nil, noDNS{})
	if err != nil || len(res.IPs) != 65536 {
		t.Fatalf("/16: %v %d", err, len(res.IPs))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("/16 expansion took %v", d)
	}
	if _, err := ParseAndNormalizeTargets(context.Background(), []string{"10.0.0.0/8"}, nil, noDNS{}); err == nil {
		t.Fatal("/8 must be refused by the safety cap")
	}
}

func FuzzParseAndNormalizeTargets(f *testing.F) {
	for _, s := range []string{"10.0.0.0/24", "10.0.0.1-50", "2001:db8::/120", "a.example", "http://[::1]:80/", "1.2.3.4-1.2.3.3", "0.0.0.0/0"} {
		f.Add(s, "10.0.0.0/28")
	}
	f.Fuzz(func(t *testing.T, target, exclusion string) {
		targets := strings.Split(target, "\n")
		_, _ = ValidateTargetEntry(target, DefaultMaxExpandedIPs)
		res, err := ParseAndNormalizeTargetsWithLimit(context.Background(), targets,
			[]domain.TargetExclusion{{Value: exclusion}}, noDNS{}, 70000)
		if err == nil && len(res.IPs) > 70000 {
			t.Fatalf("cap exceeded: %d", len(res.IPs))
		}
	})
}

func FuzzParsePorts(f *testing.F) {
	for _, s := range []string{"22,80", "1-65535", "0", "70000", "22,,80", "-", "5-1", " 443 "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		ports, err := ParsePorts(spec)
		if err != nil {
			return
		}
		for _, p := range ports {
			if p < 1 || p > 65535 {
				t.Fatalf("ParsePorts(%q) returned %d", spec, p)
			}
		}
	})
}

func FuzzParseNmapXML(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port></ports></host></nmaprun>`))
	// Entity expansion and external entities must not be resolved.
	f.Add([]byte(`<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun><host><address addr="&b;&x;" addrtype="ipv4"/></host></nmaprun>`))
	f.Add([]byte(`<nmaprun><host><address addr="10.0.0.1" addrtype="mac"/><ports><port portid="99999"/></ports></host>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseNmapXML(data)
	})
}

func TestParseNmapXMLDoesNotExpandEntities(t *testing.T) {
	doc := `<?xml version="1.0"?><!DOCTYPE l [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun><host><status state="up"/><address addr="&x;" addrtype="ipv4"/></host></nmaprun>`
	hosts, err := ParseNmapXML([]byte(doc))
	if err == nil {
		for _, h := range hosts {
			if strings.Contains(h.IP, "root:") {
				t.Fatal("external entity was resolved")
			}
		}
	}
}
