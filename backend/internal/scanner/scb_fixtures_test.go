package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Real-world nmap XML from the OWASP secureCodeBox nmap parser test suite
// (testdata/scb, Apache-2.0, see testdata/scb/NOTICE).

func parseSCBFixture(t *testing.T, name string) []domain.ObservedHost {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "scb", name))
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := ParseNmapXML(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return hosts
}

func aliveHosts(hosts []domain.ObservedHost) []domain.ObservedHost {
	var out []domain.ObservedHost
	for _, h := range hosts {
		if h.IsAlive {
			out = append(out, h)
		}
	}
	return out
}

func svcByPort(h domain.ObservedHost, port int) *domain.ObservedService {
	for i := range h.Services {
		if h.Services[i].Port == port {
			return &h.Services[i]
		}
	}
	return nil
}

func TestSCBFixturesAllParse(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "scb", "*.xml"))
	if len(files) < 9 {
		t.Fatalf("expected the secureCodeBox fixtures, found %d", len(files))
	}
	for _, f := range files {
		parseSCBFixture(t, filepath.Base(f))
	}
}

func TestSCBFixtureExpectations(t *testing.T) {
	cases := []struct {
		file      string
		alive     int
		ip        string
		hostname  string
		openPorts []int
	}{
		{"no-host.xml", 0, "", "", nil},
		{"no-ports.xml", 1, "127.0.0.1", "localhost", nil},
		// a single filtered port: host is up, but filtered is not an open service
		{"no-service.xml", 1, "93.184.216.34", "example.com", nil},
		{"localhost.xml", 1, "127.0.0.1", "localhost", []int{53, 8021, 8080, 9200}},
		{"ftp.xml", 1, "10.103.42.74", "dummy-ftp.demo-targets.svc.cluster.local", []int{21}},
		{"scanme.nmap.org-ipv6.xml", 1, "2600:3c01::f03c:91ff:fe18:bb2f", "scanme.nmap.org", []int{22, 80, 31337}},
		// two <host> blocks for one IP (user-supplied name + PTR) are merged into one host
		{"service-scan.xml", 1, "10.50.0.2", "example.com", []int{80, 443}},
		{"localhost-smb-script.xml", 1, "10.50.0.2", "example.com", []int{445}},
		// /24 with 246 down hosts: only <host> blocks that are up count as alive
		{"local-network-verbose.xml", 5, "192.168.178.1", "fritz.box", nil},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			hosts := parseSCBFixture(t, tc.file)
			alive := aliveHosts(hosts)
			if len(alive) != tc.alive {
				t.Fatalf("alive=%d want %d", len(alive), tc.alive)
			}
			if tc.alive == 0 {
				return
			}
			h := alive[0]
			if h.IP != tc.ip || h.Hostname != tc.hostname {
				t.Fatalf("host=%s/%q want %s/%q", h.IP, h.Hostname, tc.ip, tc.hostname)
			}
			if tc.openPorts == nil {
				if tc.file != "local-network-verbose.xml" && len(h.Services) != 0 {
					t.Fatalf("expected no open services, got %+v", h.Services)
				}
				return
			}
			var got []int
			for _, s := range h.Services {
				got = append(got, s.Port)
				if s.State != "open" {
					t.Fatalf("non-open state leaked: %+v", s)
				}
			}
			if len(got) != len(tc.openPorts) {
				t.Fatalf("ports=%v want %v", got, tc.openPorts)
			}
			for i := range got {
				if got[i] != tc.openPorts[i] {
					t.Fatalf("ports=%v want %v", got, tc.openPorts)
				}
			}
		})
	}
}

func TestSCBFixtureServiceDetails(t *testing.T) {
	h := aliveHosts(parseSCBFixture(t, "service-scan.xml"))[0]
	https := svcByPort(h, 443)
	if https == nil || https.ServiceName != "https" || https.Product != "nginx" || https.CPE != "cpe:/a:igor_sysoev:nginx" {
		t.Fatalf("443 = %+v (want https/nginx via tunnel=ssl)", https)
	}
	if len(h.Domains) != 2 || h.Domains[1] != "static.86.161.13.49.clients.your-server.de" {
		t.Fatalf("domains = %v (PTR name from the duplicate host block should be kept)", h.Domains)
	}
	if n := len(parseSCBFixture(t, "service-scan.xml")); n != 1 {
		t.Fatalf("duplicate host blocks not merged: %d hosts", n)
	}
}

func TestSCBFixtureScripts(t *testing.T) {
	ftp := svcByPort(aliveHosts(parseSCBFixture(t, "ftp.xml"))[0], 21)
	if ftp == nil || !strings.Contains(ftp.Banner, "Pure-FTPd") {
		t.Fatalf("banner script not used: %+v", ftp)
	}
	if !containsStr(ftp.Tags, "ftp-anonymous") {
		t.Fatalf("ftp-anon not tagged: %v", ftp.Tags)
	}
	smb := svcByPort(aliveHosts(parseSCBFixture(t, "localhost-smb-script.xml"))[0], 445)
	if smb == nil || !containsStr(smb.Tags, "smbv1") {
		t.Fatalf("hostscript smb-protocols (SMBv1) not tagged on 445: %+v", smb)
	}
}

func TestParseNmapXMLAddressAndOSEdgeCases(t *testing.T) {
	doc := `<?xml version="1.0"?><nmaprun>
<host><status state="up"/>
  <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
  <address addr="fe80::1" addrtype="ipv6"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <hostnames/>
  <ports><port protocol="udp" portid="161"><state state="open|filtered"/></port>
         <port protocol="tcp" portid="22"><state state="closed"/></port></ports>
  <os><osmatch name="Linux 5.0 - 5.14" accuracy="96"/><osmatch name="Linux 4.15" accuracy="90"/></os>
</host>
<host><status state="up"/><address addr="AA:BB:CC:DD:EE:00" addrtype="mac"/></host>
</nmaprun>`
	hosts, err := ParseNmapXML([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("MAC-only host must be skipped, got %d hosts", len(hosts))
	}
	h := hosts[0]
	if h.IP != "10.0.0.5" || h.OSGuess != "Linux 5.0 - 5.14" || len(h.Services) != 0 || h.Hostname != "" {
		t.Fatalf("unexpected %+v", h)
	}
}

func TestGenerateNmapXMLHasNoEmptyScriptElements(t *testing.T) {
	x := GenerateNmapXML([]domain.ObservedHost{{IP: "10.0.0.1", IsAlive: true, Services: []domain.ObservedService{{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http"}}}}, "", time.Time{}, time.Time{})
	if strings.Contains(x, "hostscript") || strings.Contains(x, "<script") {
		t.Fatalf("empty script elements rendered:\n%s", x)
	}
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
