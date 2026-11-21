package ingest

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func scbTestInventory() []domain.Host {
	seen := time.Date(2026, 11, 20, 22, 0, 0, 0, time.UTC)
	return []domain.Host{
		{
			ID: "h1", IP: "10.10.0.5", Hostname: "web.agh.example", OSGuess: "Linux 5.x", LifecycleState: "ACTIVE",
			FirstSeen: seen.Add(-48 * time.Hour), LastSeen: seen, Tags: []string{"prod"},
			Services: []domain.Service{
				{ID: "s1", Port: 22, Protocol: "tcp", State: "open", ServiceName: "ssh", Product: "OpenSSH", Version: "7.4", Banner: "SSH-1.99-OpenSSH_7.4", LastSeen: seen},
				{ID: "s2", Port: 443, Protocol: "tcp", State: "open", ServiceName: "https", Product: "nginx", Version: "1.18.0", CPE: "cpe:/a:nginx:nginx:1.18.0", LastSeen: seen,
					HTTP: &domain.HTTPFingerprint{Title: "Portal", TLS: &domain.TLSInfo{Version: "TLS 1.0", CipherSuite: "TLS_RSA_WITH_AES_128_CBC_SHA", SubjectCN: "web.agh.example", IsSelfSigned: true, SHA256: "ab"}}},
				{ID: "s3", Port: 8080, Protocol: "tcp", State: "closed", ServiceName: "http-proxy", LastSeen: seen},
			},
		},
		{ID: "h2", IP: "2001:db8::7", LifecycleState: "NEW", LastSeen: seen,
			Services: []domain.Service{{ID: "s4", Port: 161, Protocol: "udp", State: "open", ServiceName: "snmp", LastSeen: seen}}},
	}
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestExportSCBShape(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportSCB(&buf, scbTestInventory()); err != nil {
		t.Fatal(err)
	}
	var findings []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &findings); err != nil {
		t.Fatalf("not a JSON array: %v", err)
	}
	byName := map[string]map[string]any{}
	for _, f := range findings {
		// required by the SCB finding schema
		for _, k := range []string{"id", "parsed_at", "severity", "category", "name", "scan"} {
			if _, ok := f[k]; !ok {
				t.Fatalf("finding %v lacks %q", f["name"], k)
			}
		}
		if !uuidRe.MatchString(f["id"].(string)) {
			t.Fatalf("id %q is not an RFC 4122 UUID", f["id"])
		}
		switch f["severity"] {
		case "INFORMATIONAL", "LOW", "MEDIUM", "HIGH":
		default:
			t.Fatalf("bad severity %v", f["severity"])
		}
		byName[f["name"].(string)] = f
	}
	for _, want := range []string{
		"Host: web.agh.example", "Open Port: 22 (ssh)", "Open Port: 443 (https)", "Host: 2001:db8::7", "Open Port: 161 (snmp)",
		"TLS Service", "TLS Version TLS 1.0 is considered insecure", "Self-Signed Certificate",
		"SSH Service", "Insecure SSH Protocol Version 1.99",
	} {
		if byName[want] == nil {
			t.Fatalf("missing finding %q; got %d findings", want, len(findings))
		}
	}
	if _, closed := byName["Open Port: 8080 (http-proxy)"]; closed {
		t.Fatal("closed service exported as Open Port")
	}
	p := byName["Open Port: 443 (https)"]
	if p["location"] != "tcp://web.agh.example:443" || p["category"] != "Open Port" || p["osi_layer"] != "NETWORK" {
		t.Fatalf("open port finding = %v", p)
	}
	a := p["attributes"].(map[string]any)
	if a["port"].(float64) != 443 || a["serviceProduct"] != "nginx" || a["tunnel"] != "ssl" || a["ip_addresses"].([]any)[0] != "10.10.0.5" {
		t.Fatalf("attributes = %v", a)
	}
	if loc := byName["Open Port: 161 (snmp)"]["location"]; loc != "udp://[2001:db8::7]:161" {
		t.Fatalf("ipv6 location = %v", loc)
	}
	if sev := byName["TLS Version TLS 1.0 is considered insecure"]["severity"]; sev != "MEDIUM" {
		t.Fatalf("outdated TLS severity = %v", sev)
	}

	// ids are stable across exports (dedup in SCB/DefectDojo)
	var again bytes.Buffer
	_ = ExportSCB(&again, scbTestInventory())
	if !strings.Contains(again.String(), byName["Open Port: 22 (ssh)"]["id"].(string)) {
		t.Fatal("finding ids are not deterministic")
	}
}

func TestSCBRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	inv := scbTestInventory()
	if err := ExportSCB(&buf, inv); err != nil {
		t.Fatal(err)
	}
	if !LooksLikeSCBFindings(buf.Bytes()) {
		t.Fatal("export not detected as secureCodeBox findings")
	}
	obs, err := ParseSCBFindings(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("hosts = %d", len(obs))
	}
	h := obs[0]
	if h.IP != "10.10.0.5" || h.Hostname != "web.agh.example" || h.OSGuess != "Linux 5.x" || !h.IsAlive {
		t.Fatalf("host = %+v", h)
	}
	if len(h.Services) != 2 {
		t.Fatalf("services = %+v (closed port must not come back)", h.Services)
	}
	ssh, https := h.Services[0], h.Services[1]
	if ssh.Port != 22 || ssh.ServiceName != "ssh" || ssh.Product != "OpenSSH" || ssh.Version != "7.4" || ssh.Banner != "SSH-1.99-OpenSSH_7.4" {
		t.Fatalf("ssh = %+v", ssh)
	}
	if https.Port != 443 || https.ServiceName != "https" || https.Product != "nginx" || https.CPE != "cpe:/a:nginx:nginx:1.18.0" {
		t.Fatalf("https = %+v", https)
	}
	for _, tag := range []string{"scb:outdated-tls-version", "scb:invalid-certificate", "scb:tls-service-info"} {
		if !containsTag(https.Tags, tag) {
			t.Fatalf("443 tags %v lack %s", https.Tags, tag)
		}
	}
	if !containsTag(ssh.Tags, "scb:ssh-policy-violation") {
		t.Fatalf("22 tags %v", ssh.Tags)
	}
	v6 := obs[1]
	if v6.IP != "2001:db8::7" || len(v6.Services) != 1 || v6.Services[0].Protocol != "udp" || v6.Services[0].Port != 161 {
		t.Fatalf("ipv6 host = %+v", v6)
	}
}

// Real findings produced by the secureCodeBox nmap scanner (scanners/nmap/examples/basic-example).
func TestParseSCBFindingsFromSecureCodeBoxNmap(t *testing.T) {
	data, err := os.ReadFile("testdata/scb/nmap-basic-findings.json")
	if err != nil {
		t.Fatal(err)
	}
	if !LooksLikeSCBFindings(data) {
		t.Fatal("SCB nmap findings not detected")
	}
	obs, err := ParseSCBFindings(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("hosts = %d", len(obs))
	}
	h := obs[0]
	if h.IP != "45.33.32.156" || h.Hostname != "scanme.nmap.org" {
		t.Fatalf("host = %+v", h)
	}
	var ports []int
	for _, s := range h.Services {
		ports = append(ports, s.Port)
	}
	// 135/139/445 are "filtered" in SCB's "Open Port" findings and are skipped
	if len(ports) != 4 || ports[0] != 22 || ports[1] != 80 || ports[2] != 9929 || ports[3] != 31337 {
		t.Fatalf("ports = %v", ports)
	}
	if h.Services[0].ServiceName != "ssh" {
		t.Fatalf("svc = %+v", h.Services[0])
	}
}

// Shapes produced by the SCB ssh-audit and sslyze parsers.
func TestParseSCBFindingsOtherScanners(t *testing.T) {
	doc := `[
 {"id":"1","name":"SSH Service","category":"SSH Service","severity":"INFORMATIONAL","location":"ssh://192.0.2.10","port":"2222",
  "attributes":{"hostname":null,"ip_address":"192.0.2.10","server_banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3","ssh_version":2}},
 {"id":"2","name":"Insecure SSH KEX Algorithms","category":"SSH Policy Violation","severity":"MEDIUM","location":"ssh://192.0.2.10","attributes":{}},
 {"id":"3","name":"TLS Version TLS 1.0 is considered insecure","category":"Outdated TLS Version","severity":"MEDIUM",
  "location":"tls-v1-0.badssl.com:1010","attributes":{"hostname":"tls-v1-0.badssl.com","ip_addresses":["104.154.89.105"],"port":1010}},
 {"id":"4","name":"Subdomain www.example.org","category":"Subdomain","severity":"INFORMATIONAL","location":"www.example.org","attributes":{}},
 {"id":"5","name":"Open Port: 22","category":"Open Port","severity":"INFORMATIONAL","location":"tcp://2001:db8::1:22","attributes":{"port":22,"state":"open","protocol":"tcp"}},
 {"id":"6","name":"Open Port: 99999","category":"Open Port","severity":"INFORMATIONAL","location":"tcp://192.0.2.11:99999","attributes":{"port":99999,"state":"open"}}
]`
	obs, err := ParseSCBFindings(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]domain.ObservedHost{}
	for _, h := range obs {
		got[h.IP] = h
	}
	if len(got) != 3 {
		t.Fatalf("hosts = %v (subdomain without IP and invalid port must be skipped)", obs)
	}
	ssh := got["192.0.2.10"]
	if len(ssh.Services) != 1 || ssh.Services[0].Port != 2222 || ssh.Services[0].ServiceName != "ssh" || ssh.Services[0].Banner != "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" {
		t.Fatalf("ssh-audit host = %+v", ssh)
	}
	if !containsTag(ssh.Tags, "scb:ssh-policy-violation") {
		t.Fatalf("port-less policy finding should tag the host: %v", ssh.Tags)
	}
	tlsHost := got["104.154.89.105"]
	if tlsHost.Hostname != "tls-v1-0.badssl.com" || len(tlsHost.Services) != 1 || tlsHost.Services[0].Port != 1010 || !containsTag(tlsHost.Services[0].Tags, "scb:outdated-tls-version") {
		t.Fatalf("sslyze host = %+v", tlsHost)
	}
	if v6 := got["2001:db8::1"]; len(v6.Services) != 1 || v6.Services[0].Port != 22 {
		t.Fatalf("unbracketed IPv6 location = %+v", v6)
	}
}

func TestLooksLikeSCBFindingsRejectsOtherJSON(t *testing.T) {
	for _, doc := range []string{
		`[{"ip":"10.0.0.1","port":22}]`,
		`[{"ip":"10.0.0.1","name":"x","category":"y","services":[]}]`,
		`{"hosts":[]}`, `[]`, `not json`,
	} {
		if LooksLikeSCBFindings([]byte(doc)) {
			t.Fatalf("%s detected as SCB", doc)
		}
	}
	if _, err := ParseSCBFindings(strings.NewReader(`[{"name":"x","category":"Host","location":"no-ip.example"}]`)); err == nil {
		t.Fatal("expected error when no finding has an IP")
	}
}

func TestPassiveChecksIgnoreHealthyServices(t *testing.T) {
	if f := TLSPassiveFindings(&domain.TLSInfo{Version: "TLS 1.3", SHA256: "x"}); len(f) != 1 || f[0].Category != "TLS Service Info" {
		t.Fatalf("healthy TLS produced %+v", f)
	}
	if f := SSHPassiveFindings(domain.Service{ServiceName: "ssh", Product: "OpenSSH", Version: "9.6", Banner: "Ubuntu Linux; protocol 2.0"}); len(f) != 1 || f[0].Attributes["ssh_version"] != "2.0" {
		t.Fatalf("healthy SSH produced %+v", f)
	}
	if f := SSHPassiveFindings(domain.Service{ServiceName: "http"}); f != nil {
		t.Fatalf("non-ssh produced %+v", f)
	}
}

func containsTag(tags []string, v string) bool {
	for _, t := range tags {
		if t == v {
			return true
		}
	}
	return false
}
