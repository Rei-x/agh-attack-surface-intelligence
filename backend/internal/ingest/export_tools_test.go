package ingest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

func toolExportFixture() []domain.Host {
	seen := time.Date(2026, 11, 20, 22, 0, 0, 0, time.UTC)
	return []domain.Host{
		{
			ID: "h1", IP: "10.0.0.5", Hostname: "cms.agh.edu.pl", LifecycleState: domain.HostStateActive,
			LastSeen: seen, FirstSeen: seen, Tags: []string{"prod"},
			Services: []domain.Service{
				{ID: "s1", Port: 80, Protocol: "tcp", State: "open", ServiceName: "http", Product: "nginx", Version: "1.24.0",
					HTTP: &domain.HTTPFingerprint{Scheme: "http", StatusCode: 200, Title: "CMS"}},
				{ID: "s2", Port: 8443, Protocol: "tcp", State: "open", ServiceName: "https-alt"},
				{ID: "s3", Port: 22, Protocol: "tcp", State: "open", ServiceName: "ssh", Product: "OpenSSH", Version: "9.6"},
			},
		},
		{
			ID: "h2", IP: "10.0.0.6", LifecycleState: domain.HostStateNew, LastSeen: seen, FirstSeen: seen,
			Services: []domain.Service{
				{ID: "s4", Port: 443, Protocol: "tcp", State: "open", ServiceName: "https"},
				{ID: "s5", Port: 3306, Protocol: "tcp", State: "open", ServiceName: "mysql"},
			},
		},
		{ID: "h3", IP: "10.0.0.7", LifecycleState: domain.HostStateMissing, LastSeen: seen, FirstSeen: seen},
	}
}

func TestExportURLsListsOnlyWebServices(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportURLs(&buf, toolExportFixture()); err != nil {
		t.Fatal(err)
	}
	want := "http://10.0.0.5\nhttps://10.0.0.5:8443\nhttps://10.0.0.6\n"
	if buf.String() != want {
		t.Fatalf("urls mismatch:\n got %q\nwant %q", buf.String(), want)
	}
}

func TestExportNmapXMLRoundTripsThroughParser(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportNmapXML(&buf, toolExportFixture()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<nmaprun") {
		t.Fatalf("not nmap xml: %s", buf.String())
	}
	obs, err := scanner.ParseNmapXML(buf.Bytes())
	if err != nil {
		t.Fatalf("own export does not parse: %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("want 3 hosts, got %d", len(obs))
	}
	if obs[0].IP != "10.0.0.5" || len(obs[0].Services) != 3 || obs[0].Services[2].Product != "OpenSSH" || obs[0].Hostname != "cms.agh.edu.pl" {
		t.Fatalf("host 1 lost data: %+v", obs[0])
	}
	if obs[2].IsAlive {
		t.Fatalf("missing host must be exported as down")
	}
}

func TestExportECSProducesNDJSONPerService(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportECS(&buf, toolExportFixture()); err != nil {
		t.Fatal(err)
	}
	var docs []map[string]any
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var d map[string]any
		if err := json.Unmarshal(sc.Bytes(), &d); err != nil {
			t.Fatalf("line is not json: %v: %s", err, sc.Text())
		}
		docs = append(docs, d)
	}
	// 3 + 2 services, plus one doc for the host without services.
	if len(docs) != 6 {
		t.Fatalf("want 6 docs, got %d", len(docs))
	}
	d := docs[0]
	if d["@timestamp"] != "2026-11-20T22:00:00Z" {
		t.Fatalf("bad @timestamp: %v", d["@timestamp"])
	}
	ev := d["event"].(map[string]any)
	if ev["kind"] != "state" || ev["dataset"] != "aegis.asset" {
		t.Fatalf("bad event: %v", ev)
	}
	if d["destination"].(map[string]any)["port"].(float64) != 80 {
		t.Fatalf("bad destination: %v", d["destination"])
	}
	if d["url"].(map[string]any)["full"] != "http://10.0.0.5" {
		t.Fatalf("bad url: %v", d["url"])
	}
	if d["http"].(map[string]any)["response"].(map[string]any)["status_code"].(float64) != 200 {
		t.Fatalf("bad http: %v", d["http"])
	}
	if _, ok := docs[2]["url"]; ok {
		t.Fatalf("ssh service must not get url.full")
	}
	if docs[5]["host"].(map[string]any)["ip"].([]any)[0] != "10.0.0.7" {
		t.Fatalf("bad host-only doc: %v", docs[5])
	}
}
