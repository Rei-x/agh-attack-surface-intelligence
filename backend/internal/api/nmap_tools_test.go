package api

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const sampleNmapXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 10.20.0.0/30" start="1763762400" version="7.94" xmloutputversion="1.05">
  <host><status state="up" reason="syn-ack"/>
    <address addr="10.20.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="gw.agh.edu.pl" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1"/></port>
      <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" tunnel="ssl" product="nginx" version="1.24.0"/></port>
      <port protocol="tcp" portid="25"><state state="closed" reason="reset"/></port>
    </ports>
  </host>
  <host><status state="up" reason="syn-ack"/>
    <address addr="10.20.0.2" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http" product="Jetty"/></port></ports>
  </host>
</nmaprun>`

func uploadImport(t *testing.T, h http.Handler, token, filename, format string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	if format != "" {
		_ = mw.WriteField("format", format)
	}
	fw, _ := mw.CreateFormFile("file", filename)
	_, _ = fw.Write(content)
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/import", &mp)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNmapXMLImportRunDownloadAndToolExports(t *testing.T) {
	_, _, h := setupTestServer(t)
	opTok := loginTest(t, h, "operator", "Operator123!")
	analystTok := loginTest(t, h, "analyst", "Analyst123!")
	viewerTok := loginTest(t, h, "viewer", "Viewer123!")

	// RBAC: import needs import:write (operator/admin only).
	if rec := uploadImport(t, h, analystTok, "scan.xml", "", []byte(sampleNmapXML)); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst import expected 403, got %d", rec.Code)
	}

	// Format auto-detected from the .xml extension.
	rec := uploadImport(t, h, opTok, "scan.xml", "", []byte(sampleNmapXML))
	if rec.Code != http.StatusCreated {
		t.Fatalf("nmap xml import failed: %d %s", rec.Code, rec.Body.String())
	}
	var res struct {
		ScanRun          domain.ScanRun `json:"scan_run"`
		HostsProcessed   int            `json:"hosts_processed"`
		ServicesUpserted int            `json:"services_upserted"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.ScanRun.RunType != domain.ScanTypeImportNmap || !res.ScanRun.HasRawNmapXML {
		t.Fatalf("unexpected run: %+v", res.ScanRun)
	}
	if res.HostsProcessed != 2 || res.ServicesUpserted != 3 {
		t.Fatalf("want 2 hosts / 3 open services, got %d / %d", res.HostsProcessed, res.ServicesUpserted)
	}

	// Imported data lands in the inventory through the same pipeline (lifecycle state, tls->https).
	hostsRec := doJSON(h, http.MethodGet, "/api/v1/hosts?q=10.20.0.1", viewerTok, nil)
	var hostsResp struct {
		Hosts []domain.Host `json:"hosts"`
	}
	_ = json.Unmarshal(hostsRec.Body.Bytes(), &hostsResp)
	if len(hostsResp.Hosts) != 1 || hostsResp.Hosts[0].LifecycleState == "" || hostsResp.Hosts[0].Hostname != "gw.agh.edu.pl" {
		t.Fatalf("imported host missing from inventory: %s", hostsRec.Body.String())
	}

	// The run's raw XML can be downloaded back by anyone with scans:read.
	xmlRec := doJSON(h, http.MethodGet, "/api/v1/scans/"+res.ScanRun.ID+"/nmap.xml", viewerTok, nil)
	if xmlRec.Code != http.StatusOK || !strings.Contains(xmlRec.Body.String(), `args="nmap -sV -oX - 10.20.0.0/30"`) {
		t.Fatalf("nmap.xml download failed: %d %s", xmlRec.Code, xmlRec.Body.String())
	}
	if ct := xmlRec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/xml") {
		t.Fatalf("bad content type %q", ct)
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/scans/"+res.ScanRun.ID+"/nmap.xml", "", nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous nmap.xml expected 401, got %d", r.Code)
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/scans/does-not-exist/nmap.xml", viewerTok, nil); r.Code != http.StatusNotFound {
		t.Fatalf("unknown run expected 404, got %d", r.Code)
	}

	// Broken XML is rejected, not silently imported as zero hosts.
	if rec := uploadImport(t, h, opTok, "broken.xml", "nmap", []byte("<nmaprun><host>")); rec.Code != http.StatusBadRequest {
		t.Fatalf("broken xml expected 400, got %d", rec.Code)
	}

	// Tool exports (export:read, viewer included).
	urls := doJSON(h, http.MethodGet, "/api/v1/export?format=urls&scan_id="+res.ScanRun.ID, viewerTok, nil)
	if urls.Code != http.StatusOK || !strings.Contains(urls.Body.String(), "https://10.20.0.1\n") || !strings.Contains(urls.Body.String(), "http://10.20.0.2:8080\n") || strings.Contains(urls.Body.String(), ":22") {
		t.Fatalf("urls export wrong: %d %q", urls.Code, urls.Body.String())
	}
	nm := doJSON(h, http.MethodGet, "/api/v1/export?format=nmap", viewerTok, nil)
	if nm.Code != http.StatusOK || !strings.Contains(nm.Body.String(), `<address addr="10.20.0.2" addrtype="ipv4"`) {
		t.Fatalf("nmap export wrong: %d %s", nm.Code, nm.Body.String())
	}
	ecs := doJSON(h, http.MethodGet, "/api/v1/export?format=ecs", viewerTok, nil)
	if ecs.Code != http.StatusOK || ecs.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("ecs export wrong: %d %s", ecs.Code, ecs.Header().Get("Content-Type"))
	}
	for _, line := range strings.Split(strings.TrimSpace(ecs.Body.String()), "\n") {
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil || doc["@timestamp"] == nil {
			t.Fatalf("bad ecs line %q: %v", line, err)
		}
	}
	if r := doJSON(h, http.MethodGet, "/api/v1/export?format=pdf", viewerTok, nil); r.Code != http.StatusBadRequest {
		t.Fatalf("unknown export format expected 400, got %d", r.Code)
	}
}
