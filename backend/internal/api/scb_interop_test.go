package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// secureCodeBox interoperability through the HTTP API: export ?format=scb, then feed an
// SCB findings.json (auto-detected as .json) back through /ingest/import.
func TestSCBExportAndImportAPI(t *testing.T) {
	_, _, h := setupTestServer(t)
	opTok := loginTest(t, h, "operator", "Operator123!")
	viewerTok := loginTest(t, h, "viewer", "Viewer123!")

	if rec := uploadImport(t, h, opTok, "scan.xml", "", []byte(sampleNmapXML)); rec.Code != http.StatusCreated {
		t.Fatalf("seed import failed: %d %s", rec.Code, rec.Body.String())
	}

	exp := doJSON(h, http.MethodGet, "/api/v1/export?format=scb", viewerTok, nil)
	if exp.Code != http.StatusOK || !strings.HasPrefix(exp.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("scb export: %d %s", exp.Code, exp.Header().Get("Content-Type"))
	}
	if !strings.Contains(exp.Header().Get("Content-Disposition"), "scb-findings.json") {
		t.Fatalf("filename: %s", exp.Header().Get("Content-Disposition"))
	}
	var findings []map[string]any
	if err := json.Unmarshal(exp.Body.Bytes(), &findings); err != nil {
		t.Fatalf("scb export is not a JSON array: %v", err)
	}
	locs := map[string]bool{}
	for _, f := range findings {
		locs[f["category"].(string)+" "+f["location"].(string)] = true
	}
	for _, want := range []string{"Host gw.agh.edu.pl", "Open Port tcp://gw.agh.edu.pl:22", "Open Port tcp://gw.agh.edu.pl:443", "Open Port tcp://10.20.0.2:8080", "SSH Service ssh://gw.agh.edu.pl:22"} {
		if !locs[want] {
			t.Fatalf("missing %q in %v", want, locs)
		}
	}

	scb := `[
  {"id":"b5f3c6a8-0000-4000-8000-000000000001","name":"Open Port: 3306 (mysql)","category":"Open Port","severity":"INFORMATIONAL",
   "location":"tcp://db.agh.example:3306","osi_layer":"NETWORK","parsed_at":"2026-11-20T10:00:00Z",
   "attributes":{"port":3306,"state":"open","ip_addresses":["10.20.0.9"],"protocol":"tcp","hostname":"db.agh.example","service":"mysql","serviceProduct":"MySQL","serviceVersion":"8.0.36"}},
  {"id":"b5f3c6a8-0000-4000-8000-000000000002","name":"Host: db.agh.example","category":"Host","severity":"INFORMATIONAL",
   "location":"db.agh.example","parsed_at":"2026-11-20T10:00:00Z","attributes":{"ip_addresses":["10.20.0.9"],"hostname":"db.agh.example","operating_system":null}}
]`
	rec := uploadImport(t, h, opTok, "findings.json", "", []byte(scb))
	if rec.Code != http.StatusCreated {
		t.Fatalf("scb import failed: %d %s", rec.Code, rec.Body.String())
	}
	var res struct {
		HostsProcessed   int `json:"hosts_processed"`
		ServicesUpserted int `json:"services_upserted"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.HostsProcessed != 1 || res.ServicesUpserted != 1 {
		t.Fatalf("want 1 host / 1 service, got %d / %d", res.HostsProcessed, res.ServicesUpserted)
	}
	hostsRec := doJSON(h, http.MethodGet, "/api/v1/hosts?q=10.20.0.9", viewerTok, nil)
	if !strings.Contains(hostsRec.Body.String(), "db.agh.example") || !strings.Contains(hostsRec.Body.String(), "MySQL") {
		t.Fatalf("imported SCB host missing: %s", hostsRec.Body.String())
	}

	// explicit format=scb on something that is not SCB is rejected
	if rec := uploadImport(t, h, opTok, "x.json", "scb", []byte(`[{"name":"x","category":"Host","location":"nohost"}]`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for SCB file without IPs, got %d", rec.Code)
	}
}
