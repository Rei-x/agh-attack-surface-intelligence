package api

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Hostile / odd inputs must produce a 4xx with a message, never a 500, panic or hang.

func TestHostileTargetAndExclusionInputs(t *testing.T) {
	_, _, h := setupTestServer(t)
	tok := loginTest(t, h, "admin", "Admin123!")
	badTargets := []string{"10.0.0.0/8", "0.0.0.0/0", "10.0.0.0/33", "300.1.1.1", "10.0.0.9-10.0.0.1",
		"foo", "a b", strings.Repeat("x", 5000), "2001:db8::/64", "<img src=x>"}
	for _, v := range badTargets {
		rec := doJSON(h, http.MethodPost, "/api/v1/targets", tok, map[string]any{"value": v})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "error") {
			t.Errorf("target %q: got %d %s", v, rec.Code, rec.Body.String())
		}
	}
	for v, kind := range map[string]string{"10.1.0.0/16": "cidr", "my-host.agh.edu.pl": "domain", "10.0.0.1-20": "range", "2001:db8::1": "ip"} {
		rec := doJSON(h, http.MethodPost, "/api/v1/targets", tok, map[string]any{"value": v})
		if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"kind":"`+kind+`"`) {
			t.Errorf("target %q: got %d %s", v, rec.Code, rec.Body.String())
		}
	}
	// Exclusions: typos rejected, wide ranges allowed.
	if rec := doJSON(h, http.MethodPost, "/api/v1/exclusions", tok, map[string]any{"value": "10.0.0.0/33"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad exclusion: %d", rec.Code)
	}
	if rec := doJSON(h, http.MethodPost, "/api/v1/exclusions", tok, map[string]any{"value": "10.0.0.0/8"}); rec.Code != http.StatusCreated {
		t.Errorf("/8 exclusion: %d %s", rec.Code, rec.Body.String())
	}
	// Wrong JSON types.
	if rec := doJSON(h, http.MethodPost, "/api/v1/targets", tok, map[string]any{"value": 12}); rec.Code != http.StatusBadRequest {
		t.Errorf("numeric value: %d", rec.Code)
	}
}

func TestHostileScanAndProfileInputs(t *testing.T) {
	_, _, h := setupTestServer(t)
	tok := loginTest(t, h, "admin", "Admin123!")
	cases := []map[string]any{
		{"targets": []string{"10.0.0.1"}, "allowed_ports": "0"},
		{"targets": []string{"10.0.0.1"}, "allowed_ports": "70000"},
		{"targets": []string{"10.0.0.1"}, "allowed_ports": "abc"},
		{"targets": []string{"10.0.0.1"}, "allowed_ports": "100-1"},
		{"targets": []string{"10.0.0.0/8"}},
		{"targets": []string{"not a target"}},
		{"targets": []string{}},
		{"targets": []string{"10.0.0.1"}, "concurrency": 10000000},
		{"targets": []string{"10.0.0.1"}, "window_enabled": true, "window_start": "25:00", "window_end": "06:00"},
		{"targets": []string{"10.0.0.1"}, "window_enabled": true, "window_start": "22:00", "window_end": "06:00", "timezone": "Mars/Olympus"},
	}
	for _, c := range cases {
		rec := doJSON(h, http.MethodPost, "/api/v1/scans", tok, c)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("start scan %v: got %d %s", c, rec.Code, rec.Body.String())
		}
	}
	// "22,,80" and "1-65535" are fine.
	for _, ports := range []string{"22,,80", "1-65535"} {
		rec := doJSON(h, http.MethodPost, "/api/v1/profiles", tok, map[string]any{"name": "p " + ports, "targets": []string{"10.0.0.1"}, "allowed_ports": ports})
		if rec.Code != http.StatusCreated {
			t.Errorf("profile ports %q: %d %s", ports, rec.Code, rec.Body.String())
		}
	}
	for _, cron := range []string{"* * *", "99 * * * *", "@every 1s", strings.Repeat("*", 2000)} {
		rec := doJSON(h, http.MethodPost, "/api/v1/profiles", tok, map[string]any{"name": "c", "targets": []string{"10.0.0.1"}, "schedule_cron": cron})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("cron %q: got %d %s", cron, rec.Code, rec.Body.String())
		}
	}
	// Multi-line target paste is split into entries.
	rec := doJSON(h, http.MethodPost, "/api/v1/profiles", tok, map[string]any{"name": "paste", "targets": []string{"10.0.0.1\r\n10.0.0.2;10.0.0.3, 10.0.0.4"}})
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"10.0.0.4"`) {
		t.Errorf("pasted targets: %d %s", rec.Code, rec.Body.String())
	}
}

func TestHostileManualEntry(t *testing.T) {
	_, _, h := setupTestServer(t)
	tok := loginTest(t, h, "admin", "Admin123!")
	for _, body := range []map[string]any{
		{"ip": "not-an-ip"}, {"ip": ""}, {"ip": "10.0.0.1", "port": 70000}, {"ip": "10.0.0.1", "services": []map[string]any{{"port": -5}}},
	} {
		rec := doJSON(h, http.MethodPost, "/api/v1/ingest/manual", tok, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("manual %v: got %d %s", body, rec.Code, rec.Body.String())
		}
	}
	rec := doJSON(h, http.MethodPost, "/api/v1/ingest/manual", tok, map[string]any{"ip": " 2001:DB8::1 ", "port": 443, "hostname": "zażółć.example"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid manual ipv6: %d %s", rec.Code, rec.Body.String())
	}
}

func hostileUpload(t *testing.T, h http.Handler, tok, filename string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", filename)
	_, _ = fw.Write(content)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHostileImports(t *testing.T) {
	_, _, h := setupTestServer(t)
	tok := loginTest(t, h, "operator", "Operator123!")
	bad := map[string][]byte{
		"empty.csv":       {},
		"blank.csv":       []byte("  \r\n \n"),
		"header-only.csv": []byte("ip,port\n"),
		"no-ip-col.csv":   []byte("name,port\nfoo,22\n"),
		"garbage-ip.csv":  []byte("ip,port\nnot-an-ip,22\n<script>,80\n"),
		"binary.json":     {0x00, 0xFF, 0x13, 0x37, 0x89, 'P', 'N', 'G'},
		"binary.csv":      {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00},
		"deep.json":       []byte(strings.Repeat("[", 50000) + strings.Repeat("]", 50000)),
		"bomb.xml": []byte(`<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><nmaprun><host><address addr="&lol3;" addrtype="ipv4"/></host></nmaprun>`),
		"xxe.xml":   []byte(`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun><host><address addr="&x;" addrtype="ipv4"/></host></nmaprun>`),
		"empty.xml": []byte(`<nmaprun></nmaprun>`),
	}
	for name, content := range bad {
		rec := hostileUpload(t, h, tok, name, content)
		if rec.Code < 400 || rec.Code >= 500 {
			t.Errorf("%s: got %d %s, want 4xx", name, rec.Code, rec.Body.String())
		}
	}
	// Polish Excel export with duplicates, BOM, CRLF, unicode hostname.
	csv := "\ufeffsep=;\r\nIP;Port;Hostname\r\n10.9.0.1;22;zażółć.agh.edu.pl\r\n10.9.0.1;22;zażółć.agh.edu.pl\r\nbad;80;x\r\n"
	rec := hostileUpload(t, h, tok, "excel.csv", []byte(csv))
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"skipped_records":1`) {
		t.Fatalf("excel csv: %d %s", rec.Code, rec.Body.String())
	}
}

func TestImportTooLargeIs413NotTruncated(t *testing.T) {
	_, _, h := setupTestServer(t)
	tok := loginTest(t, h, "operator", "Operator123!")
	big := bytes.Repeat([]byte("10.0.0.1,22\n"), int(maxImportFileBytes/12)+100)
	rec := hostileUpload(t, h, tok, "big.csv", append([]byte("ip,port\n"), big...))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String()[:min(200, rec.Body.Len())])
	}
}
