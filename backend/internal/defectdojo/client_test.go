package defectdojo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// fakeDojo mimics the DefectDojo v2 rules that matter to us: token auth, reimport-scan
// needing either a test id or product/engagement names + auto_create_context, and a stable
// test per (engagement, test_title).
type fakeDojo struct {
	t        *testing.T
	tests    map[string]int // test_title -> id
	forms    []map[string]string
	files    []string
	findings map[int][]map[string]any
}

func newFakeDojo(t *testing.T) *fakeDojo {
	return &fakeDojo{t: t, tests: map[string]int{}, findings: map[int][]map[string]any{}}
}

func (f *fakeDojo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Token secret-dojo-token" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"Invalid token"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v2/engagements/7/"):
		_, _ = w.Write([]byte(`{"id":7,"name":"CBI ASI 2026","product":3}`))
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/products/3/":
		_, _ = w.Write([]byte(`{"id":3,"name":"AGH Kampus","prod_type":2}`))
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/product_types/2/":
		_, _ = w.Write([]byte(`{"id":2,"name":"Uczelnia"}`))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v2/engagements"):
		_, _ = w.Write([]byte(`{"count":3,"results":[{"id":1,"name":"CBI AGH ASI"}]}`))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/findings/":
		// Real DefectDojo rejects findings without a test.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"Unable to check for permissions: Attribute 'test' is required"}`))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/reimport-scan/":
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			f.t.Errorf("ParseMultipartForm: %v", err)
		}
		form := map[string]string{}
		for k, v := range r.MultipartForm.Value {
			form[k] = v[0]
		}
		if form["auto_create_context"] != "true" || form["product_name"] == "" || form["engagement_name"] == "" || form["test_title"] == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"detail":"test or product/engagement names required"}`))
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			f.t.Fatalf("FormFile: %v", err)
		}
		b, _ := io.ReadAll(file)
		file.Close()
		f.forms = append(f.forms, form)
		f.files = append(f.files, string(b))
		id, ok := f.tests[form["test_title"]]
		if !ok {
			id = 40 + len(f.tests)
			f.tests[form["test_title"]] = id
		}
		if form["scan_type"] == "Generic Findings Import" {
			var doc struct {
				Findings []map[string]any `json:"findings"`
			}
			_ = json.Unmarshal(b, &doc)
			f.findings[id] = append(f.findings[id], doc.Findings...)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"test":` + itoa(id) + `,"engagement_id":7,"product_id":3,"statistics":{"after":{"total":{"total":1}}}}`))
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/findings/":
		id := 0
		for _, c := range r.URL.Query().Get("test") {
			id = id*10 + int(c-'0')
		}
		var out []map[string]any
		for i, fd := range f.findings[id] {
			out = append(out, map[string]any{"id": 100 + i, "unique_id_from_tool": fd["unique_id_from_tool"]})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": out})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestDefectDojoClientUsesReimportWithResolvedContext(t *testing.T) {
	fd := newFakeDojo(t)
	srv := httptest.NewServer(fd)
	defer srv.Close()

	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "secret-dojo-token", EngagementID: 7, VerifyTLS: true}
	client := NewClient()
	ctx := context.Background()

	st, err := client.TestConnection(ctx, cfg)
	if err != nil || !st.OK || st.EngagementsCount != 3 {
		t.Fatalf("TestConnection failed: st=%+v err=%v", st, err)
	}

	xmlPayload := `<?xml version="1.0"?><nmaprun scanner="nmap"><host><address addr="172.28.0.10" addrtype="ipv4"/><hostnames/></host></nmaprun>`
	imp, err := client.ImportNmapXML(ctx, cfg, 0, NmapTestTitle("Kampus nocny"), "Run #3", xmlPayload)
	if err != nil {
		t.Fatalf("ImportNmapXML: %v", err)
	}
	form := fd.forms[0]
	if form["scan_type"] != "Nmap Scan" || form["close_old_findings"] != "true" || form["version"] != "Run #3" {
		t.Fatalf("unexpected nmap reimport form: %+v", form)
	}
	if form["product_type_name"] != "Uczelnia" || form["product_name"] != "AGH Kampus" || form["engagement_name"] != "CBI ASI 2026" {
		t.Fatalf("pinned engagement 7 was not resolved to names: %+v", form)
	}
	if form["test_title"] != "Dzięcioł Nmap: Kampus nocny" || !strings.Contains(fd.files[0], "172.28.0.10") {
		t.Fatalf("unexpected test title/file: %+v", form)
	}
	if imp.TestID != 40 || !strings.HasSuffix(imp.ExternalURL, "/test/40") {
		t.Fatalf("unexpected import result: %+v", imp)
	}

	// Second run of the same profile lands in the same test.
	if imp2, err := client.ImportNmapXML(ctx, cfg, 0, NmapTestTitle("Kampus nocny"), "Run #4", xmlPayload); err != nil || imp2.TestID != 40 {
		t.Fatalf("second run should reimport into test 40: %+v %v", imp2, err)
	}

	res, err := client.PushFindings(ctx, cfg, 0, []FindingInput{{
		SourceID: "svc-1", HostIP: "172.28.0.11", Port: 80, Protocol: "tcp",
		Title: "Exposed Admin Panel on 172.28.0.11:80", Description: "Evidence", Severity: "high", Tags: []string{"admin_panel"},
	}})
	if err != nil || len(res) != 1 || res[0].Status != "success" {
		t.Fatalf("PushFindings failed: res=%+v err=%v", res, err)
	}
	last := fd.forms[len(fd.forms)-1]
	if last["scan_type"] != "Generic Findings Import" || last["test_title"] != ObservationsTest || last["close_old_findings"] != "false" {
		t.Fatalf("observations must use Generic Findings Import without closing old findings: %+v", last)
	}
	expectedUID := UniqueID("172.28.0.11", 80, "tcp", "svc-1")
	if res[0].UniqueIDFromTool != expectedUID || res[0].ExternalID != "100" || !strings.HasSuffix(res[0].ExternalURL, "/finding/100") {
		t.Fatalf("unexpected push result: %+v", res[0])
	}
	if !strings.Contains(fd.files[len(fd.files)-1], expectedUID) || !strings.Contains(fd.files[len(fd.files)-1], `"severity":"High"`) {
		t.Fatalf("generic findings payload missing uid/severity: %s", fd.files[len(fd.files)-1])
	}
}

// TestRealDefectDojo runs against a live instance when AEGIS_DD_URL and AEGIS_DD_TOKEN are set:
//
//	AEGIS_DD_URL=http://localhost:8081 AEGIS_DD_TOKEN=... go test ./internal/defectdojo -run Real -v
func TestRealDefectDojo(t *testing.T) {
	url, token := os.Getenv("AEGIS_DD_URL"), os.Getenv("AEGIS_DD_TOKEN")
	if url == "" || token == "" {
		t.Skip("AEGIS_DD_URL/AEGIS_DD_TOKEN not set")
	}
	cfg := &domain.DefectDojoConfig{URL: url, APIToken: token}
	client := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if st, err := client.TestConnection(ctx, cfg); err != nil || !st.OK {
		t.Fatalf("TestConnection: %+v %v", st, err)
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	title := NmapTestTitle("integration-" + stamp)
	run1 := `<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sV" start="1763730000" version="7.94"><host><status state="up"/><address addr="10.66.0.5" addrtype="ipv4"/><hostnames></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port></ports></host></nmaprun>`
	imp, err := client.ImportNmapXML(ctx, cfg, 0, title, "run-1", run1)
	if err != nil || imp.TestID == 0 {
		t.Fatalf("nmap import run 1: %+v %v", imp, err)
	}
	run2 := strings.Replace(run1, `<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>`, "", 1)
	imp2, err := client.ImportNmapXML(ctx, cfg, 0, title, "run-2", run2)
	if err != nil || imp2.TestID != imp.TestID {
		t.Fatalf("nmap reimport run 2 should hit the same test: %+v %v", imp2, err)
	}
	var active struct {
		Count int `json:"count"`
	}
	if err := client.getJSON(ctx, cfg, "/api/v2/findings/?active=true&test="+itoa(imp.TestID), &active); err != nil {
		t.Fatal(err)
	}
	if active.Count != 1 {
		t.Fatalf("after run 2 only port 22 should stay active (port 80 closed by DefectDojo), got %d", active.Count)
	}

	res, err := client.PushFindings(ctx, cfg, 0, []FindingInput{{
		SourceID: "svc-it-" + stamp, HostIP: "10.66.0.5", Port: 8080, Protocol: "tcp",
		Title: "Exposed admin panel 10.66.0.5:8080 " + stamp, Description: "integration", Severity: "info",
	}})
	if err != nil || len(res) != 1 || res[0].Status != "success" || res[0].ExternalID == "" {
		t.Fatalf("PushFindings: %+v %v", res, err)
	}
	t.Logf("nmap test %s, finding %s", imp.ExternalURL, res[0].ExternalURL)
}
