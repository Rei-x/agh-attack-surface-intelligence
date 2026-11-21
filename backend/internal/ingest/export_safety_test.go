package ingest

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestExportCSVNeutralizesFormulaInjection(t *testing.T) {
	hosts := []domain.Host{{IP: "10.0.0.1", Hostname: "=cmd|' /C calc'!A0", Services: []domain.Service{
		{Port: 80, Protocol: "tcp", Product: "@SUM(1+1)", HTTP: &domain.HTTPFingerprint{Title: "+HYPERLINK(\"http://x\")"}},
	}}}
	var buf bytes.Buffer
	if err := ExportCSV(&buf, hosts); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if cell != "" && (cell[0] == '=' || cell[0] == '+' || cell[0] == '@') {
				t.Fatalf("formula cell exported unescaped: %q", cell)
			}
		}
	}
}

func TestExportJSONStreamsValidDocumentThatReimports(t *testing.T) {
	var hosts []domain.Host
	for i := 0; i < 3000; i++ {
		hosts = append(hosts, domain.Host{IP: fmt.Sprintf("10.1.%d.%d", i/250, i%250+1), Services: []domain.Service{{Port: 22, Protocol: "tcp"}}})
	}
	var buf bytes.Buffer
	if err := ExportJSON(&buf, hosts); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Count int           `json:"count"`
		Hosts []domain.Host `json:"hosts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil || doc.Count != 3000 || len(doc.Hosts) != 3000 {
		t.Fatalf("export invalid: %v count=%d hosts=%d", err, doc.Count, len(doc.Hosts))
	}
	var empty bytes.Buffer
	_ = ExportJSON(&empty, nil)
	if !json.Valid(empty.Bytes()) {
		t.Fatalf("empty export invalid: %s", empty.String())
	}
	back, err := ParseJSON(bytes.NewReader(buf.Bytes()))
	if err != nil || len(back) != 3000 {
		t.Fatalf("re-import of own export: %v %d", err, len(back))
	}
}
