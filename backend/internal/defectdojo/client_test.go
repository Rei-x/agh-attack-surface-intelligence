package defectdojo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestDefectDojoClientV2EndToEnd(t *testing.T) {
	var gotAuth, gotScanType, gotXML, gotUniqueID string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth != "Token secret-dojo-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"Invalid token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v2/engagements"):
			_, _ = w.Write([]byte(`{"count":3,"results":[{"id":1,"name":"CBI AGH ASI"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/import-scan/":
			if err := r.ParseMultipartForm(4 << 20); err != nil {
				t.Errorf("ParseMultipartForm: %v", err)
			}
			gotScanType = r.FormValue("scan_type")
			f, _, err := r.FormFile("file")
			if err != nil {
				t.Errorf("FormFile: %v", err)
			} else {
				b, _ := io.ReadAll(f)
				gotXML = string(b)
				f.Close()
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"test":42,"engagement_id":7,"message":"Imported"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/findings/":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotUniqueID, _ = body["unique_id_from_tool"].(string)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":101}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := &domain.DefectDojoConfig{
		URL:          srv.URL,
		APIToken:     "secret-dojo-token",
		EngagementID: 7,
		VerifyTLS:    true,
	}
	client := NewClient()
	ctx := context.Background()

	// 1. TestConnection
	st, err := client.TestConnection(ctx, cfg)
	if err != nil || !st.OK || st.EngagementsCount != 3 {
		t.Fatalf("TestConnection failed: st=%+v err=%v", st, err)
	}

	// 2. ImportNmapXML
	xmlPayload := `<?xml version="1.0"?><nmaprun scanner="nmap"><host><address addr="172.28.0.10" addrtype="ipv4"/></host></nmaprun>`
	imp, err := client.ImportNmapXML(ctx, cfg, 7, "CBI Lab Scan", xmlPayload)
	if err != nil {
		t.Fatalf("ImportNmapXML: %v", err)
	}
	if imp.TestID != 42 || gotScanType != "Nmap Scan" || !strings.Contains(gotXML, "172.28.0.10") {
		t.Fatalf("unexpected import result: imp=%+v scanType=%q", imp, gotScanType)
	}

	// 3. PushFindings with deterministic unique_id_from_tool
	res, err := client.PushFindings(ctx, cfg, 7, []FindingInput{
		{
			SourceID:    "svc-1",
			HostIP:      "172.28.0.11",
			Port:        80,
			Protocol:    "tcp",
			Title:       "Exposed Admin Panel on 172.28.0.11:80",
			Description: "Evidence receipt details",
			Severity:    "high",
			Tags:        []string{"admin_panel"},
		},
	})
	if err != nil || len(res) != 1 || res[0].Status != "success" || res[0].ExternalID != "101" {
		t.Fatalf("PushFindings failed: res=%+v err=%v", res, err)
	}
	expectedUID := UniqueID("172.28.0.11", 80, "tcp", "svc-1")
	if gotUniqueID != expectedUID || res[0].UniqueIDFromTool != expectedUID {
		t.Fatalf("deterministic unique_id_from_tool mismatch: got=%q want=%q", gotUniqueID, expectedUID)
	}
}
