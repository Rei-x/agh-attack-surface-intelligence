package api

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// A /16 (65,536 IPs) must go through estimate and scan start quickly, without the HTTP
// request doing the expansion work synchronously for long.
func TestSlash16EstimateAndStartAreFast(t *testing.T) {
	_, _, h := setupTestServer(t)
	tok := loginTest(t, h, "operator", "Operator123!")
	start := time.Now()
	rec := doJSON(h, http.MethodPost, "/api/v1/targets/estimate", tok, map[string]any{"targets": []string{"10.20.0.0/16"}, "ports": "22,80,443"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "65536") {
		t.Fatalf("estimate /16: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(h, http.MethodPost, "/api/v1/scans", tok, map[string]any{"targets": []string{"10.20.0.0/16"}, "allowed_ports": "22"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start /16: %d %s", rec.Code, rec.Body.String())
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("/16 estimate+start took %v", d)
	}
	// 100k-entry target list is refused, not processed.
	many := make([]string, maxTargetEntries+1)
	for i := range many {
		many[i] = "10.0.0.1"
	}
	if rec := doJSON(h, http.MethodPost, "/api/v1/scans", tok, map[string]any{"targets": many}); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized target list: %d", rec.Code)
	}
}
