package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// SyncTriage: FP -> false_p, accepted risk -> risk_accepted (enabling simple risk acceptance
// on the product when DefectDojo refuses), withdrawn -> active; already-correct and
// mitigated findings are left alone.
func TestSyncTriageMirrorsDecisions(t *testing.T) {
	var mu sync.Mutex
	patches := map[string]map[string]any{}
	notes := 0
	productRA := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/findings/":
			_, _ = io.WriteString(w, `{"results":[
				{"id":1,"unique_id_from_tool":"u-fp","active":true},
				{"id":2,"unique_id_from_tool":"u-ra","active":true},
				{"id":3,"unique_id_from_tool":"u-back","active":false,"false_p":true},
				{"id":4,"unique_id_from_tool":"u-ok","active":true},
				{"id":5,"unique_id_from_tool":"u-fixed","active":false,"is_mitigated":true}]}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v2/products/7/":
			productRA = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v2/findings/"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["risk_accepted"] == true && !productRA {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"risk_accepted":["Simple risk acceptance is disabled for this product"]}`)
				return
			}
			patches[r.URL.Path] = body
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/notes/"):
			notes++
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusNotFound)
		}
	}))
	defer srv.Close()

	exp := time.Now().Add(48 * time.Hour)
	mk := func(uid string, tr *domain.TriageInfo) ChangeFinding {
		f := ChangeFinding{Kind: KindExposure, ServiceID: "svc-" + uid, Triage: tr}
		f.UniqueIDFromTool = uid
		return f
	}
	findings := []ChangeFinding{
		mk("u-fp", &domain.TriageInfo{Status: domain.TriageFalsePositive, Reason: "sinkhole", By: "ana"}),
		mk("u-ra", &domain.TriageInfo{Status: domain.TriageAcceptedRisk, Reason: "honeypot", By: "ana", ExpiresAt: &exp}),
		mk("u-back", nil),
		mk("u-ok", nil),
		mk("u-fixed", nil),
		mk("u-new", nil),
	}
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}
	refs, changed, err := NewClient().SyncTriage(context.Background(), cfg, 9, 7, findings)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 3 || len(refs) != 6 {
		t.Fatalf("changed=%d refs=%d", changed, len(refs))
	}
	if p := patches["/api/v2/findings/1/"]; p["false_p"] != true || p["active"] != false {
		t.Errorf("FP patch: %v", p)
	}
	if p := patches["/api/v2/findings/2/"]; p["risk_accepted"] != true || !productRA {
		t.Errorf("RA patch: %v (product simple RA enabled: %v)", p, productRA)
	}
	if p := patches["/api/v2/findings/3/"]; p["active"] != true || p["false_p"] != false {
		t.Errorf("reactivation patch: %v", p)
	}
	if _, ok := patches["/api/v2/findings/4/"]; ok {
		t.Error("already-active finding patched")
	}
	if _, ok := patches["/api/v2/findings/5/"]; ok {
		t.Error("mitigated finding re-activated")
	}
	if notes != 3 {
		t.Errorf("notes=%d, want 3", notes)
	}
	want := map[string]string{"svc-u-fp": DojoStateFalsePos, "svc-u-ra": DojoStateRiskAccepted, "svc-u-back": DojoStateActive, "svc-u-fixed": DojoStateMitigated}
	for _, r := range refs {
		if w, ok := want[r.ServiceID]; ok && r.State != w {
			t.Errorf("%s state %s, want %s", r.ServiceID, r.State, w)
		}
		if r.ServiceID == "svc-u-fp" && r.URL != srv.URL+"/finding/1" {
			t.Errorf("finding link %q", r.URL)
		}
	}
}
