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
// mitigated findings are left alone, and so is a false positive set in DefectDojo itself.
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
				{"id":3,"unique_id_from_tool":"u-back","active":false,"false_p":true,"notes":[
					{"id":30,"entry":"Dzięcioł triage: False positive by ana on 2026-11-20. Reason: sinkhole"}]},
				{"id":4,"unique_id_from_tool":"u-ok","active":true},
				{"id":5,"unique_id_from_tool":"u-fixed","active":false,"is_mitigated":true},
				{"id":6,"unique_id_from_tool":"u-dd","active":false,"false_p":true,"notes":[
					{"id":61,"entry":"Not our host, belongs to the ISP"},
					{"id":60,"entry":"Dzięcioł: analyst decision withdrawn or expired - finding is active again."},
					{"id":59,"entry":"Dzięcioł triage: False positive by ana on 2026-11-01. Reason: lab"}]}]}`)
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
		mk("u-dd", nil),
	}
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}
	refs, changed, err := NewClient().SyncTriage(context.Background(), cfg, 9, 7, findings)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 3 || len(refs) != 7 {
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
	if _, ok := patches["/api/v2/findings/6/"]; ok {
		t.Error("false positive set in DefectDojo (after the Dzięcioł decision was withdrawn) re-activated")
	}
	if notes != 3 {
		t.Errorf("notes=%d, want 3", notes)
	}
	want := map[string]string{"svc-u-fp": DojoStateFalsePos, "svc-u-ra": DojoStateRiskAccepted, "svc-u-back": DojoStateActive,
		"svc-u-fixed": DojoStateMitigated, "svc-u-dd": DojoStateFalsePos}
	for _, r := range refs {
		if w, ok := want[r.ServiceID]; ok && r.State != w {
			t.Errorf("%s state %s, want %s", r.ServiceID, r.State, w)
		}
		if r.ServiceID == "svc-u-fp" && r.URL != srv.URL+"/finding/1" {
			t.Errorf("finding link %q", r.URL)
		}
	}
}

// A change test of a large scope holds thousands of findings: SyncTriage must page through
// all of them (DefectDojo caps a page), not decide on the first page only.
func TestSyncTriagePagesThroughLargeTests(t *testing.T) {
	const total = 2500
	var queries []string
	patched := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/findings/":
			q := r.URL.Query()
			queries = append(queries, r.URL.RawQuery)
			if q.Has("is_mitigated") || q.Has("active") {
				t.Errorf("listing must include mitigated findings (a false positive is one): %s", r.URL.RawQuery)
			}
			limit, offset := atoiQ(q.Get("limit")), atoiQ(q.Get("offset"))
			var res []map[string]any
			for i := offset; i < total && i < offset+limit; i++ {
				res = append(res, map[string]any{"id": i + 1, "unique_id_from_tool": fmt.Sprintf("u-%d", i), "active": true})
			}
			var next any
			if offset+limit < total {
				next = "http://dojo.internal/api/v2/findings/?offset=x"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"count": total, "next": next, "results": res})
		case r.Method == http.MethodPatch:
			patched[r.URL.Path] = true
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	f := ChangeFinding{Kind: KindExposure, Triage: &domain.TriageInfo{Status: domain.TriageFalsePositive, Reason: "lab"}}
	f.UniqueIDFromTool = fmt.Sprintf("u-%d", total-1) // on the last page
	refs, changed, err := NewClient().SyncTriage(context.Background(), &domain.DefectDojoConfig{URL: srv.URL}, 5, 0, []ChangeFinding{f})
	if err != nil || changed != 1 || refs[0].FindingID != total {
		t.Fatalf("refs=%+v changed=%d err=%v (queries %v)", refs, changed, err, queries)
	}
	if len(queries) != 3 || !patched[fmt.Sprintf("/api/v2/findings/%d/", total)] {
		t.Fatalf("want 3 pages and a patch of finding %d, got %v %v", total, queries, patched)
	}
}

func atoiQ(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
