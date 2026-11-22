package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

// With retention on, every ingest compacts: the host timeline summarizes the removed change
// events (those of the newest three runs are protected from the per-host cap) and the scan
// diff explains a removed snapshot instead of diffing against nothing.
func TestRetentionTimelineRollupAndRetiredSnapshot(t *testing.T) {
	srv, _, h := setupTestServer(t)
	ctx := context.Background()
	viewerTok := loginTest(t, h, "viewer", "Viewer123!")
	srv.pipeline.SetRetention(db.RetentionPolicy{ChangesPerHost: 2, SnapshotRuns: 1})

	var runs []*domain.ScanRun
	for i, ports := range [][]int{{80}, {80, 22}, {22}, {22, 3389}} {
		var svcs []domain.ObservedService
		for _, p := range ports {
			svcs = append(svcs, domain.ObservedService{Port: p, ServiceName: map[int]string{80: "http", 22: "ssh", 3389: "ms-wbt-server"}[p]})
		}
		res, err := srv.pipeline.ProcessObservations(ctx, ingest.IngestRequest{
			ScanName:     "run",
			Observations: []domain.ObservedHost{{IP: "10.70.0.5", IsAlive: true, Services: svcs}},
		})
		if err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
		runs = append(runs, res.ScanRun)
		time.Sleep(5 * time.Millisecond)
	}
	host, err := srv.store.GetHostByIP(ctx, "10.70.0.5")
	if err != nil {
		t.Fatal(err)
	}

	r := doJSON(h, http.MethodGet, "/api/v1/hosts/"+host.ID+"/timeline", viewerTok, nil)
	var tl struct {
		Entries []domain.HostTimelineEntry `json:"entries"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &tl)
	var rollup *domain.HostTimelineEntry
	changes := 0
	for i := range tl.Entries {
		switch tl.Entries[i].Kind {
		case "compacted":
			rollup = &tl.Entries[i]
		case "change":
			changes++
		}
	}
	if r.Code != http.StatusOK || rollup == nil || changes < 2 {
		t.Fatalf("timeline should keep the recent change events and one summary row: %d %s", r.Code, r.Body.String())
	}
	if rollup.Count < 2 || !strings.Contains(rollup.Summary, "NEW_HOST") || !strings.Contains(rollup.Summary, "history retention") {
		t.Fatalf("summary row: %+v", rollup)
	}

	// Runs 0 and 1 lost their snapshots (newest 1 overall, newest 2 of the profile kept).
	r = doJSON(h, http.MethodGet, "/api/v1/scans/diff?from="+runs[0].ID+"&to="+runs[3].ID, viewerTok, nil)
	if r.Code != http.StatusGone || !strings.Contains(r.Body.String(), "DZIECIOL_RETENTION_SNAPSHOTS") {
		t.Fatalf("diff against a retired snapshot: %d %s", r.Code, r.Body.String())
	}
	r = doJSON(h, http.MethodGet, "/api/v1/scans/diff?from="+runs[2].ID+"&to="+runs[3].ID, viewerTok, nil)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "3389") {
		t.Fatalf("diff of kept snapshots: %d %s", r.Code, r.Body.String())
	}
}
