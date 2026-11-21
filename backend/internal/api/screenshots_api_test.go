package api

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/screenshot"
)

func testShot(t *testing.T, seed uint8) *domain.Screenshot {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1280, 800))
	for i := range img.Pix {
		img.Pix[i] = uint8(i/4096) + seed
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	p, err := screenshot.Process(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return &domain.Screenshot{Image: p.Full, Thumb: p.Thumb, PHash: screenshot.FormatHash(p.PHash),
		URL: "http://10.20.0.5:8080/", Title: "Jenkins", CapturedAt: time.Now().UTC()}
}

func setupScreenshotServer(t *testing.T) (*Server, http.Handler, *screenshot.Store) {
	t.Helper()
	srv, store, h := setupTestServer(t)
	v, _ := crypto.NewVault("")
	st, err := screenshot.OpenStore(t.TempDir(), v, 3)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetScreenshots(st)
	srv.pipeline.SetScreenshotSink(&screenshot.Sink{Store: st, DB: store})
	return srv, h, st
}

func TestScreenshotPipelineAndGallery(t *testing.T) {
	srv, h, st := setupScreenshotServer(t)
	obs := []domain.ObservedHost{{IP: "10.20.0.5", IsAlive: true, ObservedAt: time.Now().UTC(), Services: []domain.ObservedService{
		{Port: 8080, Protocol: "tcp", State: "open", ServiceName: "http",
			HTTP:       &domain.HTTPFingerprint{Scheme: "http", StatusCode: 200, Title: "Dashboard [Jenkins]"},
			Screenshot: testShot(t, 0)},
		{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http",
			HTTP:       &domain.HTTPFingerprint{Scheme: "http", StatusCode: 200, Title: "Apache2 Ubuntu Default Page: It works"},
			Screenshot: testShot(t, 40)},
	}}}
	if _, err := srv.pipeline.ProcessObservations(context.Background(), ingest.IngestRequest{RunType: domain.ScanTypeActive, Observations: obs}); err != nil {
		t.Fatal(err)
	}
	if st.Count() != 2 {
		t.Fatalf("stored %d screenshots, want 2", st.Count())
	}
	if obs[0].Services[0].Screenshot == nil {
		t.Fatal("pipeline must not mutate the caller's observations")
	}

	// Imports are user supplied: screenshots are stripped, never stored.
	imp := []domain.ObservedHost{{IP: "10.20.0.6", IsAlive: true, Services: []domain.ObservedService{{Port: 80, Protocol: "tcp", State: "open", Screenshot: testShot(t, 90)}}}}
	if _, err := srv.pipeline.ProcessObservations(context.Background(), ingest.IngestRequest{RunType: domain.ScanTypeImportJSON, Observations: imp}); err != nil {
		t.Fatal(err)
	}
	if st.Count() != 2 {
		t.Fatal("imported screenshot was stored")
	}

	token := loginTest(t, h, "admin", "Admin123!")
	rec := doJSON(h, http.MethodGet, "/api/v1/screenshots", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Items  []GalleryItem  `json:"items"`
		Total  int            `json:"total"`
		Counts map[string]int `json:"counts"`
		Status map[string]any `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if list.Total != 2 || list.Items[0].HostID == "" || list.Counts["default"] != 1 {
		t.Fatalf("gallery: %+v", list)
	}

	// Asset query language and kind chips filter the gallery.
	for q, want := range map[string]int{"/api/v1/screenshots?q=port:8080": 1, "/api/v1/screenshots?kind=default": 1, "/api/v1/screenshots?q=port:22": 0} {
		rec := doJSON(h, http.MethodGet, q, token, nil)
		var l struct {
			Total int `json:"total"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &l)
		if l.Total != want {
			t.Errorf("%s: total %d want %d", q, l.Total, want)
		}
	}
	if rec := doJSON(h, http.MethodGet, "/api/v1/screenshots?q=port:abc", token, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad query: %d", rec.Code)
	}

	// Image: JPEG for an authenticated user, 401 without a token, 404 for unknown ids.
	id := list.Items[0].Shot.Thumb
	req := httptest.NewRequest(http.MethodGet, "/api/v1/screenshots/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	img := httptest.NewRecorder()
	h.ServeHTTP(img, req)
	if img.Code != http.StatusOK || img.Header().Get("Content-Type") != "image/jpeg" || !bytes.HasPrefix(img.Body.Bytes(), []byte{0xFF, 0xD8}) {
		t.Fatalf("image: %d %s", img.Code, img.Header().Get("Content-Type"))
	}
	for _, path := range []string{"/api/v1/screenshots/" + id, "/api/v1/screenshots", "/api/v1/hosts/" + list.Items[0].HostID + "/screenshots"} {
		anon := httptest.NewRecorder()
		h.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, path, nil))
		if anon.Code != http.StatusUnauthorized {
			t.Errorf("%s without token: %d", path, anon.Code)
		}
	}
	if rec := doJSON(h, http.MethodGet, "/api/v1/screenshots/"+string(bytes.Repeat([]byte("a"), 64)), token, nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id: %d", rec.Code)
	}

	// Host drawer view.
	rec = doJSON(h, http.MethodGet, "/api/v1/hosts/"+list.Items[0].HostID+"/screenshots", token, nil)
	var hs struct {
		Services []screenshot.Service `json:"services"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &hs)
	if rec.Code != http.StatusOK || len(hs.Services) != 2 {
		t.Fatalf("host screenshots: %d %s", rec.Code, rec.Body.String())
	}

	// A visibly different page on the next scan records a change event.
	obs2 := []domain.ObservedHost{{IP: "10.20.0.5", IsAlive: true, ObservedAt: time.Now().UTC(), Services: []domain.ObservedService{
		{Port: 8080, Protocol: "tcp", State: "open", ServiceName: "http", HTTP: &domain.HTTPFingerprint{Scheme: "http", StatusCode: 200}, Screenshot: changedShot(t)},
	}}}
	if _, err := srv.pipeline.ProcessObservations(context.Background(), ingest.IngestRequest{RunType: domain.ScanTypeActive, Observations: obs2}); err != nil {
		t.Fatal(err)
	}
	rec = doJSON(h, http.MethodGet, "/api/v1/changes?event_type="+screenshot.EventScreenshotChanged, token, nil)
	if !bytes.Contains(rec.Body.Bytes(), []byte(screenshot.EventScreenshotChanged)) {
		t.Fatalf("no screenshot_changed event: %s", rec.Body.String())
	}
}

// changedShot is a left-to-right gradient: its difference hash is the opposite of a flat page.
func changedShot(t *testing.T) *domain.Screenshot {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1280, 800))
	for y := 0; y < 800; y++ {
		for x := 0; x < 1280; x++ {
			o := y*img.Stride + x*4
			g := uint8(250 - x*200/1280)
			img.Pix[o], img.Pix[o+1], img.Pix[o+2], img.Pix[o+3] = g, g, g, 255
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	p, err := screenshot.Process(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return &domain.Screenshot{Image: p.Full, Thumb: p.Thumb, PHash: screenshot.FormatHash(p.PHash), CapturedAt: time.Now().UTC()}
}
