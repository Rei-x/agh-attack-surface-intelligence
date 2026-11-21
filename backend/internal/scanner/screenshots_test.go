package scanner

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

type fakeCapturer struct {
	mu   sync.Mutex
	urls []string
}

func (f *fakeCapturer) Capture(_ context.Context, url string) (*domain.Screenshot, error) {
	f.mu.Lock()
	f.urls = append(f.urls, url)
	f.mu.Unlock()
	if url == "http://10.0.0.2:8080/" {
		return nil, errors.New("net::ERR_CONNECTION_RESET")
	}
	return &domain.Screenshot{Image: []byte{0xFF, 0xD8}, URL: url}, nil
}

func svcMapForShots() map[string][]domain.ObservedService {
	return map[string][]domain.ObservedService{
		"10.0.0.1": {
			{Port: 22, ServiceName: "ssh"},
			{Port: 443, ServiceName: "https", HTTP: &domain.HTTPFingerprint{Scheme: "https", StatusCode: 200}},
		},
		"10.0.0.2": {
			{Port: 8080, ServiceName: "http", HTTP: &domain.HTTPFingerprint{Scheme: "http", StatusCode: 401}},
			{Port: 9000, ServiceName: "http"}, // fingerprint failed: no screenshot attempt
		},
	}
}

func TestCaptureScreenshotsCountsAgainstGovernor(t *testing.T) {
	fc := &fakeCapturer{}
	e := NewEngine(EngineConfig{Screenshots: fc})
	gov := NewGovernor(GovernorConfig{GlobalRatePerSec: 1000, GlobalBurst: 100, PerHostRatePerSec: 1000, PerHostBurst: 100})
	st := &stageStats{}
	m := svcMapForShots()
	var mu sync.Mutex
	e.captureScreenshots(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, m, domain.ScanProfile{}, gov, st, &mu)

	if len(fc.urls) != 2 {
		t.Fatalf("captured %v, want the two fingerprinted HTTP services", fc.urls)
	}
	if st.httpRequests.Load() != 2 {
		t.Fatalf("http requests = %d, want 2 (screenshots count against the HTTP budget)", st.httpRequests.Load())
	}
	if m["10.0.0.1"][1].Screenshot == nil || m["10.0.0.1"][1].Screenshot.URL != "https://10.0.0.1/" {
		t.Fatalf("https service screenshot: %+v", m["10.0.0.1"][1].Screenshot)
	}
	if m["10.0.0.2"][0].Screenshot != nil {
		t.Fatal("failed capture must leave no screenshot (and not fail the scan)")
	}
	if m["10.0.0.1"][0].Screenshot != nil || m["10.0.0.2"][1].Screenshot != nil {
		t.Fatal("non-HTTP service got a screenshot")
	}
}

func TestCaptureScreenshotsRespectsProfileAndAbsence(t *testing.T) {
	off := false
	fc := &fakeCapturer{}
	var mu sync.Mutex
	NewEngine(EngineConfig{Screenshots: fc}).captureScreenshots(context.Background(), []string{"10.0.0.1"}, svcMapForShots(), domain.ScanProfile{CaptureScreenshots: &off}, nil, nil, &mu)
	if len(fc.urls) != 0 {
		t.Fatal("profile switch off must skip screenshots")
	}
	// No browser on this host: nothing happens.
	m := svcMapForShots()
	NewEngine(EngineConfig{}).captureScreenshots(context.Background(), []string{"10.0.0.1"}, m, domain.ScanProfile{}, nil, nil, &mu)
	if m["10.0.0.1"][1].Screenshot != nil {
		t.Fatal("screenshot without capturer")
	}
}

func TestScreenshotURL(t *testing.T) {
	cases := map[string]string{
		screenshotURL("10.0.0.1", 80, "http"):    "http://10.0.0.1/",
		screenshotURL("10.0.0.1", 443, "https"):  "https://10.0.0.1/",
		screenshotURL("10.0.0.1", 8443, "https"): "https://10.0.0.1:8443/",
		screenshotURL("fd00::1", 8080, ""):       "http://[fd00::1]:8080/",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %s want %s", got, want)
		}
	}
}
