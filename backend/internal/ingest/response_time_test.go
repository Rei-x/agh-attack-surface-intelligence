package ingest

import (
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestResponseTimeJump(t *testing.T) {
	cases := []struct {
		before, after  int64
		slower, faster bool
	}{
		{12, 520, true, false},    // Toxiproxy latency 500 ms
		{520, 12, false, true},    // latency removed
		{40, 90, false, false},    // noise: ratio < 3
		{10, 150, false, false},   // ratio 15 but only +140 ms
		{900, 1300, false, false}, // slow app, small relative change
		{0, 600, true, false},
	}
	for _, c := range cases {
		s, f := ResponseTimeJump(c.before, c.after)
		if s != c.slower || f != c.faster {
			t.Errorf("%d -> %d: got slower=%v faster=%v", c.before, c.after, s, f)
		}
	}
}

func TestResponseTimeEvent(t *testing.T) {
	prev := &domain.Service{HTTP: &domain.HTTPFingerprint{ResponseTimeMs: 30, MedianResponseMs: 12}}
	curr := &domain.Service{HTTP: &domain.HTTPFingerprint{ResponseTimeMs: 1100, MedianResponseMs: 520, ResponseSamples: 11}}
	ev, ok := responseTimeEvent(prev, curr)
	if !ok || ev.EventType != "RESPONSE_TIME_CHANGED" || !strings.Contains(ev.Summary, "12 ms -> 520 ms") {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
	if _, ok := responseTimeEvent(&domain.Service{}, curr); ok {
		t.Fatal("no event without a previous HTTP measurement")
	}
}
