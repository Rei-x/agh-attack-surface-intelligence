package agent

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestTrimScreenshotsKeepsResults(t *testing.T) {
	shot := func() *domain.Screenshot {
		return &domain.Screenshot{Image: make([]byte, 600), Thumb: make([]byte, 100)}
	}
	obs := []domain.ObservedHost{
		{IP: "10.0.0.1", Services: []domain.ObservedService{{Port: 80, Screenshot: shot()}, {Port: 443, Screenshot: shot()}}},
		{IP: "10.0.0.2", Services: []domain.ObservedService{{Port: 8080, Screenshot: shot()}, {Port: 22}}},
	}
	if n := trimScreenshots(obs, 1500); n != 1 {
		t.Fatalf("dropped %d, want 1", n)
	}
	if obs[0].Services[0].Screenshot == nil || obs[0].Services[1].Screenshot == nil || obs[1].Services[0].Screenshot != nil {
		t.Fatal("wrong screenshot dropped")
	}
	if len(obs[1].Services) != 2 {
		t.Fatal("services must survive trimming")
	}
}

func TestGzipBody(t *testing.T) {
	if _, ok := gzipBody([]byte(`{"small":true}`)); ok {
		t.Fatal("small bodies stay uncompressed")
	}
	big := bytes.Repeat([]byte(`{"image":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="},`), 4000)
	z, ok := gzipBody(big)
	if !ok || len(z) >= len(big) {
		t.Fatal("large body not compressed")
	}
	zr, err := gzip.NewReader(bytes.NewReader(z))
	if err != nil {
		t.Fatal(err)
	}
	back, _ := io.ReadAll(zr)
	if !bytes.Equal(back, big) {
		t.Fatal("round trip")
	}
}
