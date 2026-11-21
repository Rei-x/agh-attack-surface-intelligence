package screenshot

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestRealChrome drives an installed Chromium end to end. Opt in with DZIECIOL_CHROME_TEST=1
// (it needs a browser, so it is skipped by default and in CI).
func TestRealChrome(t *testing.T) {
	if os.Getenv("DZIECIOL_CHROME_TEST") == "" {
		t.Skip("set DZIECIOL_CHROME_TEST=1 to run against a real Chromium")
	}
	path := FindChrome()
	if path == "" {
		t.Skip("no Chromium found")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>iDRAC9 Login</title></head><body style="background:#123">
<script>alert("dialogs are dismissed")</script><h1 style="color:white">Integrated Dell Remote Access Controller</h1></body></html>`)
	}))
	defer srv.Close()

	c := NewCapturer(func() (Browser, error) { return LaunchChrome(path) }, Options{})
	defer c.Close()
	shot, err := c.Capture(context.Background(), srv.URL+"/") // self-signed: TLS errors ignored
	if err != nil {
		t.Fatal(err)
	}
	if shot.Title != "iDRAC9 Login" || shot.Width != FullWidth || len(shot.Image) < 1000 {
		t.Fatalf("title=%q size=%dx%d bytes=%d", shot.Title, shot.Width, shot.Height, len(shot.Image))
	}
	t.Logf("full %d B, thumb %d B, phash %s", len(shot.Image), len(shot.Thumb), shot.PHash)
}
