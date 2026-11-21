package main

import (
	"fmt"
	"io"
	"log"
	"path/filepath"
	"runtime"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/screenshot"
)

// screenshotCapturer is the shared headless-Chromium capturer, or nil when this host has no
// browser (scans then simply run without screenshots).
func screenshotCapturer() scanner.ScreenshotCapturer {
	if c := screenshot.Shared(); c != nil {
		return c
	}
	return nil
}

// screenshotStore opens the encrypted screenshot store in <data dir>/screenshots once per
// runtime. nil when there is no data directory or it cannot be opened (logged).
func (rt *appRuntime) screenshotStore() *screenshot.Store {
	rt.shotsOnce.Do(func() {
		if rt.Dir == nil || rt.Vault == nil {
			return
		}
		st, err := screenshot.OpenStore(filepath.Join(rt.Dir.Path, "screenshots"), rt.Vault, screenshot.DefaultKeep)
		if err != nil {
			log.Printf("[WARN] screenshots disabled: %v", err)
			return
		}
		rt.shots = st
	})
	return rt.shots
}

// printScreenshotPreflight reports whether web services will be captured as pictures.
func printScreenshotPreflight(w io.Writer) {
	a := screenshot.Status()
	fmt.Fprintf(w, "shots:   %s\n", a.Detail)
	if !a.Available && !screenshot.Disabled() {
		switch runtime.GOOS {
		case "linux":
			fmt.Fprintln(w, "         for web screenshots: sudo apt install chromium   (or chromium-headless-shell; DZIECIOL_CHROME_PATH=/path)")
		case "darwin":
			fmt.Fprintln(w, "         for web screenshots install Google Chrome, or set DZIECIOL_CHROME_PATH")
		}
	}
}

// attachScreenshots wires the screenshot store into an ingest pipeline.
func (rt *appRuntime) attachScreenshots(p *ingest.Pipeline, emit func(domain.LiveEvent)) {
	if st := rt.screenshotStore(); st != nil {
		p.SetScreenshotSink(&screenshot.Sink{Store: st, DB: rt.Store, Emit: emit})
	}
}
