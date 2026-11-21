package domain

import "time"

// Screenshot is a rendered picture of a web service's landing page, taken by a headless
// Chromium during HTTP fingerprinting (internal/screenshot). It rides on ObservedService from
// the scanner (local or remote agent) to the ingest pipeline, which moves it into the
// encrypted screenshot store and strips it from the observation.
type Screenshot struct {
	Image      []byte    `json:"image"`           // JPEG, downscaled (about 960x600)
	Thumb      []byte    `json:"thumb"`           // JPEG thumbnail (about 320x200)
	Width      int       `json:"width"`           // of Image
	Height     int       `json:"height"`          // of Image
	PHash      string    `json:"phash"`           // 64-bit difference hash, 16 hex chars
	URL        string    `json:"url"`             // page that was loaded
	Title      string    `json:"title,omitempty"` // document.title after load
	CapturedAt time.Time `json:"captured_at"`
}

// ScreenshotsEnabled reports whether runs of this profile capture screenshots (default on).
func (p ScanProfile) ScreenshotsEnabled() bool {
	return p.CaptureScreenshots == nil || *p.CaptureScreenshots
}
