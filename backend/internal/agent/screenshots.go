package agent

import (
	"bytes"
	"compress/gzip"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// gzipMinBytes is the request body size above which bodies are sent gzip-compressed.
const gzipMinBytes = 64 << 10

// gzipBody compresses a large JSON body. ok=false leaves it as is (small, or no gain).
func gzipBody(raw []byte) ([]byte, bool) {
	if len(raw) < gzipMinBytes {
		return nil, false
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if _, err := zw.Write(raw); err != nil {
		return nil, false
	}
	if err := zw.Close(); err != nil || buf.Len() >= len(raw) {
		return nil, false
	}
	return buf.Bytes(), true
}

// maxChunkScreenshotBytes caps the image bytes one chunk upload carries (well under the
// server's 65 MB agent body limit even after base64). A /24 full of web servers stays far
// below it: a stored screenshot is about 50 KB plus a 10 KB thumbnail.
const maxChunkScreenshotBytes = 24 << 20

// trimScreenshots drops screenshots beyond the byte budget so a chunk upload never grows
// past what the server accepts. Results themselves are always kept. Returns how many
// screenshots were dropped.
func trimScreenshots(obs []domain.ObservedHost, budget int) int {
	used, dropped := 0, 0
	for i := range obs {
		svcs := obs[i].Services
		for j := range svcs {
			sh := svcs[j].Screenshot
			if sh == nil {
				continue
			}
			size := len(sh.Image) + len(sh.Thumb)
			if used+size > budget {
				svcs[j].Screenshot = nil
				dropped++
				continue
			}
			used += size
		}
	}
	return dropped
}
