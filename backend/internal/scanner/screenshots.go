package scanner

import (
	"context"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ScreenshotCapturer renders a web page (internal/screenshot.Capturer with a headless
// Chromium). Tests plug in fakes.
type ScreenshotCapturer interface {
	Capture(ctx context.Context, url string) (*domain.Screenshot, error)
}

// maxScreenshotWorkers bounds pages rendered at once per chunk; the capturer has its own
// scan-wide limit on browser tabs.
const maxScreenshotWorkers = 4

// screenshotURL is the landing page of a fingerprinted service, addressed by IP so it works
// without DNS. The browser follows redirects itself.
func screenshotURL(ip string, port int, scheme string) string {
	if scheme != "https" {
		scheme = "http"
	}
	host := ip
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		host = net.JoinHostPort(ip, strconv.Itoa(port))
	} else if net.ParseIP(ip) != nil && net.ParseIP(ip).To4() == nil {
		host = "[" + ip + "]"
	}
	return scheme + "://" + host + "/"
}

// captureScreenshots takes a picture of every service that answered HTTP in this chunk.
// Each page load counts as one HTTP request against the Governor. Failures are ignored:
// a missing screenshot never fails the scan.
func (e *Engine) captureScreenshots(ctx context.Context, activeIPs []string, svcMap map[string][]domain.ObservedService, profile domain.ScanProfile, gov *Governor, st *stageStats, mu *sync.Mutex) {
	if e.cfg.Screenshots == nil || !profile.ScreenshotsEnabled() || ctx.Err() != nil {
		return
	}
	type job struct {
		ip  string
		idx int
		url string
	}
	var jobs []job
	mu.Lock()
	for _, ip := range activeIPs {
		for idx, s := range svcMap[ip] {
			if s.HTTP == nil || s.HTTP.StatusCode == 0 {
				continue
			}
			jobs = append(jobs, job{ip: ip, idx: idx, url: screenshotURL(ip, s.Port, s.HTTP.Scheme)})
		}
	}
	mu.Unlock()
	if len(jobs) == 0 {
		return
	}
	workers := maxScreenshotWorkers
	if workers > len(jobs) {
		workers = len(jobs)
	}
	ch := make(chan job, len(jobs))
	for _, j := range jobs {
		ch <- j
	}
	close(ch)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				if ctx.Err() != nil {
					return
				}
				if gov != nil {
					if err := gov.Wait(ctx, j.ip); err != nil {
						return
					}
				}
				if st != nil {
					st.httpRequests.Add(1)
				}
				shot, err := e.cfg.Screenshots.Capture(ctx, j.url)
				if err != nil || shot == nil {
					if debugHTTP {
						logScreenshotErr(j.url, err)
					}
					continue
				}
				mu.Lock()
				svcMap[j.ip][j.idx].Screenshot = shot
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

func logScreenshotErr(url string, err error) {
	log.Printf("[DEBUG] screenshot %s: %v", url, err)
}
