package screenshot

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Browser renders one page and returns the raw image (PNG or JPEG) and its title.
// The real implementation is a headless Chromium (LaunchChrome); tests use a fake.
type Browser interface {
	Screenshot(ctx context.Context, url string) (raw []byte, title string, err error)
	Alive() bool
	Close() error
}

// Launcher starts a Browser.
type Launcher func() (Browser, error)

// Options tune a Capturer.
type Options struct {
	Timeout     time.Duration // per page, default 8s
	Concurrency int           // pages rendered at once, default 3
	IdleClose   time.Duration // browser exits after this long without work, default 90s
	Now         func() time.Time
}

// Capturer renders landing pages with one lazily started, shared browser. The browser is
// launched on first use, restarted if it dies, and closed when idle so it costs nothing
// between scans. A failed launch is not retried for a minute.
type Capturer struct {
	launch Launcher
	opts   Options
	sem    chan struct{}

	mu        sync.Mutex
	browser   Browser
	busy      int
	idleTimer *time.Timer
	launchErr error
	failedAt  time.Time
	closed    bool
}

// NewCapturer builds a Capturer around a browser launcher.
func NewCapturer(launch Launcher, opts Options) *Capturer {
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 3
	}
	if opts.IdleClose <= 0 {
		opts.IdleClose = 90 * time.Second
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Capturer{launch: launch, opts: opts, sem: make(chan struct{}, opts.Concurrency)}
}

// Timeout is the per-page budget.
func (c *Capturer) Timeout() time.Duration { return c.opts.Timeout }

// LastError is the most recent browser launch failure ("" when the browser starts fine).
func (c *Capturer) LastError() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.launchErr == nil {
		return ""
	}
	return c.launchErr.Error()
}

func (c *Capturer) acquire() (Browser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("capturer closed")
	}
	if c.idleTimer != nil {
		c.idleTimer.Stop()
		c.idleTimer = nil
	}
	if c.browser != nil && !c.browser.Alive() {
		_ = c.browser.Close()
		c.browser = nil
	}
	if c.browser == nil {
		if c.launchErr != nil && time.Since(c.failedAt) < time.Minute {
			return nil, c.launchErr
		}
		b, err := c.launch()
		if err != nil {
			// One clear warning per distinct failure: a browser that cannot start must not
			// silently produce a scan without screenshots.
			if c.launchErr == nil || c.launchErr.Error() != err.Error() {
				log.Printf("[WARN] screenshots: cannot start the browser, pages will not be captured: %v", err)
			}
			c.launchErr, c.failedAt = err, time.Now()
			return nil, err
		}
		c.browser, c.launchErr = b, nil
	}
	c.busy++
	return c.browser, nil
}

func (c *Capturer) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.busy--
	if c.busy == 0 && c.browser != nil && !c.closed {
		b := c.browser
		c.idleTimer = time.AfterFunc(c.opts.IdleClose, func() {
			c.mu.Lock()
			if c.busy == 0 && c.browser == b {
				c.browser = nil
				c.mu.Unlock()
				_ = b.Close()
				return
			}
			c.mu.Unlock()
		})
	}
}

// Capture renders url and returns the processed screenshot.
func (c *Capturer) Capture(ctx context.Context, url string) (*domain.Screenshot, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.sem }()

	b, err := c.acquire()
	if err != nil {
		return nil, err
	}
	defer c.release()

	pctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	raw, title, err := b.Screenshot(pctx, url)
	if err != nil {
		return nil, err
	}
	p, err := Process(raw)
	if err != nil {
		return nil, err
	}
	if len(title) > 300 {
		title = title[:300]
	}
	return &domain.Screenshot{
		Image:      p.Full,
		Thumb:      p.Thumb,
		Width:      p.Width,
		Height:     p.Height,
		PHash:      FormatHash(p.PHash),
		URL:        url,
		Title:      title,
		CapturedAt: c.opts.Now(),
	}, nil
}

// Close stops the browser for good.
func (c *Capturer) Close() {
	c.mu.Lock()
	c.closed = true
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	b := c.browser
	c.browser = nil
	c.mu.Unlock()
	if b != nil {
		_ = b.Close()
	}
}

// ---- process-wide capturer -------------------------------------------------------------

// EnvScreenshots set to false/0/off disables screenshots on this host.
const EnvScreenshots = "DZIECIOL_SCREENSHOTS"

var (
	sharedOnce sync.Once
	shared     *Capturer
	sharedPath string
)

// Disabled reports whether DZIECIOL_SCREENSHOTS turns screenshots off.
func Disabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvScreenshots))) {
	case "0", "false", "off", "no":
		return true
	}
	return false
}

// Shared returns the process-wide capturer, or nil when screenshots are disabled or no
// Chromium is installed. Inside `go test` it is always nil so unit tests never spawn a browser.
func Shared() *Capturer {
	sharedOnce.Do(func() {
		if testing.Testing() || Disabled() {
			return
		}
		sharedPath = FindChrome()
		if sharedPath == "" {
			return
		}
		opts := Options{}
		if v, err := strconv.Atoi(os.Getenv("DZIECIOL_SCREENSHOT_CONCURRENCY")); err == nil && v > 0 && v <= 16 {
			opts.Concurrency = v
		}
		if v, err := time.ParseDuration(os.Getenv("DZIECIOL_SCREENSHOT_TIMEOUT")); err == nil && v >= time.Second && v <= time.Minute {
			opts.Timeout = v
		}
		path := sharedPath
		shared = NewCapturer(func() (Browser, error) { return LaunchChrome(path) }, opts)
	})
	return shared
}

// Shutdown stops the shared browser, if one was started. The browser runs in its own process
// group, so it would outlive the process otherwise.
func Shutdown() {
	sharedOnce.Do(func() {}) // no capturer may be created after this
	if shared != nil {
		shared.Close()
	}
}

// Availability describes screenshot support on this host for preflight output and health.
type Availability struct {
	Available bool   `json:"available"`
	Browser   string `json:"browser,omitempty"`
	Detail    string `json:"detail"`
}

// Status reports whether this host can capture screenshots. It never launches the browser;
// a failed launch seen earlier is included.
func Status() Availability {
	if Disabled() {
		return Availability{Detail: "screenshots disabled (" + EnvScreenshots + "=false)"}
	}
	path := FindChrome()
	if path == "" {
		if os.Getenv(EnvChromePath) != "" {
			return Availability{Detail: "screenshots unavailable (" + EnvChromePath + " does not point to a browser)"}
		}
		return Availability{Detail: "screenshots unavailable (no Chromium)"}
	}
	a := Availability{Available: true, Browser: path, Detail: "screenshots on (" + path + ")"}
	if c := Shared(); c != nil {
		if e := c.LastError(); e != "" {
			a.Available = false
			a.Detail = fmt.Sprintf("screenshots failing: %s", e)
		}
	}
	return a
}
