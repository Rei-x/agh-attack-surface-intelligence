package screenshot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// EnvChromePath overrides browser discovery (path to chrome, chromium or chrome-headless-shell).
const EnvChromePath = "DZIECIOL_CHROME_PATH"

// FindChrome returns the path of a usable Chromium-family browser, or "" when none is found.
// DZIECIOL_CHROME_PATH wins; then common binary names on PATH; then well-known install paths.
func FindChrome() string {
	if p := strings.TrimSpace(os.Getenv(EnvChromePath)); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
		if lp, err := exec.LookPath(p); err == nil {
			return lp
		}
		return ""
	}
	for _, name := range []string{
		"chrome-headless-shell", "headless_shell", "chromium", "chromium-browser",
		"google-chrome-stable", "google-chrome", "chrome", "microsoft-edge",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		}
	case "linux":
		candidates = []string{
			"/usr/lib/chromium/chromium", "/usr/lib/chromium-browser/chromium-browser",
			"/snap/bin/chromium", "/opt/google/chrome/chrome", "/usr/bin/chromium",
		}
	case "windows":
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LocalAppData")} {
			if base != "" {
				candidates = append(candidates,
					filepath.Join(base, `Google\Chrome\Application\chrome.exe`),
					filepath.Join(base, `Microsoft\Edge\Application\msedge.exe`))
			}
		}
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// chromeArgs are the flags of a disposable, quiet, headless browser.
func chromeArgs(userDataDir string) []string {
	args := []string{
		"--headless",
		"--remote-debugging-pipe",
		"--user-data-dir=" + userDataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-gpu",
		"--disable-extensions",
		"--disable-sync",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-default-apps",
		"--disable-breakpad",
		"--disable-crash-reporter",
		"--disable-features=Translate,MediaRouter,OptimizationHints,AutofillServerCommunication",
		"--disable-notifications",
		"--metrics-recording-only",
		"--mute-audio",
		"--hide-scrollbars",
		"--ignore-certificate-errors",
		"--password-store=basic",
		"--use-mock-keychain",
		fmt.Sprintf("--window-size=%d,%d", ViewportWidth, ViewportHeight),
	}
	if runtime.GOOS == "linux" {
		args = append(args, "--disable-dev-shm-usage")
		// Chromium refuses to start its sandbox as root (typical for a systemd agent).
		if os.Geteuid() == 0 || os.Getenv("DZIECIOL_CHROME_NO_SANDBOX") != "" {
			args = append(args, "--no-sandbox")
		}
	}
	return append(args, "about:blank")
}

// chromeBrowser is one running headless browser driven over the DevTools pipe.
type chromeBrowser struct {
	conn    *cdpConn
	proc    *exec.Cmd
	dataDir string
	stop    func() // kills the process tree
	once    sync.Once
	exited  chan struct{}
}

// LaunchChrome starts a headless browser at path.
func LaunchChrome(path string) (Browser, error) {
	b, err := launchChrome(path)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (b *chromeBrowser) Alive() bool {
	select {
	case <-b.exited:
		return false
	default:
		return b.conn.alive()
	}
}

func (b *chromeBrowser) Close() error {
	b.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = b.conn.call(ctx, "", "Browser.close", nil, nil)
		cancel()
		select {
		case <-b.exited:
		case <-time.After(3 * time.Second):
		}
		b.stop()
		_ = os.RemoveAll(b.dataDir)
	})
	return nil
}

// Screenshot loads url in a fresh incognito context with a fixed viewport and returns the
// raw JPEG of the rendered page and its title. TLS errors are ignored, dialogs dismissed and
// downloads denied. The page gets until ctx's deadline minus a short reserve for capture.
func (b *chromeBrowser) Screenshot(ctx context.Context, url string) ([]byte, string, error) {
	if !b.Alive() {
		return nil, "", errors.New("browser is not running")
	}
	c := b.conn
	var bc struct {
		BrowserContextID string `json:"browserContextId"`
	}
	if err := c.call(ctx, "", "Target.createBrowserContext", map[string]any{"disposeOnDetach": true}, &bc); err != nil {
		return nil, "", err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = c.call(cctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": bc.BrowserContextID}, nil)
		cancel()
	}()
	_ = c.call(ctx, "", "Browser.setDownloadBehavior", map[string]any{"behavior": "deny", "browserContextId": bc.BrowserContextID}, nil)

	var tgt struct {
		TargetID string `json:"targetId"`
	}
	if err := c.call(ctx, "", "Target.createTarget", map[string]any{
		"url": "about:blank", "browserContextId": bc.BrowserContextID,
		"width": ViewportWidth, "height": ViewportHeight,
	}, &tgt); err != nil {
		return nil, "", err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = c.call(cctx, "", "Target.closeTarget", map[string]any{"targetId": tgt.TargetID}, nil)
		cancel()
	}()
	var att struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": tgt.TargetID, "flatten": true}, &att); err != nil {
		return nil, "", err
	}
	s := att.SessionID
	loaded := make(chan struct{})
	var loadOnce sync.Once
	c.subscribe(s, func(method string, _ json.RawMessage) {
		switch method {
		case "Page.loadEventFired":
			loadOnce.Do(func() { close(loaded) })
		case "Page.javascriptDialogOpening":
			go func() {
				dctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_ = c.call(dctx, s, "Page.handleJavaScriptDialog", map[string]any{"accept": false}, nil)
				cancel()
			}()
		}
	})
	defer c.unsubscribe(s)

	for _, step := range []struct {
		method string
		params any
	}{
		{"Page.enable", nil},
		{"Emulation.setDeviceMetricsOverride", map[string]any{"width": ViewportWidth, "height": ViewportHeight, "deviceScaleFactor": 1, "mobile": false}},
		{"Security.setIgnoreCertificateErrors", map[string]any{"ignore": true}},
	} {
		if err := c.call(ctx, s, step.method, step.params, nil); err != nil && step.method == "Page.enable" {
			return nil, "", err
		}
	}

	// Leave time to capture even when the page never finishes loading.
	navCtx := ctx
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		navCtx, cancel = context.WithDeadline(ctx, dl.Add(-1500*time.Millisecond))
		defer cancel()
	}
	var nav struct {
		ErrorText string `json:"errorText"`
	}
	if err := c.call(navCtx, s, "Page.navigate", map[string]any{"url": url}, &nav); err != nil {
		return nil, "", err
	}
	if nav.ErrorText != "" {
		return nil, "", fmt.Errorf("navigate: %s", nav.ErrorText)
	}
	select {
	case <-loaded:
		// Client-rendered panels (React/Angular admin UIs) paint after onload.
		settle := time.NewTimer(800 * time.Millisecond)
		select {
		case <-settle.C:
		case <-navCtx.Done():
		}
		settle.Stop()
	case <-navCtx.Done():
	}
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}

	var title string
	var ev struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
	}
	if err := c.call(ctx, s, "Runtime.evaluate", map[string]any{"expression": "document.title", "returnByValue": true}, &ev); err == nil {
		if t, ok := ev.Result.Value.(string); ok {
			title = strings.TrimSpace(t)
		}
	}
	var shot struct {
		Data string `json:"data"`
	}
	if err := c.call(ctx, s, "Page.captureScreenshot", map[string]any{"format": "jpeg", "quality": 85}, &shot); err != nil {
		return nil, "", err
	}
	raw, err := base64.StdEncoding.DecodeString(shot.Data)
	if err != nil {
		return nil, "", fmt.Errorf("decode screenshot: %w", err)
	}
	return raw, title, nil
}
