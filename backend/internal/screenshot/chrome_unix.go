//go:build !windows

package screenshot

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// launchChrome starts the browser, without Chromium's sandbox when it cannot work here
// (sandboxUnavailable). If a sandboxed start fails anyway (e.g. user namespaces disabled by
// the kernel or AppArmor), it retries once with --no-sandbox and says so in the log.
func launchChrome(path string) (*chromeBrowser, error) {
	noSandbox, why := sandboxUnavailable()
	if noSandbox {
		noSandboxNote.Do(func() { log.Printf("[INFO] screenshots: starting Chromium with --no-sandbox (%s)", why) })
	}
	b, err := startChrome(path, noSandbox)
	if err == nil || noSandbox {
		return b, err
	}
	b2, err2 := startChrome(path, true)
	if err2 != nil {
		return nil, fmt.Errorf("%v; retry with --no-sandbox: %v", err, err2)
	}
	log.Printf("[WARN] screenshots: Chromium sandbox is not available on this host (%v); using --no-sandbox", firstLine(err.Error()))
	return b2, nil
}

var noSandboxNote sync.Once

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// tailBuffer keeps the last max bytes written to it (Chromium's stderr, for error messages).
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

// fatalLines returns the stderr lines that explain a failed start (FATAL/ERROR/sandbox).
func (t *tailBuffer) fatalLines() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var keep []string
	for _, l := range bytes.Split(t.buf, []byte("\n")) {
		ls := string(bytes.TrimSpace(l))
		if strings.Contains(ls, "FATAL") || strings.Contains(strings.ToLower(ls), "sandbox") {
			keep = append(keep, ls)
		}
	}
	if len(keep) > 3 {
		keep = keep[len(keep)-3:]
	}
	return strings.Join(keep, " | ")
}

func startChrome(path string, noSandbox bool) (*chromeBrowser, error) {
	dataDir, err := os.MkdirTemp("", "dzieciol-chrome-")
	if err != nil {
		return nil, err
	}
	// fd 3: browser reads commands; fd 4: browser writes replies.
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		cmdR.Close()
		cmdW.Close()
		_ = os.RemoveAll(dataDir)
		return nil, err
	}
	cmd := exec.Command(path, chromeArgs(dataDir, noSandbox)...)
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	stderr := &tailBuffer{max: 8192}
	cmd.Stdout = stderr
	cmd.Stderr = stderr
	// A systemd DynamicUser service has no writable home: keep Chromium's profile, NSS
	// database and caches inside the throwaway data directory.
	cmd.Env = append(os.Environ(), "HOME="+dataDir, "XDG_CONFIG_HOME="+dataDir, "XDG_CACHE_HOME="+dataDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		cmdR.Close()
		cmdW.Close()
		outR.Close()
		outW.Close()
		_ = os.RemoveAll(dataDir)
		return nil, fmt.Errorf("start %s: %w", path, err)
	}
	cmdR.Close()
	outW.Close()

	b := &chromeBrowser{
		conn:    newCDPConn(outR, cmdW),
		proc:    cmd,
		dataDir: dataDir,
		exited:  make(chan struct{}),
	}
	b.stop = func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		cmdW.Close()
		outR.Close()
	}
	go func() {
		_ = cmd.Wait()
		close(b.exited)
	}()

	// The browser answers once it is ready; a binary that is not Chromium never does.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := b.conn.call(ctx, "", "Browser.getVersion", nil, nil); err != nil {
		b.stop()
		<-b.exited
		_ = os.RemoveAll(dataDir)
		if detail := stderr.fatalLines(); detail != "" {
			return nil, fmt.Errorf("browser did not start (%s): %w: %s", path, err, detail)
		}
		return nil, fmt.Errorf("browser did not start (%s): %w", path, err)
	}
	return b, nil
}
