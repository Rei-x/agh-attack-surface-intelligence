//go:build !windows

package screenshot

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func launchChrome(path string) (*chromeBrowser, error) {
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
	cmd := exec.Command(path, chromeArgs(dataDir)...)
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
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
		return nil, fmt.Errorf("browser did not start (%s): %w", path, err)
	}
	return b, nil
}
