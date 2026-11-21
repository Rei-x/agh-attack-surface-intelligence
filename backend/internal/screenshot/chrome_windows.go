//go:build windows

package screenshot

import "errors"

// The DevTools pipe needs inherited fds 3 and 4, which os/exec cannot pass on Windows.
func launchChrome(string) (*chromeBrowser, error) {
	return nil, errors.New("screenshots are not supported on Windows hosts yet")
}
