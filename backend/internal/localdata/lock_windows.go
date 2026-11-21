//go:build windows

package localdata

import (
	"os"

	"golang.org/x/sys/windows"
)

func tryLock(f *os.File) error {
	// Lock a byte far beyond the JSON content so other processes can still read holder info.
	ol := &windows.Overlapped{OffsetHigh: 1}
	return windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
}

func unlock(f *os.File) error {
	ol := &windows.Overlapped{OffsetHigh: 1}
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}
