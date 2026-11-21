package localdata

import (
	"os"
	"strings"
	"testing"
)

func TestReadOnlyDataDirGivesClearError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Acquire(LockInfo{Command: "serve"})
	if err == nil || !strings.Contains(err.Error(), "not writable") || !strings.Contains(err.Error(), "--data-dir") {
		t.Fatalf("want a clear 'not writable' error, got %v", err)
	}
}
