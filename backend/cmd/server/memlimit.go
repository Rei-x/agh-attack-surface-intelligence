package main

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// containerMemoryShare is the part of a container memory limit given to the Go heap as a soft
// limit; the rest covers goroutine stacks, the runtime, nmap and Chrome child processes.
const containerMemoryShare = 0.8

// goMemoryLimit is the soft limit set from the container limit at startup (0 = none).
var goMemoryLimit int64

// cgroupMemoryLimitFiles are the cgroup v2 and v1 memory limit files (Linux containers).
var cgroupMemoryLimitFiles = []string{
	"/sys/fs/cgroup/memory.max",
	"/sys/fs/cgroup/memory/memory.limit_in_bytes",
}

// applyContainerMemoryLimit sets a Go soft memory limit below the container's memory limit
// unless GOMEMLIMIT is set (the runtime applies that one itself; GOMEMLIMIT=off disables
// it). Without a soft limit the garbage collector lets the heap grow to twice the live data
// before collecting, so an ingest spike can cross a container limit that the live data is
// far below. It returns the limit it set (0 when none).
func applyContainerMemoryLimit() int64 {
	if strings.TrimSpace(os.Getenv("GOMEMLIMIT")) != "" {
		return 0
	}
	limit := readCgroupMemoryLimit(cgroupMemoryLimitFiles)
	if limit <= 0 {
		return 0
	}
	soft := int64(float64(limit) * containerMemoryShare)
	debug.SetMemoryLimit(soft)
	return soft
}

// readCgroupMemoryLimit returns the first finite memory limit found in files, 0 if none
// ("max", missing files, or the near-2^63 value cgroup v1 reports for "unlimited").
func readCgroupMemoryLimit(files []string) int64 {
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		v := strings.TrimSpace(string(raw))
		if v == "" || v == "max" {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 || n >= 1<<60 {
			continue
		}
		return n
	}
	return 0
}
