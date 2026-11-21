package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// scannerInfo describes the scan backend that will be used on this machine.
type scannerInfo struct {
	NmapPath    string
	NmapVersion string
	Privileged  bool
	ForcedGo    bool // --no-nmap
}

func (s scannerInfo) HasNmap() bool { return s.NmapPath != "" }

func (s scannerInfo) Engine() string {
	if s.HasNmap() {
		return "nmap"
	}
	return "pure-Go TCP connect"
}

func detectScanner() scannerInfo {
	info := scannerInfo{Privileged: isPrivileged()}
	path, err := exec.LookPath("nmap")
	if err != nil {
		return info
	}
	info.NmapPath = path
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, path, "--version").Output(); err == nil {
		first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
		info.NmapVersion = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(first, "Nmap version"), "( https://nmap.org )"))
	}
	return info
}

func isPrivileged() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return os.Geteuid() == 0
}

// printPreflight explains the scanner backend, how to install nmap and privilege caveats.
func printPreflight(w io.Writer, s scannerInfo) {
	if s.HasNmap() {
		v := s.NmapVersion
		if v == "" {
			v = "unknown version"
		}
		fmt.Fprintf(w, "scanner: nmap %s (%s)\n", v, s.NmapPath)
		if !s.Privileged {
			switch runtime.GOOS {
			case "darwin":
				fmt.Fprintln(w, "         running unprivileged: nmap uses TCP connect (-sT) and TCP-ping discovery; ICMP echo is unavailable on macOS without root (not required).")
			case "windows":
				fmt.Fprintln(w, "         TCP connect (-sT) scanning; Npcap is only needed for raw-packet modes (not required).")
			default:
				fmt.Fprintln(w, "         running unprivileged: TCP connect (-sT) + TCP-ping discovery, no raw ICMP/SYN (not required).")
			}
		}
		return
	}
	if s.ForcedGo {
		fmt.Fprintln(w, "scanner: built-in pure-Go TCP connect scanner (--no-nmap)")
		return
	}
	fmt.Fprintln(w, "scanner: nmap not found - using the built-in pure-Go TCP connect scanner + banner grabbing (works, but no nmap -sV version detection).")
	switch runtime.GOOS {
	case "darwin":
		fmt.Fprintln(w, "         install nmap for richer fingerprints: brew install nmap")
	case "linux":
		fmt.Fprintln(w, "         install nmap for richer fingerprints: sudo apt install nmap   (or: sudo dnf install nmap)")
	case "windows":
		fmt.Fprintln(w, "         install nmap for richer fingerprints: winget install Insecure.Nmap   (or https://nmap.org/download)")
	}
}
