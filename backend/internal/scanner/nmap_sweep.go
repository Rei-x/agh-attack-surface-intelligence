package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync/atomic"
)

// SweepResult is the outcome of Stage 1 in sweep mode.
type SweepResult struct {
	// Alive lists hosts that answered anything (open/closed port or ICMP echo), sorted.
	Alive []string
	// OpenPorts maps a live host to its open ports. nil means "unknown" (ping-mode or
	// pure-Go fallback discovery): Stage 2 must then scan every profile port.
	OpenPorts map[string][]int
	// Commands are the exact command lines executed (or a fallback description).
	Commands []string
}

// privilege states for NmapRunner.priv.
const (
	privUnknown int32 = iota
	privYes
	privNo
)

// Privileged reports whether raw-socket scans (-sS, ICMP) are used. It starts from the
// effective UID (or NMAP_PRIVILEGED / NMAP_UNPRIVILEGED) and drops to false for the rest of
// the runner's life the first time nmap refuses a raw scan (root without CAP_NET_RAW).
func (r *NmapRunner) Privileged() bool {
	switch atomic.LoadInt32(&r.priv) {
	case privYes:
		return true
	case privNo:
		return false
	}
	p := os.Geteuid() == 0
	if _, ok := os.LookupEnv("NMAP_PRIVILEGED"); ok {
		p = true
	}
	if _, ok := os.LookupEnv("NMAP_UNPRIVILEGED"); ok {
		p = false
	}
	v := privNo
	if p {
		v = privYes
	}
	atomic.CompareAndSwapInt32(&r.priv, privUnknown, v)
	return atomic.LoadInt32(&r.priv) == privYes
}

func isRawSocketDenied(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "requires root privileges") || strings.Contains(s, "operation not permitted") ||
		strings.Contains(s, "dnet: failed to open device") || strings.Contains(s, "couldn't open a raw socket")
}

// SweepDetailed runs Stage 1 for ips. In sweep mode it runs the ICMP echo pass (privileged
// only) and the -Pn port sweep of ports, both at ratePPS; the two run back to back, so the
// process never exceeds its rate share. In ping mode (or without nmap) it falls back to
// DiscoverHostsDetailed and reports OpenPorts=nil.
func (r *NmapRunner) SweepDetailed(ctx context.Context, ips []string, ports []int, ratePPS int, gov *Governor) (SweepResult, error) {
	if len(ips) == 0 {
		return SweepResult{}, nil
	}
	opts := r.options()
	if !r.UseNmap || r.NmapBinary == "" || opts.Discovery == DiscoveryPing || len(ports) == 0 {
		alive, cmd, err := r.DiscoverHostsDetailed(ctx, ips, ports, ratePPS, gov)
		res := SweepResult{Alive: alive}
		if cmd != "" {
			res.Commands = []string{cmd}
		}
		return res, err
	}

	var res SweepResult
	aliveSet := make(map[string]bool)
	open := make(map[string][]int)

	if r.Privileged() {
		args := opts.BuildICMPArgs(ips, ratePPS)
		out, cmdLine, stderr, err := r.runNmap(ctx, args)
		res.Commands = append(res.Commands, cmdLine)
		switch {
		case err == nil:
			hosts, perr := ParseNmapXML(out)
			if perr != nil {
				return res, perr
			}
			for _, h := range hosts {
				if h.IsAlive && h.IP != "" {
					aliveSet[h.IP] = true
				}
			}
		case ctx.Err() != nil:
			return res, ctx.Err()
		case isRawSocketDenied(stderr):
			atomic.StoreInt32(&r.priv, privNo)
		default:
			return res, fmt.Errorf("nmap ICMP pass failed: %w (%s)", err, truncateStr(strings.TrimSpace(stderr), 200))
		}
	}

	sweep := func(priv bool) ([]byte, string, string, error) {
		return r.runNmap(ctx, opts.BuildSweepArgs(ips, ports, ratePPS, priv))
	}
	priv := r.Privileged() && !anyLocalAddress(ips)
	out, cmdLine, stderr, err := sweep(priv)
	if err != nil && ctx.Err() == nil && priv && isRawSocketDenied(stderr) {
		atomic.StoreInt32(&r.priv, privNo)
		res.Commands = append(res.Commands, cmdLine)
		out, cmdLine, _, err = sweep(false)
	}
	res.Commands = append(res.Commands, cmdLine)
	if err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		// nmap unusable here: fall back to the pure-Go path for this chunk.
		alive, cmd, ferr := r.DiscoverHostsDetailed(ctx, ips, ports, ratePPS, gov)
		res.Commands = append(res.Commands, cmd)
		res.Alive, res.OpenPorts = alive, nil
		if ferr != nil {
			return res, ferr
		}
		return res, nil
	}
	if err := parseSweepXML(out, aliveSet, open); err != nil {
		return res, err
	}
	for ip := range aliveSet {
		res.Alive = append(res.Alive, ip)
	}
	sort.Strings(res.Alive)
	res.OpenPorts = open
	return res, nil
}

func (r *NmapRunner) runNmap(ctx context.Context, args []string) ([]byte, string, string, error) {
	cmdLine := FormatCommand(r.NmapBinary, args)
	if err := ValidateSafeNmapArgs(args); err != nil {
		return nil, cmdLine, "", err
	}
	cmd := exec.CommandContext(ctx, r.NmapBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), cmdLine, stderr.String(), err
}

// guessedServices returns "ip:port" for open ports whose service name nmap only guessed from
// the port number (method="table"): no -sV probe, including its HTTP GET, got a matching
// answer. HTTP fingerprinting treats those as speculative.
func guessedServices(xmlStr string) map[string]bool {
	out := map[string]bool{}
	if strings.TrimSpace(xmlStr) == "" {
		return out
	}
	var doc nmapRunXML
	if err := xml.Unmarshal([]byte(xmlStr), &doc); err != nil {
		return out
	}
	for _, h := range doc.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				ip = a.Addr
				break
			}
		}
		for _, p := range h.Ports.Ports {
			if p.State.State == "open" && (p.Service == nil || p.Service.Method == "table") {
				out[fmt.Sprintf("%s:%d", ip, p.PortID)] = true
			}
		}
	}
	return out
}

// parseSweepXML marks a host alive when any port answered (open, closed, unfiltered) and
// records open ports. With -Pn nmap reports every target as "up", so <status> is ignored.
func parseSweepXML(xmlBytes []byte, alive map[string]bool, open map[string][]int) error {
	if len(bytes.TrimSpace(xmlBytes)) == 0 {
		return nil
	}
	var doc nmapRunXML
	if err := xml.Unmarshal(xmlBytes, &doc); err != nil {
		return fmt.Errorf("parse nmap sweep xml: %w", err)
	}
	for _, h := range doc.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				ip = a.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		for _, p := range h.Ports.Ports {
			switch p.State.State {
			case "open":
				alive[ip] = true
				open[ip] = append(open[ip], p.PortID)
			case "closed", "unfiltered":
				alive[ip] = true
			}
		}
	}
	for ip := range open {
		sort.Ints(open[ip])
	}
	return nil
}
