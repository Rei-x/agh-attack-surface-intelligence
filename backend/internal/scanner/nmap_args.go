package scanner

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// NmapOptions holds the tunable, safety-reviewed knobs for the two nmap invocations
// (Stage 1 host discovery and Stage 2 service/version detection).
//
// Everything here maps to a fixed allow-list of nmap flags; there is deliberately no
// "extra args" escape hatch, so no configuration can enable NSE scripts (--script/-sC),
// OS detection, aggressive mode (-A) or any intrusive probe.
type NmapOptions struct {
	// Discovery probes (Stage 1). Unprivileged nmap transparently degrades -PS/-PA
	// to connect() probes and skips ICMP, so these are safe to request without root.
	PingICMPEcho bool  // -PE
	PingSYNPorts []int // -PS<ports>
	PingACKPorts []int // -PA<ports>
	// AddProfilePortsToPing appends the profile's allowed ports to -PS so hosts that
	// only expose e.g. :8081 are still discovered when they drop ICMP.
	AddProfilePortsToPing bool
	DiscoveryMaxRetries   int           // --max-retries during -sn
	DiscoveryHostTimeout  time.Duration // --host-timeout during -sn

	// Service detection (Stage 2).
	ServiceMaxRetries  int           // --max-retries during -sT -sV
	ServiceHostTimeout time.Duration // --host-timeout during -sT -sV (one tarpit host can't stall a chunk)
	VersionIntensity   int           // --version-intensity 0..9

	// Timing is the -T template (0..5). <0 means "derive from the per-process rate".
	Timing int

	// Discovery selects the Stage 1 method:
	//   "sweep" (default): -Pn port sweep of every profile port (+ ICMP echo pass when
	//            privileged). One probe per (IP, port), no retransmissions; a host is alive if
	//            any port answers (SYN-ACK or RST) or it answers ICMP echo. The sweep also
	//            yields the open ports, so Stage 2 runs -sV only on hosts/ports known open.
	//   "ping":  the classic nmap -sn ping scan (PingICMPEcho/PingSYNPorts/PingACKPorts).
	// Measured on the 10.66.0.0/22 scale-lab slice: ping scan 50 probes/IP (it needs
	// --max-retries 1; with 0 it sends ~2 probes/IP and misses 15% of hosts), sweep 27.4
	// probes/IP with 100% host and open-port recall.
	Discovery string
	// SweepMaxRetries is --max-retries for the sweep (0: each (IP,port) probed once).
	SweepMaxRetries int
	// SweepMinRatePct sets --min-rate to this percentage of the process's --max-rate share.
	// nmap's --max-rate is a long-run average: after an idle stretch it "catches up" with
	// bursts (measured 610/s on a 375 pps share). Pacing with --min-rate close to --max-rate
	// keeps every second under the cap (measured 1227..1402/s on a 1500 share). 0 disables.
	SweepMinRatePct int
}

// Discovery modes.
const (
	DiscoverySweep = "sweep"
	DiscoveryPing  = "ping"
)

// Default discovery probe set: ICMP echo + TCP SYN to common ports + TCP ACK to 80/443.
// Catches hosts that drop ICMP (very common in university networks behind firewalls).
var (
	defaultPingSYNPorts = []int{21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443}
	defaultPingACKPorts = []int{80, 443}
)

// maxPingSYNPorts bounds -PS in ping mode. It was 24, which silently dropped the highest profile
// ports (8443, 9090, 9100, 9200 on the 28-port scale lab) from discovery.
const maxPingSYNPorts = 64

// DefaultNmapOptions returns conservative defaults for large, partially hostile networks.
func DefaultNmapOptions() NmapOptions {
	return NmapOptions{
		PingICMPEcho:          true,
		PingSYNPorts:          append([]int(nil), defaultPingSYNPorts...),
		PingACKPorts:          append([]int(nil), defaultPingACKPorts...),
		AddProfilePortsToPing: true,
		DiscoveryMaxRetries:   1,
		DiscoveryHostTimeout:  20 * time.Second,
		ServiceMaxRetries:     2,
		ServiceHostTimeout:    3 * time.Minute,
		// -sV time is dominated by waiting for silent services (NULL probe 6 s, then probe
		// chains), not by packets, and an nmap host group finishes with its slowest service.
		// Intensity 2 (= --version-light) halved a 38-host group (94.8 s -> 49.7 s) with the
		// same 64 versions identified.
		VersionIntensity: 2,
		Timing:           -1,
		Discovery:        DiscoverySweep,
		SweepMaxRetries:  0,
		SweepMinRatePct:  90,
	}
}

// NmapOptionsFromEnv applies ASI_NMAP_* environment overrides on top of DefaultNmapOptions.
// Invalid values are ignored (defaults kept) so a typo can never widen the scan.
//
//	ASI_NMAP_PING_ICMP=true|false
//	ASI_NMAP_PING_SYN_PORTS=21,22,80,443     (empty string disables -PS)
//	ASI_NMAP_PING_ACK_PORTS=80,443           (empty string disables -PA)
//	ASI_NMAP_DISCOVERY_MAX_RETRIES=1
//	ASI_NMAP_DISCOVERY_HOST_TIMEOUT=20s
//	ASI_NMAP_MAX_RETRIES=2
//	ASI_NMAP_HOST_TIMEOUT=3m
//	ASI_NMAP_VERSION_INTENSITY=5
//	ASI_NMAP_TIMING=3                         (unset/auto = derived from rate)
func NmapOptionsFromEnv() NmapOptions {
	o := DefaultNmapOptions()
	if v, ok := os.LookupEnv("ASI_NMAP_PING_ICMP"); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			o.PingICMPEcho = b
		}
	}
	if v, ok := os.LookupEnv("ASI_NMAP_PING_SYN_PORTS"); ok {
		if strings.TrimSpace(v) == "" {
			o.PingSYNPorts = nil
		} else if ports, err := ParsePorts(v); err == nil {
			o.PingSYNPorts = ports
		}
	}
	if v, ok := os.LookupEnv("ASI_NMAP_PING_ACK_PORTS"); ok {
		if strings.TrimSpace(v) == "" {
			o.PingACKPorts = nil
		} else if ports, err := ParsePorts(v); err == nil {
			o.PingACKPorts = ports
		}
	}
	envInt := func(key string, lo, hi int, dst *int) {
		if v, ok := os.LookupEnv(key); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= lo && n <= hi {
				*dst = n
			}
		}
	}
	envDur := func(key string, dst *time.Duration) {
		if v, ok := os.LookupEnv(key); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
				*dst = d
			}
		}
	}
	envInt("ASI_NMAP_DISCOVERY_MAX_RETRIES", 0, 10, &o.DiscoveryMaxRetries)
	envDur("ASI_NMAP_DISCOVERY_HOST_TIMEOUT", &o.DiscoveryHostTimeout)
	envInt("ASI_NMAP_MAX_RETRIES", 0, 10, &o.ServiceMaxRetries)
	envDur("ASI_NMAP_HOST_TIMEOUT", &o.ServiceHostTimeout)
	envInt("ASI_NMAP_VERSION_INTENSITY", 0, 9, &o.VersionIntensity)
	envInt("ASI_NMAP_TIMING", 0, 5, &o.Timing)
	if v, ok := os.LookupEnv("ASI_NMAP_DISCOVERY"); ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case DiscoverySweep:
			o.Discovery = DiscoverySweep
		case DiscoveryPing:
			o.Discovery = DiscoveryPing
		}
	}
	envInt("ASI_NMAP_SWEEP_MAX_RETRIES", 0, 3, &o.SweepMaxRetries)
	envInt("ASI_NMAP_SWEEP_MIN_RATE_PCT", 0, 100, &o.SweepMinRatePct)
	return o
}

// BuildSweepArgs returns the nmap argv for the Stage 1 port sweep: every target, every
// profile port, one probe each (-Pn: no ping phase; liveness is decided from the answers).
// -sS needs raw sockets; unprivileged runs use -sT (connect), which nmap rate-limits the same way.
func (o NmapOptions) BuildSweepArgs(targets []string, ports []int, ratePPS int, privileged bool) []string {
	if ratePPS <= 0 {
		ratePPS = 300
	}
	scan := "-sT"
	if privileged {
		scan = "-sS"
	}
	args := []string{scan, "-Pn", "-n", "-p", joinPorts(dedupeSortPorts(ports))}
	retries := o.SweepMaxRetries
	if retries < 0 {
		retries = 0
	}
	args = append(args, "--max-retries", strconv.Itoa(retries), "-T"+strconv.Itoa(o.timingFor(ratePPS)), "--max-rate", strconv.Itoa(ratePPS))
	args = o.appendPacing(args, ratePPS)
	args = append(args, "-oX", "-")
	return append(args, CompactIPv4Targets(targets)...)
}

// appendPacing adds --min-rate (SweepMinRatePct of the share) so nmap sends evenly instead of
// catching up on its long-run --max-rate average with bursts.
func (o NmapOptions) appendPacing(args []string, ratePPS int) []string {
	if o.SweepMinRatePct > 0 {
		if minRate := ratePPS * o.SweepMinRatePct / 100; minRate >= 1 {
			args = append(args, "--min-rate", strconv.Itoa(minRate))
		}
	}
	return args
}

// BuildICMPArgs returns the nmap argv for the ICMP echo liveness pass that complements the
// sweep (hosts whose every port is filtered but that answer ping). Privileged only.
func (o NmapOptions) BuildICMPArgs(targets []string, ratePPS int) []string {
	if ratePPS <= 0 {
		ratePPS = 300
	}
	args := []string{"-sn", "-n", "-PE", "--max-retries", "1"}
	if o.DiscoveryHostTimeout > 0 {
		args = append(args, "--host-timeout", nmapDuration(o.DiscoveryHostTimeout))
	}
	args = append(args, "-T"+strconv.Itoa(o.timingFor(ratePPS)), "--max-rate", strconv.Itoa(ratePPS))
	// Paced like the sweep: unpaced, 4 ICMP passes starting together peaked at 1436/s
	// against a 1264 pps summed share.
	args = o.appendPacing(args, ratePPS)
	args = append(args, "-oX", "-")
	return append(args, CompactIPv4Targets(targets)...)
}

// timingFor picks the -T template. Explicit configuration wins; otherwise we pick
// T3 (normal) for slow per-process budgets and T4 (aggressive timeouts, still bounded by
// --max-rate) when the process has a healthy rate budget. T0-T2 are avoided by default
// because their serial scan-delay makes 10k+ IP scopes impossible within a night window,
// and --max-rate is already the hard politeness cap.
func (o NmapOptions) timingFor(ratePPS int) int {
	if o.Timing >= 0 && o.Timing <= 5 {
		return o.Timing
	}
	if ratePPS >= 200 {
		return 4
	}
	return 3
}

// BuildDiscoveryArgs returns the exact nmap argv (without binary) for Stage 1 host discovery.
func (o NmapOptions) BuildDiscoveryArgs(targets []string, profilePorts []int, ratePPS int) []string {
	if ratePPS <= 0 {
		ratePPS = 300
	}
	args := []string{"-sn", "-n"}
	if o.PingICMPEcho {
		args = append(args, "-PE")
	}
	syn := append([]int(nil), o.PingSYNPorts...)
	if o.AddProfilePortsToPing {
		syn = append(syn, profilePorts...)
	}
	syn = dedupeSortPorts(syn)
	if len(syn) > maxPingSYNPorts {
		syn = syn[:maxPingSYNPorts]
	}
	if len(syn) > 0 {
		args = append(args, "-PS"+joinPorts(syn))
	}
	if ack := dedupeSortPorts(o.PingACKPorts); len(ack) > 0 {
		args = append(args, "-PA"+joinPorts(ack))
	}
	if o.DiscoveryMaxRetries >= 0 {
		args = append(args, "--max-retries", strconv.Itoa(o.DiscoveryMaxRetries))
	}
	if o.DiscoveryHostTimeout > 0 {
		args = append(args, "--host-timeout", nmapDuration(o.DiscoveryHostTimeout))
	}
	args = append(args,
		"-T"+strconv.Itoa(o.timingFor(ratePPS)),
		"--max-rate", strconv.Itoa(ratePPS),
		"-oX", "-",
	)
	return append(args, CompactIPv4Targets(targets)...)
}

// BuildServiceArgs returns the exact nmap argv (without binary) for Stage 2 service detection.
// -sT (connect scan) works unprivileged; -Pn because Stage 1 already proved liveness.
func (o NmapOptions) BuildServiceArgs(targets []string, ports []int, ratePPS int) []string {
	return o.BuildServiceArgsPriv(targets, ports, ratePPS, false)
}

// BuildServiceArgsPriv is BuildServiceArgs choosing -sS (raw SYN) when privileged.
func (o NmapOptions) BuildServiceArgsPriv(targets []string, ports []int, ratePPS int, privileged bool) []string {
	if ratePPS <= 0 {
		ratePPS = 200
	}
	intensity := o.VersionIntensity
	if intensity < 0 || intensity > 9 {
		intensity = 2
	}
	scan := "-sT"
	if privileged {
		scan = "-sS"
	}
	args := []string{
		scan, "-sV",
		"--version-intensity", strconv.Itoa(intensity),
		"-Pn", "-n",
		"-p", joinPorts(ports),
	}
	if o.ServiceMaxRetries >= 0 {
		args = append(args, "--max-retries", strconv.Itoa(o.ServiceMaxRetries))
	}
	if o.ServiceHostTimeout > 0 {
		args = append(args, "--host-timeout", nmapDuration(o.ServiceHostTimeout))
	}
	args = append(args,
		"-T"+strconv.Itoa(o.timingFor(ratePPS)),
		"--max-rate", strconv.Itoa(ratePPS),
		"-oX", "-",
	)
	return append(args, CompactIPv4Targets(targets)...)
}

// forbiddenNmapFlags are never allowed in generated command lines (scanner safety policy).
var forbiddenNmapFlags = []string{"--script", "-sC", "-A", "-O", "--osscan", "--data", "--badsum", "-f", "--mtu", "-D", "-S", "--spoof-mac", "--version-all"}

// ValidateSafeNmapArgs rejects any argv containing intrusive or exploit-ish options.
func ValidateSafeNmapArgs(args []string) error {
	for _, a := range args {
		for _, bad := range forbiddenNmapFlags {
			if a == bad || strings.HasPrefix(a, bad+"=") || (strings.HasPrefix(bad, "--") && strings.HasPrefix(a, bad)) {
				return fmt.Errorf("forbidden nmap option %q (scanner safety policy)", a)
			}
		}
	}
	return nil
}

// FormatCommand renders argv as a copy-pasteable shell command line.
func FormatCommand(bin string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(bin))
	for _, a := range args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r == '-' || r == '_' || r == '.' || r == '/' || r == ',' || r == ':' || r == '=' || r == '+' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// nmapDuration renders a duration in nmap's time syntax (ms/s/m/h).
func nmapDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	case d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	default:
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	}
}

func joinPorts(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

func dedupeSortPorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// CompactIPv4Targets collapses runs of consecutive IPv4 addresses inside the same /24 into
// nmap octet-range notation (10.0.0.1-50). The resulting target set is exactly the input
// set (no widening); non-IPv4 entries are passed through untouched. This keeps the recorded
// command line short and readable for 512-IP chunks.
func CompactIPv4Targets(ips []string) []string {
	type v4 struct {
		prefix [3]byte
		last   int
	}
	var parsed []v4
	var others []string
	seen := make(map[string]struct{}, len(ips))
	for _, s := range ips {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip4 := ip.To4(); ip4 != nil && !strings.Contains(s, ":") {
			parsed = append(parsed, v4{prefix: [3]byte{ip4[0], ip4[1], ip4[2]}, last: int(ip4[3])})
			continue
		}
		others = append(others, s)
	}
	sort.Slice(parsed, func(i, j int) bool {
		a, b := parsed[i], parsed[j]
		if a.prefix != b.prefix {
			for k := 0; k < 3; k++ {
				if a.prefix[k] != b.prefix[k] {
					return a.prefix[k] < b.prefix[k]
				}
			}
		}
		return a.last < b.last
	})
	out := make([]string, 0, len(parsed)/8+len(others)+1)
	for i := 0; i < len(parsed); {
		j := i
		for j+1 < len(parsed) && parsed[j+1].prefix == parsed[i].prefix && parsed[j+1].last == parsed[j].last+1 {
			j++
		}
		p := parsed[i].prefix
		base := fmt.Sprintf("%d.%d.%d.", p[0], p[1], p[2])
		if i == j {
			out = append(out, base+strconv.Itoa(parsed[i].last))
		} else {
			out = append(out, fmt.Sprintf("%s%d-%d", base, parsed[i].last, parsed[j].last))
		}
		i = j + 1
	}
	return append(out, others...)
}
