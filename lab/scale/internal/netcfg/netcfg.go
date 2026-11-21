// Package netcfg wires the lab's address space into the Linux network stack
// using ip(8), tc(8) and iptables(8). Every step degrades gracefully: when a
// tool or kernel feature is missing the lab keeps running and logs a warning.
package netcfg

import (
	"bytes"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

type Config struct {
	Iface  string       // dummy interface holding live-host addresses (default scl0)
	Uplink string       // interface scanners reach us on (netem is applied here)
	CIDR   netip.Prefix // lab address space; blackholed so dead IPs never answer
	Netem  string       // e.g. "delay 4ms 2ms distribution normal loss 0.2%"; "" disables
	DryRun bool         // log commands only (development on non-Linux)
}

type Net struct {
	cfg   Config
	mu    sync.Mutex
	addrs map[netip.Addr]bool
	Warn  []string
}

func run(dry bool, name string, args ...string) error {
	if dry {
		log.Printf("[dry-run] %s %s", name, strings.Join(args, " "))
		return nil
	}
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runStdin(dry bool, stdin string, name string, args ...string) error {
	if dry {
		log.Printf("[dry-run] %s %s <<%d bytes>>", name, strings.Join(args, " "), len(stdin))
		return nil
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

func (n *Net) warn(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	n.Warn = append(n.Warn, msg)
	log.Printf("[netcfg] WARNING: %s", msg)
}

// Setup creates the dummy interface, blackhole route, nonlocal-bind and netem.
func Setup(cfg Config) (*Net, error) {
	if cfg.Iface == "" {
		cfg.Iface = "scl0"
	}
	n := &Net{cfg: cfg, addrs: map[netip.Addr]bool{}}
	d := cfg.DryRun
	_ = run(d, "ip", "link", "del", cfg.Iface)
	// Clean leftovers of a previous unclean exit.
	_ = run(d, "iptables", "-t", "nat", "-F", natChain)
	if err := run(d, "ip", "link", "add", cfg.Iface, "type", "dummy"); err != nil {
		return nil, fmt.Errorf("cannot create dummy interface (need CAP_NET_ADMIN and the dummy module): %w", err)
	}
	if err := run(d, "ip", "link", "set", cfg.Iface, "up"); err != nil {
		return nil, err
	}
	// Dead IPs: blackhole = silently dropped, no ICMP unreachable, never forwarded.
	_ = run(d, "ip", "route", "del", "blackhole", cfg.CIDR.String())
	if err := run(d, "ip", "route", "add", "blackhole", cfg.CIDR.String()); err != nil {
		n.warn("blackhole route failed (dead IPs may emit ICMP or be forwarded): %v", err)
	}
	if cur, _ := os.ReadFile("/proc/sys/net/ipv4/ip_nonlocal_bind"); !d && strings.TrimSpace(string(cur)) != "1" {
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_nonlocal_bind", []byte("1"), 0644); err != nil {
			n.warn("ip_nonlocal_bind: %v (IP_FREEBIND is used instead)", err)
		}
	}
	if cfg.Netem != "" && cfg.Uplink != "" {
		args := append([]string{"qdisc", "replace", "dev", cfg.Uplink, "root", "netem"}, strings.Fields(cfg.Netem)...)
		if err := run(d, "tc", args...); err != nil {
			n.warn("tc netem unavailable: %v", err)
		} else {
			log.Printf("[netcfg] netem on %s: %s", cfg.Uplink, cfg.Netem)
		}
	}
	return n, nil
}

// SetUp makes exactly the given addresses live on the dummy interface.
// It returns the addresses that were added and removed.
func (n *Net) SetUp(want map[netip.Addr]bool) (added, removed []netip.Addr, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var b strings.Builder
	for a := range want {
		if !n.addrs[a] {
			added = append(added, a)
			fmt.Fprintf(&b, "addr add %s/32 dev %s\n", a, n.cfg.Iface)
		}
	}
	for a := range n.addrs {
		if !want[a] {
			removed = append(removed, a)
			fmt.Fprintf(&b, "addr del %s/32 dev %s\n", a, n.cfg.Iface)
		}
	}
	if b.Len() == 0 {
		return nil, nil, nil
	}
	if err := runStdin(n.cfg.DryRun, b.String(), "ip", "-force", "-batch", "-"); err != nil {
		// -force continues past individual failures; resync from the kernel's view.
		log.Printf("[netcfg] ip batch reported errors: %v", err)
	}
	for _, a := range added {
		n.addrs[a] = true
	}
	for _, a := range removed {
		delete(n.addrs, a)
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Less(added[j]) })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Less(removed[j]) })
	return added, removed, nil
}

// FilterRule describes per-host packet filtering.
type FilterRule struct {
	IP          netip.Addr
	ICMPBlocked bool
	Firewalled  bool  // DROP every TCP port not in Open (instead of kernel RST)
	Open        []int // open TCP ports
}

const chain = "SCALELAB"

// ApplyFilters atomically replaces the SCALELAB chain.
func (n *Net) ApplyFilters(rules []FilterRule) error {
	var b strings.Builder
	b.WriteString("*filter\n:" + chain + " - [0:0]\n")
	for _, r := range rules {
		if r.ICMPBlocked {
			fmt.Fprintf(&b, "-A %s -d %s/32 -p icmp -j DROP\n", chain, r.IP)
		}
		if r.Firewalled {
			ports := make([]string, 0, len(r.Open))
			for _, p := range r.Open {
				ports = append(ports, fmt.Sprint(p))
			}
			// multiport accepts at most 15 entries
			for len(ports) > 15 {
				ports = ports[:15]
			}
			if len(ports) == 0 {
				fmt.Fprintf(&b, "-A %s -d %s/32 -p tcp -j DROP\n", chain, r.IP)
			} else {
				fmt.Fprintf(&b, "-A %s -d %s/32 -p tcp -m multiport ! --dports %s -j DROP\n", chain, r.IP, strings.Join(ports, ","))
			}
			// Firewalled hosts also silently drop UDP probes.
			fmt.Fprintf(&b, "-A %s -d %s/32 -p udp -j DROP\n", chain, r.IP)
		}
	}
	b.WriteString("COMMIT\n")
	if err := runStdin(n.cfg.DryRun, b.String(), "iptables-restore", "--noflush"); err != nil {
		n.warn("iptables-restore failed, ICMP-blocking/firewalled hosts degrade to normal hosts: %v", err)
		return err
	}
	if run(n.cfg.DryRun, "iptables", "-C", "INPUT", "-d", n.cfg.CIDR.String(), "-j", chain) != nil {
		if err := run(n.cfg.DryRun, "iptables", "-I", "INPUT", "1", "-d", n.cfg.CIDR.String(), "-j", chain); err != nil {
			n.warn("iptables jump failed: %v", err)
			return err
		}
	}
	return nil
}

const natChain = "SCALELAB_NAT"

// RedirectPort makes TCP port `port` on every lab address reach `alt` (same IP).
// Used when a host service (e.g. sshd on 0.0.0.0:22) already owns the port.
func (n *Net) RedirectPort(port, alt int) error {
	d := n.cfg.DryRun
	_ = run(d, "iptables", "-t", "nat", "-N", natChain) // may already exist
	if run(d, "iptables", "-t", "nat", "-C", "PREROUTING", "-d", n.cfg.CIDR.String(), "-j", natChain) != nil {
		if err := run(d, "iptables", "-t", "nat", "-I", "PREROUTING", "1", "-d", n.cfg.CIDR.String(), "-j", natChain); err != nil {
			n.warn("nat jump failed: %v", err)
			return err
		}
	}
	args := []string{"-t", "nat", "-A", natChain, "-d", n.cfg.CIDR.String(), "-p", "tcp", "--dport", fmt.Sprint(port), "-j", "DNAT", "--to-destination", fmt.Sprintf(":%d", alt)}
	if err := run(d, "iptables", args...); err != nil {
		n.warn("port redirect %d->%d failed: %v", port, alt, err)
		return err
	}
	log.Printf("[netcfg] port %d is taken on this host; lab listeners use %d via DNAT (dst IP preserved)", port, alt)
	return nil
}

// Teardown removes everything Setup/ApplyFilters created.
func (n *Net) Teardown() {
	d := n.cfg.DryRun
	_ = run(d, "iptables", "-t", "nat", "-D", "PREROUTING", "-d", n.cfg.CIDR.String(), "-j", natChain)
	_ = run(d, "iptables", "-t", "nat", "-F", natChain)
	_ = run(d, "iptables", "-t", "nat", "-X", natChain)
	_ = run(d, "iptables", "-D", "INPUT", "-d", n.cfg.CIDR.String(), "-j", chain)
	_ = run(d, "iptables", "-F", chain)
	_ = run(d, "iptables", "-X", chain)
	if n.cfg.Netem != "" && n.cfg.Uplink != "" {
		_ = run(d, "tc", "qdisc", "del", "dev", n.cfg.Uplink, "root")
	}
	_ = run(d, "ip", "route", "del", "blackhole", n.cfg.CIDR.String())
	_ = run(d, "ip", "link", "del", n.cfg.Iface)
	log.Printf("[netcfg] teardown complete")
}
