package agent

import (
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Interface is one network interface and its addresses (prefix = address/mask). It is the
// test seam over net.Interfaces.
type Interface struct {
	Name     string
	Up       bool
	Loopback bool
	Addrs    []netip.Prefix
}

// SystemInterfaces lists this host's interfaces.
func SystemInterfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifs))
	for _, ifc := range ifs {
		it := Interface{Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0, Loopback: ifc.Flags&net.FlagLoopback != 0}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ones, bits := ipn.Mask.Size()
			ip = ip.Unmap()
			if ip.Is4() && bits == 128 {
				ones -= 96
			}
			if ones < 0 || ones > ip.BitLen() {
				continue
			}
			it.Addrs = append(it.Addrs, netip.PrefixFrom(ip, ones))
		}
		out = append(out, it)
	}
	return out, nil
}

// privateRanges are the address blocks an agent may scan by default: RFC 1918, the CGNAT /
// shared address space (RFC 6598) and IPv6 unique local addresses (RFC 4193).
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// virtualPrefixes name container and VM bridges: real networks, but rarely what a person
// means by "my network", so they are listed after the physical ones.
var virtualPrefixes = []string{"docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "cni", "flannel",
	"cali", "weave", "lxcbr", "lxdbr", "podman", "bridge", "kube"}

func isVirtual(name string) bool {
	n := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// PrivateSubnets returns the private networks the given interfaces are attached to. Down and
// loopback interfaces, link-local and public addresses are skipped. A mask wider than the
// private block it lies in (10.1.2.3/7) is clamped to that block, so the result never covers
// a public address. Physical interfaces come first, then IPv4 before IPv6; duplicates are
// dropped.
func PrivateSubnets(ifaces []Interface) []domain.LocalSubnet {
	var out []domain.LocalSubnet
	seen := map[netip.Prefix]bool{}
	for _, ifc := range ifaces {
		if !ifc.Up || ifc.Loopback {
			continue
		}
		for _, p := range ifc.Addrs {
			addr := p.Addr().Unmap()
			var block netip.Prefix
			for _, r := range privateRanges {
				if r.Contains(addr) {
					block = r
					break
				}
			}
			if !block.IsValid() {
				continue
			}
			bits := p.Bits()
			if bits < block.Bits() {
				bits = block.Bits()
			}
			network := netip.PrefixFrom(addr, bits).Masked()
			if seen[network] {
				continue
			}
			seen[network] = true
			out = append(out, domain.LocalSubnet{
				CIDR: network.String(), Address: addr.String(), Interface: ifc.Name, Virtual: isVirtual(ifc.Name),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Virtual != out[j].Virtual {
			return !out[i].Virtual
		}
		return strings.Contains(out[j].CIDR, ":") && !strings.Contains(out[i].CIDR, ":")
	})
	return out
}
