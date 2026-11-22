package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const (
	// DefaultMaxExpandedIPs prevents accidental /0 or /8 memory exhaustion while easily supporting /16 (65,536) and /14 (262,144).
	DefaultMaxExpandedIPs = 262144
)

// Resolver abstracts DNS lookup for testability and safe resolution.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type defaultResolver struct{}

func (defaultResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	// Bound each lookup: a target list full of names behind a dead/slow DNS server must not
	// hang the estimate request or the scan start for minutes.
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

// TargetResolution contains deduplicated, exclusion-filtered target IPs and domain mappings.
type TargetResolution struct {
	IPs            []string            `json:"ips"`
	TotalCount     int                 `json:"total_count"`
	ExcludedCount  int                 `json:"excluded_count"`
	DomainToIPs    map[string][]string `json:"domain_to_ips"`
	IPToDomains    map[string][]string `json:"ip_to_domains"`
	InvalidEntries []string            `json:"invalid_entries,omitempty"`
}

type ip4Range struct {
	start uint32
	end   uint32
}

// ParseAndNormalizeTargets expands IPs, CIDRs (including fast /16 = 65,536 IPs), IP ranges (a-b),
// and domains, deduplicates all addresses, and strictly removes all TargetExclusion CIDRs/IPs.
func ParseAndNormalizeTargets(ctx context.Context, targets []string, exclusions []domain.TargetExclusion, resolver Resolver) (*TargetResolution, error) {
	return ParseAndNormalizeTargetsWithLimit(ctx, targets, exclusions, resolver, DefaultMaxExpandedIPs)
}

// ParseAndNormalizeTargetsWithLimit allows overriding the maximum expanded IP count safety cap.
func ParseAndNormalizeTargetsWithLimit(ctx context.Context, targets []string, exclusions []domain.TargetExclusion, resolver Resolver, maxIPs int) (*TargetResolution, error) {
	if resolver == nil {
		resolver = defaultResolver{}
	}
	if maxIPs <= 0 {
		maxIPs = DefaultMaxExpandedIPs
	}

	res := &TargetResolution{
		DomainToIPs: make(map[string][]string),
		IPToDomains: make(map[string][]string),
	}

	var inc4 []ip4Range
	inc6 := make(map[netip.Addr]struct{})

	// Parse targets.
	for _, raw := range targets {
		entry := cleanTargetString(raw)
		if entry == "" {
			continue
		}
		if r4, ok := parseIPv4Entry(entry); ok {
			inc4 = append(inc4, r4)
			continue
		}
		if addrs6, ok := parseIPv6Entry(entry, maxIPs); ok {
			for _, a := range addrs6 {
				inc6[a] = struct{}{}
			}
			continue
		}
		// Treat as domain and safely resolve.
		if isLikelyDomain(entry) {
			ips, err := resolver.LookupHost(ctx, entry)
			if err != nil || len(ips) == 0 {
				res.InvalidEntries = append(res.InvalidEntries, entry)
				continue
			}
			// A name with IPv4 addresses is scanned over IPv4 only: "localhost" also resolves
			// to ::1, which would show every published docker port twice as a second host.
			hasV4 := false
			for _, ipStr := range ips {
				if a, err := netip.ParseAddr(strings.TrimSpace(ipStr)); err == nil && a.Unmap().Is4() {
					hasV4 = true
				}
			}
			for _, ipStr := range ips {
				addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
				if err != nil {
					continue
				}
				addr = addr.Unmap()
				if hasV4 && !addr.Is4() {
					continue
				}
				if addr.Is4() {
					v := addr4ToUint32(addr)
					inc4 = append(inc4, ip4Range{start: v, end: v})
				} else {
					inc6[addr] = struct{}{}
				}
				s := addr.String()
				res.DomainToIPs[entry] = appendUnique(res.DomainToIPs[entry], s)
				res.IPToDomains[s] = appendUnique(res.IPToDomains[s], entry)
			}
			continue
		}
		res.InvalidEntries = append(res.InvalidEntries, entry)
	}

	// Parse exclusions (Scope / Deny Gate).
	var exc4 []ip4Range
	var exc6Prefixes []netip.Prefix
	exc6Addrs := make(map[netip.Addr]struct{})

	for _, ex := range exclusions {
		entry := cleanTargetString(ex.Value)
		if entry == "" {
			continue
		}
		if r4, ok := parseIPv4Entry(entry); ok {
			exc4 = append(exc4, r4)
			continue
		}
		if pfx, err := netip.ParsePrefix(entry); err == nil && pfx.Addr().Is6() {
			exc6Prefixes = append(exc6Prefixes, pfx.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil && addr.Unmap().Is6() {
			exc6Addrs[addr.Unmap()] = struct{}{}
			continue
		}
		if isLikelyDomain(entry) {
			if ips, err := resolver.LookupHost(ctx, entry); err == nil {
				for _, ipStr := range ips {
					if addr, err := netip.ParseAddr(strings.TrimSpace(ipStr)); err == nil {
						addr = addr.Unmap()
						if addr.Is4() {
							v := addr4ToUint32(addr)
							exc4 = append(exc4, ip4Range{start: v, end: v})
						} else {
							exc6Addrs[addr] = struct{}{}
						}
					}
				}
			}
		}
	}

	// Merge IPv4 target intervals and compute totals before/after exclusion.
	mergedInc4 := mergeIP4Ranges(inc4)
	mergedExc4 := mergeIP4Ranges(exc4)

	total4 := countIP4Ranges(mergedInc4)
	if total4+uint64(len(inc6)) > uint64(maxIPs) {
		return nil, fmt.Errorf("target scope expands to %d IPs which exceeds safety cap %d", total4+uint64(len(inc6)), maxIPs)
	}

	effective4 := subtractIP4Ranges(mergedInc4, mergedExc4)
	effCount4 := countIP4Ranges(effective4)

	// Filter IPv6 targets against exclusions.
	var effective6 []netip.Addr
	excluded6 := 0
	for a := range inc6 {
		if isIPv6Excluded(a, exc6Addrs, exc6Prefixes) {
			excluded6++
			continue
		}
		effective6 = append(effective6, a)
	}
	sort.Slice(effective6, func(i, j int) bool { return effective6[i].Less(effective6[j]) })

	res.TotalCount = int(total4) + len(inc6)
	res.ExcludedCount = int(total4-effCount4) + excluded6

	// Pre-allocate exact slice for blazing-fast /16 (65,536 IP) expansion!
	ips := make([]string, 0, int(effCount4)+len(effective6))
	for _, r := range effective4 {
		for v := uint64(r.start); v <= uint64(r.end); v++ {
			ips = append(ips, uint32ToIPv4String(uint32(v)))
		}
	}
	for _, a := range effective6 {
		ips = append(ips, a.String())
	}
	res.IPs = ips

	// Clean domain maps of any excluded IPs so callers never see denied targets.
	if len(res.DomainToIPs) > 0 && res.ExcludedCount > 0 {
		allowed := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			allowed[ip] = struct{}{}
		}
		for dom, dIPs := range res.DomainToIPs {
			var kept []string
			for _, ip := range dIPs {
				if _, ok := allowed[ip]; ok {
					kept = append(kept, ip)
				}
			}
			if len(kept) == 0 {
				delete(res.DomainToIPs, dom)
			} else {
				res.DomainToIPs[dom] = kept
			}
		}
		for ip := range res.IPToDomains {
			if _, ok := allowed[ip]; !ok {
				delete(res.IPToDomains, ip)
			}
		}
	}

	return res, nil
}

// ParsePorts parses a port specification like "22,80,443,8000-8010" into sorted unique ports.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return []int{22, 80, 443, 8080, 8443}, nil
	}
	seen := make(map[int]struct{})
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			a, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for p := a; p <= b; p++ {
				seen[p] = struct{}{}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			seen[p] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no valid ports in %q", spec)
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func cleanTargetString(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			s = u.Hostname()
		}
	}
	return strings.TrimSpace(s)
}

func parseIPv4Entry(entry string) (ip4Range, bool) {
	// 1. Single IPv4
	if addr, err := netip.ParseAddr(entry); err == nil {
		addr = addr.Unmap()
		if addr.Is4() {
			v := addr4ToUint32(addr)
			return ip4Range{start: v, end: v}, true
		}
		return ip4Range{}, false
	}

	// 2. IPv4 CIDR
	if strings.Contains(entry, "/") {
		pfx, err := netip.ParsePrefix(entry)
		if err != nil || !pfx.Addr().Unmap().Is4() {
			return ip4Range{}, false
		}
		pfx = pfx.Masked()
		bits := pfx.Bits()
		start := addr4ToUint32(pfx.Addr().Unmap())
		var mask uint32
		if bits == 0 {
			mask = 0
		} else {
			mask = ^uint32(0) << uint(32-bits)
		}
		end := start | ^mask
		return ip4Range{start: start, end: end}, true
	}

	// 3. IPv4 range: "10.0.0.1-10.0.0.50" or shorthand "10.0.0.1-50"
	if strings.Contains(entry, "-") {
		parts := strings.SplitN(entry, "-", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])
		a1, err1 := netip.ParseAddr(left)
		if err1 != nil || !a1.Unmap().Is4() {
			return ip4Range{}, false
		}
		a1 = a1.Unmap()
		s := addr4ToUint32(a1)
		if a2, err2 := netip.ParseAddr(right); err2 == nil && a2.Unmap().Is4() {
			e := addr4ToUint32(a2.Unmap())
			if e < s {
				return ip4Range{}, false
			}
			return ip4Range{start: s, end: e}, true
		}
		// Shorthand last octet: "10.0.0.1-50"
		if lastOctet, err := strconv.Atoi(right); err == nil && lastOctet >= 0 && lastOctet <= 255 {
			b := a1.As4()
			if byte(lastOctet) < b[3] {
				return ip4Range{}, false
			}
			b[3] = byte(lastOctet)
			e := binary.BigEndian.Uint32(b[:])
			return ip4Range{start: s, end: e}, true
		}
	}

	return ip4Range{}, false
}

func parseIPv6Entry(entry string, maxIPs int) ([]netip.Addr, bool) {
	if addr, err := netip.ParseAddr(entry); err == nil && addr.Unmap().Is6() {
		return []netip.Addr{addr.Unmap()}, true
	}
	if strings.Contains(entry, "/") {
		pfx, err := netip.ParsePrefix(entry)
		if err == nil && pfx.Addr().Is6() {
			pfx = pfx.Masked()
			hostBits := 128 - pfx.Bits()
			if hostBits > 16 {
				return nil, false
			}
			count := 1 << hostBits
			if count > maxIPs {
				count = maxIPs
			}
			out := make([]netip.Addr, 0, count)
			cur := pfx.Addr()
			for i := 0; i < count && pfx.Contains(cur); i++ {
				out = append(out, cur)
				cur = cur.Next()
			}
			return out, true
		}
	}
	return nil, false
}

func isLikelyDomain(s string) bool {
	if s == "" || strings.ContainsAny(s, " /\\") {
		return false
	}
	if strings.EqualFold(s, "localhost") {
		return true
	}
	return strings.Contains(s, ".") && !strings.HasPrefix(s, ".") && !strings.HasSuffix(s, ".")
}

func addr4ToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func uint32ToIPv4String(v uint32) string {
	var buf [15]byte
	b := buf[:0]
	b = strconv.AppendInt(b, int64(byte(v>>24)), 10)
	b = append(b, '.')
	b = strconv.AppendInt(b, int64(byte(v>>16)), 10)
	b = append(b, '.')
	b = strconv.AppendInt(b, int64(byte(v>>8)), 10)
	b = append(b, '.')
	b = strconv.AppendInt(b, int64(byte(v)), 10)
	return string(b)
}

func mergeIP4Ranges(in []ip4Range) []ip4Range {
	if len(in) <= 1 {
		return append([]ip4Range(nil), in...)
	}
	cp := append([]ip4Range(nil), in...)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].start != cp[j].start {
			return cp[i].start < cp[j].start
		}
		return cp[i].end < cp[j].end
	})
	out := make([]ip4Range, 0, len(cp))
	cur := cp[0]
	for _, r := range cp[1:] {
		if uint64(r.start) <= uint64(cur.end)+1 {
			if r.end > cur.end {
				cur.end = r.end
			}
		} else {
			out = append(out, cur)
			cur = r
		}
	}
	out = append(out, cur)
	return out
}

func subtractIP4Ranges(inc, exc []ip4Range) []ip4Range {
	if len(inc) == 0 || len(exc) == 0 {
		return inc
	}
	var out []ip4Range
	j := 0
	for _, r := range inc {
		curStart := uint64(r.start)
		curEnd := uint64(r.end)
		for j < len(exc) && uint64(exc[j].end) < curStart {
			j++
		}
		k := j
		for k < len(exc) && uint64(exc[k].start) <= curEnd {
			exStart := uint64(exc[k].start)
			exEnd := uint64(exc[k].end)
			if exStart > curStart {
				out = append(out, ip4Range{start: uint32(curStart), end: uint32(exStart - 1)})
			}
			if exEnd >= curEnd {
				curStart = curEnd + 1
				break
			}
			curStart = exEnd + 1
			k++
		}
		if curStart <= curEnd {
			out = append(out, ip4Range{start: uint32(curStart), end: uint32(curEnd)})
		}
	}
	return out
}

func countIP4Ranges(ranges []ip4Range) uint64 {
	var total uint64
	for _, r := range ranges {
		total += uint64(r.end) - uint64(r.start) + 1
	}
	return total
}

func isIPv6Excluded(a netip.Addr, addrs map[netip.Addr]struct{}, prefixes []netip.Prefix) bool {
	if _, ok := addrs[a]; ok {
		return true
	}
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func appendUnique(slice []string, v string) []string {
	for _, s := range slice {
		if s == v {
			return slice
		}
	}
	return append(slice, v)
}
