package scanner

import (
	"fmt"
	"testing"
)

func TestPermuteTargetsIsAPermutation(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 5, 31, 256, 1000, 16384} {
		ips := make([]string, n)
		for i := range ips {
			ips[i] = fmt.Sprintf("10.66.%d.%d", i/256, i%256)
		}
		out := PermuteTargets(ips, 42)
		if len(out) != n {
			t.Fatalf("n=%d: got %d elements", n, len(out))
		}
		seen := make(map[string]bool, n)
		for _, ip := range out {
			if seen[ip] {
				t.Fatalf("n=%d: duplicate %s", n, ip)
			}
			seen[ip] = true
		}
		again := PermuteTargets(ips, 42)
		for i := range out {
			if out[i] != again[i] {
				t.Fatalf("n=%d: permutation not deterministic for a fixed seed", n)
			}
		}
	}
}

// A 512-IP slice of a permuted /18 must touch (nearly) every /24, instead of 2 contiguous ones.
func TestPermuteTargetsSpreadsAcrossSubnets(t *testing.T) {
	ips := make([]string, 16384)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.66.%d.%d", i/256, i%256)
	}
	out := PermuteTargets(ips, 7)
	subnets := map[string]int{}
	for _, ip := range out[:512] {
		var a, b, c, d int
		fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
		subnets[fmt.Sprintf("%d", c)]++
	}
	if len(subnets) < 56 {
		t.Fatalf("first 512 permuted IPs only hit %d of 64 /24s", len(subnets))
	}
	for s, n := range subnets {
		if n > 24 {
			t.Fatalf("/24 %s got %d of 512 probes; expected ~8", s, n)
		}
	}
}
