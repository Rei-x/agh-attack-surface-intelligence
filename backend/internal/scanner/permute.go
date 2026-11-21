package scanner

import (
	"math/big"
	"math/rand/v2"
)

// PermuteTargets returns ips in a pseudo-random order produced by iterating a multiplicative
// cyclic group modulo a prime, exactly like ZMap (Durumeric, Wustrow, Halderman, "ZMap: Fast
// Internet-wide Scanning and its Security Applications", USENIX Security 2013, §3.1):
//
//	p      = smallest prime > len(ips)
//	g      = a random primitive root of Z*_p (a generator of the whole group)
//	x_0    = random element of Z*_p,  x_{k+1} = g * x_k mod p
//
// The sequence visits every element of 1..p-1 exactly once; elements > len(ips) are skipped.
// Consecutive chunks of the result therefore sample the whole scope instead of one or two
// contiguous /24s, so at any moment the probe rate is spread over every subnet in scope
// (e.g. 1500 pps over a /18 is ~23 pps per /24, instead of ~190 pps per /24 when 4 workers
// each sweep a contiguous 512-IP block). The seed makes the order reproducible per run.
func PermuteTargets(ips []string, seed uint64) []string {
	n := len(ips)
	if n < 3 {
		return append([]string(nil), ips...)
	}
	p := nextPrime(uint64(n) + 1)
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	g := randomPrimitiveRoot(p, rng)
	x := 1 + rng.Uint64N(p-1)

	out := make([]string, 0, n)
	for i := uint64(0); i < p-1; i++ {
		if x <= uint64(n) {
			out = append(out, ips[x-1])
		}
		x = mulMod(x, g, p)
	}
	return out
}

func mulMod(a, b, m uint64) uint64 {
	// p stays far below 2^32 for any scope we accept, so the product cannot overflow.
	return (a * b) % m
}

func nextPrime(n uint64) uint64 {
	if n <= 2 {
		return 2
	}
	if n%2 == 0 {
		n++
	}
	for !new(big.Int).SetUint64(n).ProbablyPrime(20) {
		n += 2
	}
	return n
}

// randomPrimitiveRoot picks random candidates until one generates all of Z*_p: g is a
// primitive root iff g^((p-1)/q) != 1 (mod p) for every prime factor q of p-1.
func randomPrimitiveRoot(p uint64, rng *rand.Rand) uint64 {
	factors := primeFactors(p - 1)
	bp := new(big.Int).SetUint64(p)
	for {
		g := 2 + rng.Uint64N(p-3)
		bg := new(big.Int).SetUint64(g)
		ok := true
		for _, q := range factors {
			if new(big.Int).Exp(bg, new(big.Int).SetUint64((p-1)/q), bp).Cmp(big.NewInt(1)) == 0 {
				ok = false
				break
			}
		}
		if ok {
			return g
		}
	}
}

func primeFactors(n uint64) []uint64 {
	var fs []uint64
	for q := uint64(2); q*q <= n; q++ {
		if n%q == 0 {
			fs = append(fs, q)
			for n%q == 0 {
				n /= q
			}
		}
	}
	if n > 1 {
		fs = append(fs, n)
	}
	return fs
}
