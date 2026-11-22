package scanner

import "log"

// warnFallback logs the first nmap failure that forced the pure-Go fallback. The fallback is
// much weaker (no -sV, synthesized XML), so it must never be silent: a missing nmap-scripts
// package in the Docker image makes every -sV fail unnoticed.
func (r *NmapRunner) warnFallback(reason string) {
	if r.fallbackWarned.CompareAndSwap(false, true) {
		log.Printf("[WARN] nmap unusable, falling back to the pure-Go TCP connect scanner (reported once): %s", reason)
	}
}
