package scanner

import (
	"context"
	"sync"
)

// rateBudget hands out shares of a fixed packets-per-second budget to concurrent nmap
// processes. nmap's --max-rate is fixed for a process's lifetime, so a share is acquired
// before launch and released when the process exits: at every instant the sum of
// --max-rate over running processes is <= total. Discovery, service detection and the
// tail of the scan draw from the same pool, so budget left idle by one stage (e.g. -sV
// waiting on silent services) is picked up by the next process that starts.
type rateBudget struct {
	mu      sync.Mutex
	total   int
	used    int
	peak    int
	changed chan struct{}
}

func newRateBudget(total int) *rateBudget {
	if total < 1 {
		total = 1
	}
	return &rateBudget{total: total, changed: make(chan struct{})}
}

// acquire blocks until at least min pps are free, then grants min(want, free).
func (b *rateBudget) acquire(ctx context.Context, want, min int) (int, error) {
	if min < 1 {
		min = 1
	}
	if min > b.total {
		min = b.total
	}
	if want < min {
		want = min
	}
	for {
		b.mu.Lock()
		free := b.total - b.used
		if free >= min {
			g := want
			if g > free {
				g = free
			}
			b.used += g
			if b.used > b.peak {
				b.peak = b.used
			}
			b.mu.Unlock()
			return g, nil
		}
		ch := b.changed
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ch:
		}
	}
}

func (b *rateBudget) release(n int) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
	close(b.changed)
	b.changed = make(chan struct{})
	b.mu.Unlock()
}

// peakUsed is the largest sum of concurrently granted shares (always <= total).
func (b *rateBudget) peakUsed() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peak
}
