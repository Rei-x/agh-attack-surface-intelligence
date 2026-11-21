package scanner

import (
	"context"
	"sort"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// chunkWork carries one ledger chunk through the pipelined stages.
type chunkWork struct {
	idx     int
	start   time.Time
	targets []string
	cmds    []string
	sm      chunkStageMs

	alive    []string
	aliveSet map[string]bool
	// open maps a live host to its open ports from the sweep; hosts absent from it (and
	// every host when open == nil) have unknown ports and get the full profile port list.
	open      map[string][]int
	openKnown map[string]bool

	svcMap map[string][]domain.ObservedService
	// guessed holds "ip:port" of services nmap named only from the port table.
	guessed map[string]bool
	xml    string
}

func (w *chunkWork) record(cmds ...string) {
	for _, c := range cmds {
		if c != "" {
			w.cmds = append(w.cmds, c)
		}
	}
}

// discoverChunk is Stage 1 (sweep or ping discovery) plus the early Stage 4 re-probe of
// previously-seen hosts that did not answer.
func (e *Engine) discoverChunk(ctx context.Context, w *chunkWork, ports []int, ratePPS, retryUnstable int, gov *Governor, unstableSet map[string]struct{}, st *stageStats) error {
	t0 := time.Now()
	var alive []string
	var open map[string][]int
	var err error
	if e.cfg.CustomDiscoveryFn != nil {
		alive, err = e.cfg.CustomDiscoveryFn(ctx, w.targets)
	} else {
		var res SweepResult
		res, err = e.cfg.NmapRunner.SweepDetailed(ctx, w.targets, ports, ratePPS, gov)
		w.record(res.Commands...)
		alive, open = res.Alive, res.OpenPorts
	}
	d := time.Since(t0)
	st.discoveryNs.Add(int64(d))
	w.sm.Discovery += d.Milliseconds()
	st.discoveryIPs.Add(int64(len(w.targets)))
	if err != nil {
		return err
	}

	w.aliveSet = make(map[string]bool, len(alive))
	w.openKnown = make(map[string]bool, len(alive))
	for _, ip := range alive {
		w.aliveSet[ip] = true
		if open != nil {
			w.openKnown[ip] = true
		}
	}
	w.alive = append([]string(nil), alive...)
	w.open = open

	// Stage 4 (early verification): re-probe previously-seen hosts missed in Stage 1 with
	// the full ping probe set; recovered hosts have unknown ports.
	t1 := time.Now()
	var toReprobe []string
	for _, ip := range w.targets {
		if !w.aliveSet[ip] {
			if _, tracked := unstableSet[ip]; tracked {
				toReprobe = append(toReprobe, ip)
			}
		}
	}
	for attempt := 0; attempt < retryUnstable && len(toReprobe) > 0; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		recovered, rcmd, rerr := e.discoverStage(ctx, toReprobe, ports, ratePPS, gov)
		w.record(rcmd)
		if rerr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			break
		}
		recSet := make(map[string]bool, len(recovered))
		for _, ip := range recovered {
			recSet[ip] = true
			if !w.aliveSet[ip] {
				w.aliveSet[ip] = true
				w.alive = append(w.alive, ip)
			}
		}
		var still []string
		for _, ip := range toReprobe {
			if !recSet[ip] {
				still = append(still, ip)
			}
		}
		toReprobe = still
	}
	d = time.Since(t1)
	st.reprobeNs.Add(int64(d))
	w.sm.Reprobe += d.Milliseconds()
	st.liveHosts.Add(int64(len(w.alive)))
	return nil
}

// serviceChunk is Stage 2: -sV on live hosts. Hosts whose open ports are known from the
// sweep are scanned on the union of those ports (hosts with none are skipped: nothing to
// identify); hosts with unknown ports are scanned on every profile port.
func (e *Engine) serviceChunk(ctx context.Context, w *chunkWork, ports []int, budget *rateBudget, want func() (int, int), gov *Governor, st *stageStats) error {
	t0 := time.Now()
	defer func() {
		d := time.Since(t0)
		st.serviceNs.Add(int64(d))
		w.sm.Service += d.Milliseconds()
	}()

	var knownHosts, unknownHosts []string
	unionSet := map[int]bool{}
	for _, ip := range w.alive {
		if w.openKnown[ip] {
			if ps := w.open[ip]; len(ps) > 0 {
				knownHosts = append(knownHosts, ip)
				for _, p := range ps {
					unionSet[p] = true
				}
			}
			continue
		}
		unknownHosts = append(unknownHosts, ip)
	}
	union := make([]int, 0, len(unionSet))
	for p := range unionSet {
		union = append(union, p)
	}
	sort.Ints(union)

	type group struct {
		hosts []string
		ports []int
	}
	var groups []group
	if len(knownHosts) > 0 {
		groups = append(groups, group{knownHosts, union})
	}
	if len(unknownHosts) > 0 {
		groups = append(groups, group{unknownHosts, ports})
	}
	if len(groups) == 0 {
		return nil
	}

	w.svcMap = make(map[string][]domain.ObservedService)
	var docs []string
	for _, g := range groups {
		ws, wmin := want()
		rate, err := budget.acquire(ctx, ws, wmin)
		if err != nil {
			return err
		}
		m, x, cmd, err := e.serviceScanStage(ctx, g.hosts, g.ports, rate, gov)
		budget.release(rate)
		w.record(cmd)
		if err != nil {
			return err
		}
		for ip, svcs := range m {
			w.svcMap[ip] = svcs
			st.openPorts.Add(int64(len(svcs)))
		}
		if x != "" {
			docs = append(docs, x)
		}
	}
	w.guessed = map[string]bool{}
	for _, d := range docs {
		for k := range guessedServices(d) {
			w.guessed[k] = true
		}
	}
	switch len(docs) {
	case 0:
	case 1:
		w.xml = docs[0]
	default:
		w.xml = MergeNmapXML(docs)
	}
	return nil
}

// buildObserved turns a finished chunk into one ObservedHost per target IP.
func (e *Engine) buildObserved(w *chunkWork, ipToDomains map[string][]string) []domain.ObservedHost {
	now := e.cfg.Now()
	observed := make([]domain.ObservedHost, 0, len(w.targets))
	for _, ip := range w.targets {
		domains := ipToDomains[ip]
		var hostname string
		if len(domains) > 0 {
			hostname = domains[0]
		}
		svcs := w.svcMap[ip]
		observed = append(observed, domain.ObservedHost{
			IP:         ip,
			Hostname:   hostname,
			Domains:    append([]string(nil), domains...),
			IsAlive:    w.aliveSet[ip] || len(svcs) > 0,
			ObservedAt: now,
			Services:   svcs,
		})
	}
	return observed
}
