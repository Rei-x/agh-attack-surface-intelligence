package emu

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/netcfg"
	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/plan"
	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/truth"
)

type Options struct {
	Plan     *plan.Plan
	Net      *netcfg.Net
	Scenario string
	TOD      truth.HourRange
	Loc      *time.Location
	// BindHost overrides the address listeners bind to (dev mode on non-Linux).
	BindHost string
}

type Lab struct {
	opt   Options
	certs *CertStore

	mu        sync.RWMutex
	scen      string
	listeners map[string]io.Closer
	up        map[netip.Addr]bool
	markAt    *time.Time
	toggled   map[netip.Addr]bool
	switched  time.Time
	remap     map[int]int // lab port -> local alt port (host already owns the port)
}

func New(opt Options) (*Lab, error) {
	cs, err := NewCertStore()
	if err != nil {
		return nil, err
	}
	if opt.Loc == nil {
		opt.Loc = time.Local
	}
	if opt.Scenario == "" {
		opt.Scenario = "A"
	}
	return &Lab{opt: opt, certs: cs, listeners: map[string]io.Closer{}, up: map[netip.Addr]bool{}, toggled: map[netip.Addr]bool{}, remap: map[int]int{}}, nil
}

func (l *Lab) Scenario() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.scen
}

func (l *Lab) lookup(ip netip.Addr, port int) (*plan.Host, *plan.Svc) {
	l.mu.RLock()
	sc := l.opt.Plan.Scenarios[l.scen]
	l.mu.RUnlock()
	if sc == nil {
		return nil, nil
	}
	h := sc.Hosts[ip]
	if h == nil {
		return nil, nil
	}
	return h, h.Svc(port)
}

// hostUp evaluates flapping / time-of-day state at time t.
func (l *Lab) hostUp(h *plan.Host, t time.Time) bool {
	if h.FlapPeriod > 0 {
		phase := (t.Unix() + int64(h.FlapPhase)) % int64(h.FlapPeriod)
		if phase >= int64(h.FlapPeriod)/2 {
			return false
		}
	}
	if h.TOD {
		hr := t.In(l.opt.Loc).Hour()
		s, e := l.opt.TOD.Start, l.opt.TOD.End
		in := hr >= s && hr < e
		if s > e {
			in = hr >= s || hr < e
		}
		if !in {
			return false
		}
	}
	return true
}

// SetScenario switches the live scenario: listeners, filters and addresses.
func (l *Lab) SetScenario(name string) error {
	sc := l.opt.Plan.Scenarios[name]
	if sc == nil {
		return fmt.Errorf("unknown scenario %q", name)
	}
	l.mu.Lock()
	l.scen = name
	l.switched = time.Now()
	l.mu.Unlock()

	want := map[string]bool{}
	for ip, h := range sc.Hosts {
		for i := range h.Svcs {
			s := &h.Svcs[i]
			want[lkey(ip, s)] = true
		}
	}
	l.mu.Lock()
	for k, c := range l.listeners {
		if !want[k] {
			_ = c.Close()
			delete(l.listeners, k)
		}
	}
	l.mu.Unlock()
	opened, failed := 0, 0
	for ip, h := range sc.Hosts {
		for i := range h.Svcs {
			s := &h.Svcs[i]
			k := lkey(ip, s)
			l.mu.RLock()
			_, have := l.listeners[k]
			l.mu.RUnlock()
			if have {
				continue
			}
			c, err := l.listen(ip, s.Port, s.Kind)
			if err != nil {
				failed++
				if failed < 5 {
					log.Printf("[lab] listen %s: %v", k, err)
				}
				continue
			}
			opened++
			l.mu.Lock()
			l.listeners[k] = c
			l.mu.Unlock()
		}
	}
	if l.opt.Net != nil {
		var rules []netcfg.FilterRule
		for ip, h := range sc.Hosts {
			if !h.ICMPBlocked && !h.Firewalled {
				continue
			}
			r := netcfg.FilterRule{IP: ip, ICMPBlocked: h.ICMPBlocked, Firewalled: h.Firewalled}
			l.mu.RLock()
			for _, s := range h.Svcs {
				r.Open = append(r.Open, s.Port)
				if alt, ok := l.remap[s.Port]; ok {
					r.Open = append(r.Open, alt) // filter INPUT sees the DNATed port
				}
			}
			l.mu.RUnlock()
			rules = append(rules, r)
		}
		sort.Slice(rules, func(i, j int) bool { return rules[i].IP.Less(rules[j].IP) })
		_ = l.opt.Net.ApplyFilters(rules)
	}
	l.mu.RLock()
	total := len(l.listeners)
	l.mu.RUnlock()
	log.Printf("[lab] scenario %s: %d hosts, %d listeners (+%d new, %d failed)", name, len(sc.Hosts), total, opened, failed)
	l.Tick()
	return nil
}

func lkey(ip netip.Addr, s *plan.Svc) string {
	return ip.String() + ":" + strconv.Itoa(s.Port) + "/" + s.Kind
}

// Tick recomputes which addresses are up and applies the difference.
func (l *Lab) Tick() {
	now := time.Now()
	l.mu.RLock()
	sc := l.opt.Plan.Scenarios[l.scen]
	l.mu.RUnlock()
	want := map[netip.Addr]bool{}
	for ip, h := range sc.Hosts {
		if l.hostUp(h, now) {
			want[ip] = true
		}
	}
	if l.opt.Net != nil {
		if _, _, err := l.opt.Net.SetUp(want); err != nil {
			log.Printf("[lab] SetUp: %v", err)
		}
	}
	l.mu.Lock()
	for _, ip := range l.opt.Plan.All {
		if l.up[ip] != want[ip] && l.markAt != nil {
			l.toggled[ip] = true
		}
	}
	l.up = want
	l.mu.Unlock()
}

// Run ticks every second until ctx is done.
func (l *Lab) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Tick()
		}
	}
}

func (l *Lab) Mark() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().UTC()
	l.markAt = &now
	l.toggled = map[netip.Addr]bool{}
	return now
}

func (l *Lab) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, c := range l.listeners {
		_ = c.Close()
		delete(l.listeners, k)
	}
}

// ---------------------------------------------------------------- listeners

func (l *Lab) listen(ip netip.Addr, port int, kind string) (io.Closer, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) { serr = freebind(fd) })
		if err != nil {
			return err
		}
		return serr
	}}
	bind := ip.String()
	if l.opt.BindHost != "" {
		bind = l.opt.BindHost
	}
	l.mu.RLock()
	alt, remapped := l.remap[port]
	l.mu.RUnlock()
	lport := port
	if remapped {
		lport = alt
	}
	ln, err := lc.Listen(context.Background(), "tcp4", net.JoinHostPort(bind, strconv.Itoa(lport)))
	if err != nil && !remapped && l.opt.Net != nil && errors.Is(err, syscall.EADDRINUSE) && port+20000 < 65536 {
		// A host service (typically sshd on 0.0.0.0:22) owns this port.
		alt = port + 20000
		if rerr := l.opt.Net.RedirectPort(port, alt); rerr == nil {
			l.mu.Lock()
			l.remap[port] = alt
			l.mu.Unlock()
			ln, err = lc.Listen(context.Background(), "tcp4", net.JoinHostPort(bind, strconv.Itoa(alt)))
		}
	}
	if err != nil {
		return nil, err
	}
	switch kind {
	case "http", "https":
		var hl net.Listener = ln
		scheme := "http"
		if kind == "https" {
			scheme = "https"
			hl = tls.NewListener(ln, &tls.Config{
				MinVersion: tls.VersionTLS10,
				GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
					h, s := l.lookup(ip, port)
					if h == nil || s == nil {
						return nil, fmt.Errorf("no service")
					}
					org := "Akademia Gorniczo-Hutnicza"
					switch s.App {
					case "hp-printer":
						org = "HP"
					case "synology":
						org = "Synology Inc."
					case "idrac":
						org = "Dell Inc."
					}
					cn := h.Hostname + ".lab.agh.local"
					return l.certs.Get(ip.String(), cn, nonEmpty(s.Cert, "self_signed"), org)
				},
			})
		}
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h, s := l.lookup(ip, port)
				if h == nil || s == nil {
					hj, ok := w.(http.Hijacker)
					if ok {
						if c, _, err := hj.Hijack(); err == nil {
							_ = c.Close()
						}
					}
					return
				}
				// Go sets Date itself; drop its default Content-Type sniffing by always setting it in apps.
				ServeApp(w, r, h, s, scheme, ip.String(), port)
			}),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       15 * time.Second,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
		go func() { _ = srv.Serve(hl) }()
		return srv, nil
	default:
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				h, s := l.lookup(ip, port)
				if h == nil || s == nil {
					_ = c.Close()
					continue
				}
				go serveConn(c, h, s, ip.String())
			}
		}()
		return ln, nil
	}
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---------------------------------------------------------------- truth

// Truth builds the ground truth document for a scenario.
func (l *Lab) Truth(scenario string) (*truth.Document, error) {
	p := l.opt.Plan
	sc := p.Scenarios[scenario]
	if sc == nil {
		return nil, fmt.Errorf("unknown scenario %q", scenario)
	}
	now := time.Now()
	l.mu.RLock()
	cur := l.scen
	up := l.up
	toggled := l.toggled
	markAt := l.markAt
	l.mu.RUnlock()
	doc := &truth.Document{Scenario: scenario, CIDR: p.CIDR.String(), Seed: p.Seed, GeneratedAt: now.UTC(), MarkedAt: markAt, Ports: p.Ports()}
	for _, ip := range p.All {
		h := sc.Hosts[ip]
		var th truth.Host
		if h == nil {
			// Exists only in another scenario: list it as not alive.
			for _, other := range p.Scenarios {
				if oh := other.Hosts[ip]; oh != nil {
					th = truth.Host{IP: ip.String(), Hostname: oh.Hostname, Archetype: oh.Archetype}
					break
				}
			}
			doc.Hosts = append(doc.Hosts, th)
			continue
		}
		th = truth.Host{IP: ip.String(), Hostname: h.Hostname, Archetype: h.Archetype, ICMPBlocked: h.ICMPBlocked, Firewalled: h.Firewalled}
		if scenario == cur {
			th.Alive = up[ip]
			th.Toggled = toggled[ip]
		} else {
			th.Alive = l.hostUp(h, now)
		}
		if h.FlapPeriod > 0 {
			th.Flapping, th.FlapPeriodSec = true, h.FlapPeriod
		}
		if h.TOD {
			tz := l.opt.TOD
			tz.TZ = l.opt.Loc.String()
			th.TimeOfDay = &tz
		}
		for i := range h.Svcs {
			th.Services = append(th.Services, ServiceTruth(h, &h.Svcs[i], ip.String()))
		}
		sort.Slice(th.Services, func(i, j int) bool { return th.Services[i].Port < th.Services[j].Port })
		doc.Hosts = append(doc.Hosts, th)
	}
	return doc, nil
}

// ---------------------------------------------------------------- control API

func (l *Lab) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		enc := json.NewEncoder(w)
		enc.SetIndent("", " ")
		_ = enc.Encode(v)
	}
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok", "scenario": l.Scenario()})
	})
	mux.HandleFunc("GET /scenario", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"name": l.Scenario(), "available": []string{"A", "B"}})
	})
	mux.HandleFunc("POST /scenario", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		if err := l.SetScenario(req.Name); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"name": l.Scenario()})
	})
	mux.HandleFunc("POST /mark", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"marked_at": l.Mark()})
	})
	mux.HandleFunc("GET /truth", func(w http.ResponseWriter, r *http.Request) {
		s := r.URL.Query().Get("scenario")
		if s == "" {
			s = l.Scenario()
		}
		doc, err := l.Truth(s)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, doc)
	})
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		l.mu.RLock()
		defer l.mu.RUnlock()
		var warns []string
		if l.opt.Net != nil {
			warns = l.opt.Net.Warn
		}
		hosts := len(l.opt.Plan.Scenarios[l.scen].Hosts)
		writeJSON(w, 200, map[string]any{
			"scenario": l.scen, "scenario_hosts": hosts, "up_now": len(l.up), "listeners": len(l.listeners),
			"toggled_since_mark": len(l.toggled), "marked_at": l.markAt, "switched_at": l.switched, "ports": l.opt.Plan.Ports(),
			"warnings": warns,
		})
	})
	return mux
}
