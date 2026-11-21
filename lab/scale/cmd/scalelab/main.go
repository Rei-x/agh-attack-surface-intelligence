// Command scalelab emulates a large (default /18, 16,384 IPs) university
// network on a single Linux host or container: ~1,500 live hosts on a dummy
// interface, realistic service personalities, network impairments, flapping
// and time-of-day hosts, two scenarios for change detection, and a control
// API that serves the ground truth.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/emu"
	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/netcfg"
	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/plan"
	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/truth"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func main() {
	var (
		cidr     = flag.String("cidr", env("SCALE_CIDR", "10.66.0.0/18"), "lab address space")
		hosts    = flag.Int("hosts", envInt("SCALE_HOSTS", 1500), "live hosts in scenario A")
		seed     = flag.Uint64("seed", uint64(envInt("SCALE_SEED", 1337)), "deterministic seed")
		iface    = flag.String("iface", env("SCALE_IFACE", "scl0"), "dummy interface name")
		uplink   = flag.String("uplink", env("SCALE_UPLINK", "eth0"), "interface scanners reach the lab on (netem target)")
		netem    = flag.String("netem", env("SCALE_NETEM", "delay 3ms 2ms distribution normal loss 0.1%"), "tc netem args; 'off' disables")
		control  = flag.String("control", env("SCALE_CONTROL", ":9900"), "control API listen address")
		scenario = flag.String("scenario", env("SCALE_SCENARIO", "A"), "initial scenario")
		flapN    = flag.Int("flap-hosts", envInt("SCALE_FLAP_HOSTS", 15), "flapping hosts")
		flapP    = flag.Int("flap-period", envInt("SCALE_FLAP_PERIOD", 120), "base flap period seconds (actual: P..2P)")
		todN     = flag.Int("tod-hosts", envInt("SCALE_TOD_HOSTS", 12), "time-of-day hosts")
		todHours = flag.String("tod-hours", env("SCALE_TOD_HOURS", "07-19"), "hours [start,end) TOD hosts are up")
		tz       = flag.String("tz", env("SCALE_TZ", "Europe/Warsaw"), "timezone for time-of-day hosts")
		truthDir = flag.String("truth-dir", env("SCALE_TRUTH_DIR", "/var/lib/scalelab"), "directory for truth dumps")
		dryRun   = flag.Bool("dry-run", os.Getenv("SCALE_DRY_RUN") == "1", "do not touch the network stack (dev)")
		bindHost = flag.String("bind", env("SCALE_BIND", ""), "dev only: bind every listener here instead of the host IP")
		planOnly = flag.Bool("plan-only", false, "print the truth for scenario A and B to truth-dir and exit")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	pfx, err := netip.ParsePrefix(*cidr)
	if err != nil {
		log.Fatalf("cidr: %v", err)
	}
	loc, err := time.LoadLocation(*tz)
	if err != nil {
		log.Printf("tz %s: %v (using UTC)", *tz, err)
		loc = time.UTC
	}
	var tod truth.HourRange
	if _, err := fmt.Sscanf(strings.Replace(*todHours, "-", " ", 1), "%d %d", &tod.Start, &tod.End); err != nil {
		log.Fatalf("tod-hours: %v", err)
	}
	tod.TZ = loc.String()

	t0 := time.Now()
	p, err := plan.Generate(plan.Config{CIDR: pfx, Hosts: *hosts, Seed: *seed, FlapHosts: *flapN, FlapPeriod: *flapP, TODHosts: *todN})
	if err != nil {
		log.Fatalf("plan: %v", err)
	}
	log.Printf("[plan] %s seed=%d: A=%d hosts B=%d hosts, union=%d, ports=%v (%.0fms)", pfx, *seed,
		len(p.Scenarios["A"].Hosts), len(p.Scenarios["B"].Hosts), len(p.All), p.Ports(), float64(time.Since(t0).Milliseconds()))

	var nc *netcfg.Net
	if !*planOnly {
		ne := *netem
		if ne == "off" || ne == "none" {
			ne = ""
		}
		nc, err = netcfg.Setup(netcfg.Config{Iface: *iface, Uplink: *uplink, CIDR: pfx, Netem: ne, DryRun: *dryRun})
		if err != nil {
			log.Fatalf("netcfg: %v", err)
		}
	}
	lab, err := emu.New(emu.Options{Plan: p, Net: nc, Scenario: *scenario, TOD: tod, Loc: loc, BindHost: *bindHost})
	if err != nil {
		log.Fatalf("lab: %v", err)
	}

	dump := func() {
		if err := os.MkdirAll(*truthDir, 0o755); err != nil {
			log.Printf("truth dir: %v", err)
			return
		}
		for _, s := range []string{"A", "B"} {
			doc, err := lab.Truth(s)
			if err != nil {
				continue
			}
			f := filepath.Join(*truthDir, "truth-"+s+".json")
			b, _ := json.MarshalIndent(doc, "", " ")
			if err := os.WriteFile(f, b, 0o644); err != nil {
				log.Printf("write %s: %v", f, err)
			}
		}
		log.Printf("[truth] nominal truth written to %s/truth-{A,B}.json", *truthDir)
	}
	if *planOnly {
		dump()
		return
	}

	if err := lab.SetScenario(*scenario); err != nil {
		log.Fatalf("scenario: %v", err)
	}
	dump()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go lab.Run(ctx)

	srv := &http.Server{Addr: *control, Handler: lab.ControlHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("[control] listening on %s (GET /truth, POST /scenario, POST /mark, GET /stats)", *control)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[control] %v", err)
			stop()
		}
	}()
	<-ctx.Done()
	log.Printf("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	lab.Close()
	if nc != nil {
		nc.Teardown()
	}
}
