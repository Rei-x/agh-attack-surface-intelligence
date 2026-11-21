// Command scanbench drives scanner.Engine directly (no DB, no API) against a target range and
// reports wall time, per-stage timing, the observed outgoing packet rate, and an export in
// the shape the scale-lab scorer reads (lab/scale/cmd/scorer). It is a development tool for
// measuring scan speed and safety; it is not part of the product.
//
//	go run ./cmd/scanbench -targets 10.66.0.0/18 -ports 22,80,443 -rate 1500 -conc 64 \
//	    -iface br-xxxx -out /tmp/export.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/intelligence"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

type exportHost struct {
	IP             string           `json:"ip"`
	Hostname       string           `json:"hostname"`
	LifecycleState string           `json:"lifecycle_state"`
	Services       []domain.Service `json:"services"`
}

func main() {
	targets := flag.String("targets", "10.66.0.0/18", "comma-separated targets")
	ports := flag.String("ports", "22,80,443", "allowed ports")
	rate := flag.Int("rate", 1500, "profile max_rate_pps")
	conc := flag.Int("conc", 64, "profile concurrency")
	workers := flag.Int("workers", 0, "max chunk workers (0 = engine default)")
	fp := flag.Bool("fp", true, "enable HTTP fingerprinting")
	httpRPS := flag.Int("http-rps", 0, "profile http_rps (0 = default)")
	iface := flag.String("iface", "", "interface whose tx_packets are sampled for the pps report")
	out := flag.String("out", "", "write scorer-compatible export JSON here")
	xmlOut := flag.String("xml", "", "write merged nmap XML here")
	unstable := flag.String("unstable", "", "file with previously-seen IPs (one per line) for the re-probe stage")
	flag.Parse()

	profile := domain.ScanProfile{
		ID: "bench", Name: "bench", Targets: strings.Split(*targets, ","), AllowedPorts: *ports,
		MaxRatePPS: *rate, Concurrency: *conc, EnableHTTPFingerprint: *fp, HTTPRPS: *httpRPS,
		ChunkTargetSec: 30,
	}
	var unstableIPs []string
	if *unstable != "" {
		raw, err := os.ReadFile(*unstable)
		if err != nil {
			log.Fatal(err)
		}
		unstableIPs = strings.Fields(string(raw))
	}
	eng := scanner.NewEngine(scanner.EngineConfig{UseNmap: scanner.NmapAvailable(), MaxChunkWorkers: *workers, UnstableHosts: unstableIPs})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	run, res, err := eng.PrepareRun(ctx, "bench", profile, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("prepared: %d IPs, %d chunks", run.TotalIPs, run.TotalChunks)

	// Packet-rate sampler.
	var ppsMu sync.Mutex
	var ppsSamples []int64
	stopSampler := make(chan struct{})
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		if *iface == "" {
			return
		}
		path := "/sys/class/net/" + *iface + "/statistics/tx_packets"
		read := func() int64 {
			b, err := os.ReadFile(path)
			if err != nil {
				return -1
			}
			n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
			return n
		}
		prev := read()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopSampler:
				return
			case <-t.C:
				cur := read()
				ppsMu.Lock()
				ppsSamples = append(ppsSamples, cur-prev)
				ppsMu.Unlock()
				prev = cur
			}
		}
	}()

	start := time.Now()
	result, err := eng.Execute(ctx, run, profile, res, scanner.RunCallbacks{
		OnEvent: func(ev domain.LiveEvent) {
			switch ev.Type {
			case "scan.chunk":
				if ev.Payload["status"] == domain.ChunkStatusDone {
					sm, _ := json.Marshal(ev.Payload["stage_ms"])
					log.Printf("chunk %v done in %vms active=%v svcs=%v stages=%s", ev.Payload["chunk_index"], ev.Payload["duration_ms"], ev.Payload["active_hosts"], ev.Payload["services"], sm)
					if cmds, ok := ev.Payload["nmap_commands"].([]string); ok {
						for _, c := range cmds {
							if len(c) > 260 {
								c = c[:260] + "..."
							}
							log.Printf("   cmd: %s", c)
						}
					}
				}
			case "scan.workers", "scan.rechunk", "governor.throttle", "scan.completed", "scan.stage":
				b, _ := json.Marshal(ev.Payload)
				log.Printf("%s %s", ev.Type, b)
			}
		},
	})
	wall := time.Since(start)
	close(stopSampler)
	<-samplerDone
	if err != nil {
		log.Printf("execute error: %v", err)
	}
	if result == nil {
		os.Exit(1)
	}

	alive, svcCount, httpCount := 0, 0, 0
	sigEngine := signatures.NewEngine(nil)
	var hosts []exportHost
	for _, o := range result.ObservedHosts {
		if !o.IsAlive {
			continue
		}
		alive++
		h := exportHost{IP: o.IP, Hostname: o.Hostname, LifecycleState: "ACTIVE"}
		for _, s := range o.Services {
			svcCount++
			if s.HTTP != nil {
				httpCount++
			}
			svc := domain.Service{Port: s.Port, Protocol: s.Protocol, State: s.State, ServiceName: s.ServiceName,
				Product: s.Product, Version: s.Version, CPE: s.CPE, Banner: s.Banner, HTTP: s.HTTP}
			intelligence.EnrichService(&svc, s, sigEngine, 1)
			h.Services = append(h.Services, svc)
		}
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP < hosts[j].IP })

	ppsMu.Lock()
	var peak, sum int64
	sorted := append([]int64(nil), ppsSamples...)
	for _, v := range ppsSamples {
		sum += v
		if v > peak {
			peak = v
		}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	ppsMu.Unlock()
	p99 := int64(0)
	if len(sorted) > 0 {
		p99 = sorted[len(sorted)*99/100]
	}

	st := result.StageTimings
	fmt.Printf("\n=== scanbench ===\nwall=%s ips=%d chunks=%d workers=%d per_worker_rate=%d\n", wall.Round(time.Millisecond), run.TotalIPs, run.TotalChunks, result.ChunkWorkers, result.PerWorkerRatePPS)
	fmt.Printf("alive=%d services=%d http_fp=%d\n", alive, svcCount, httpCount)
	fmt.Printf("stage sums: discovery=%.1fs reprobe=%.1fs service=%.1fs fingerprint=%.1fs\n",
		float64(st.DiscoveryMs)/1000, float64(st.ReprobeMs)/1000, float64(st.ServiceMs)/1000, float64(st.FingerprintMs)/1000)
	fmt.Printf("counters: %+v\n", st)
	if len(ppsSamples) > 0 {
		fmt.Printf("tx pps (%s, all packets incl. TCP/HTTP payload+ACKs): peak=%d p99=%d avg=%d\n", *iface, peak, p99, sum/int64(len(ppsSamples)))
	}
	gs, _ := json.Marshal(result.GovernorStats)
	fmt.Printf("governor: %s\n", gs)

	if *out != "" {
		b, _ := json.MarshalIndent(map[string]any{"count": len(hosts), "hosts": hosts}, "", " ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	if *xmlOut != "" {
		if err := os.WriteFile(*xmlOut, []byte(result.RawNmapXML), 0o644); err != nil {
			log.Fatal(err)
		}
	}
	if *out != "" {
		ppsFile := strings.TrimSuffix(*out, ".json") + ".pps.json"
		b, _ := json.Marshal(map[string]any{"wall_seconds": wall.Seconds(), "pps": ppsSamples, "stage_timings": st})
		_ = os.WriteFile(ppsFile, b, 0o644)
	}
}
