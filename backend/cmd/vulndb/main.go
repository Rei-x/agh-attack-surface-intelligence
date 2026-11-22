// Command vulndb builds the offline vulnerability snapshot embedded in the binary
// (internal/vulndb/snapshot.json.gz) from NVD CVE API 2.0, CISA KEV and FIRST EPSS,
// filtered to the products in vulndb.Catalog.
//
//	cd backend && go run ./cmd/vulndb          # full rebuild (about 10 minutes without an API key)
//	NVD_API_KEY=... go run ./cmd/vulndb        # faster with an NVD API key
//	go run ./cmd/vulndb -enrich-only           # refresh KEV + EPSS only
//	go run ./cmd/vulndb -retag                 # re-tag HTTP/2 / HTTP/3 preconditions, offline
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb"
)

func main() {
	out := flag.String("out", "internal/vulndb/snapshot.json.gz", "output file")
	in := flag.String("in", "", "existing snapshot to enrich (default: -out)")
	enrichOnly := flag.Bool("enrich-only", false, "only refresh KEV and EPSS of an existing snapshot")
	retag := flag.Bool("retag", false, "only re-tag protocol preconditions (HTTP/2, HTTP/3) of an existing snapshot, offline")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	b := &vulndb.Builder{NVDAPIKey: os.Getenv("NVD_API_KEY"), Log: log.Printf}
	start := time.Now()
	var snap *vulndb.Snapshot
	var err error
	if *retag {
		src := *in
		if src == "" {
			src = *out
		}
		raw, rerr := os.ReadFile(src)
		if rerr != nil {
			log.Fatal(rerr)
		}
		if snap, err = vulndb.Parse(raw); err == nil {
			st := vulndb.TagRequirements(snap)
			fmt.Printf("tagged %d HTTP/2 and %d HTTP/3 CVEs (%d from the explicit table)\n", st.ByRequirement[vulndb.ReqHTTP2], st.ByRequirement[vulndb.ReqHTTP3], st.FromTable)
			for _, e := range st.Examples {
				if len(e) > 140 {
					e = e[:140] + "..."
				}
				fmt.Println("  " + e)
			}
		}
	} else if *enrichOnly {
		src := *in
		if src == "" {
			src = *out
		}
		raw, rerr := os.ReadFile(src)
		if rerr != nil {
			log.Fatal(rerr)
		}
		if snap, err = vulndb.Parse(raw); err == nil {
			err = b.Enrich(ctx, snap)
		}
	} else {
		snap, err = b.Build(ctx)
	}
	if err != nil {
		log.Fatal(err)
	}
	raw, err := snap.Encode()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		log.Fatal(err)
	}
	info := vulndb.New(snap, *out).Info()
	fmt.Printf("wrote %s: %d bytes, %d CVEs (%d in KEV) for %d products, generated %s in %s\n",
		*out, len(raw), info.CVEs, info.KEV, info.Products, info.GeneratedAt, time.Since(start).Round(time.Second))
}
