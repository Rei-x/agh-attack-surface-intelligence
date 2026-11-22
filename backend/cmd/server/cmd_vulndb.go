package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/localdata"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb"
)

const vulndbUsage = `Usage:
  dzieciol vulndb info                 Show the active vulnerability snapshot (date, sources, counts)
  dzieciol vulndb update [--full]      Refresh it into the data directory

update downloads CISA KEV and FIRST EPSS (two files, seconds) and re-scores the CVEs of the
current snapshot; --full also re-fetches the CVE ranges from the NVD CVE API 2.0 (about 6
minutes without NVD_API_KEY). Scans never wait for it: the running server switches to the new
snapshot within a minute, and when the network is down the current snapshot stays in use.

Flags:
  --data-dir DIR   Data directory (default ~/.dzieciol, env DZIECIOL_DATA_DIR)
  --full           Rebuild the CVE ranges from NVD too
`

func vulndbOverlayPath(dir string) string { return filepath.Join(dir, "vulndb.json.gz") }

func cmdVulnDB(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(vulndbUsage)
		return nil
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("vulndb "+sub, flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "data directory (default ~/.dzieciol)")
	full := fs.Bool("full", false, "rebuild the CVE ranges from NVD too")
	if err := fs.Parse(rest); err != nil {
		return errUsage
	}
	dir, err := localdata.DefaultDir(*dataDir)
	if err != nil {
		return err
	}
	vulndb.SetOverlayPath(vulndbOverlayPath(dir))
	switch sub {
	case "info":
		printVulnDBInfo(vulndb.Current().Info())
		return nil
	case "update":
		return vulndbUpdate(dir, *full)
	}
	fmt.Fprint(os.Stderr, vulndbUsage)
	return errUsage
}

// printVulnDBPreflight reports the offline vulnerability snapshot in the startup banner.
func printVulnDBPreflight(w io.Writer) {
	i := vulndb.Current().Info()
	fmt.Fprintf(w, "vulns:   %d CVEs (%d in CISA KEV), EPSS %s, snapshot %s; refresh: dzieciol vulndb update\n", i.CVEs, i.KEV, i.Sources.EPSSDate, dateOf(i.GeneratedAt))
}

func dateOf(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

func printVulnDBInfo(i vulndb.Info) {
	fmt.Printf("snapshot:  %s (%s)\n", i.GeneratedAt, i.Origin)
	fmt.Printf("coverage:  %d CVEs for %d products, %d in CISA KEV\n", i.CVEs, i.Products, i.KEV)
	fmt.Printf("NVD:       %s (fetched %s)\n", i.Sources.NVD, i.Sources.NVDFetched)
	fmt.Printf("KEV:       catalog %s, %d entries (%s)\n", i.Sources.KEVVersion, i.Sources.KEVCount, i.Sources.KEV)
	fmt.Printf("EPSS:      model %s, scores of %s (%s)\n", i.Sources.EPSSModel, i.Sources.EPSSDate, i.Sources.EPSS)
}

func vulndbUpdate(dir string, full bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	limit := 2 * time.Minute
	if full {
		limit = 30 * time.Minute
	}
	ctx, cancelT := context.WithTimeout(ctx, limit)
	defer cancelT()
	b := &vulndb.Builder{NVDAPIKey: os.Getenv("NVD_API_KEY"), Log: func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }}
	var snap *vulndb.Snapshot
	var err error
	if full {
		fmt.Println("rebuilding from NVD CVE API 2.0, CISA KEV and FIRST EPSS ...")
		snap, err = b.Build(ctx)
	} else {
		cur := vulndb.Current()
		fmt.Printf("refreshing KEV and EPSS of the %s snapshot (%s) ...\n", cur.Info().Origin, cur.Info().GeneratedAt)
		// Work on a private copy: Current() is shared.
		raw, eerr := cur.Snapshot().Encode()
		if eerr != nil {
			return eerr
		}
		if snap, err = vulndb.Parse(raw); err == nil {
			err = b.Enrich(ctx, snap)
		}
	}
	if err != nil {
		return fmt.Errorf("update failed, the current snapshot stays in use: %w", err)
	}
	raw, err := snap.Encode()
	if err != nil {
		return err
	}
	path := vulndbOverlayPath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d KB)\n", path, len(raw)/1024)
	printVulnDBInfo(vulndb.New(snap, path).Info())
	return nil
}
