package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
)

const storeStatsUsage = `Usage: dzieciol store-stats [flags]

Shows what the store holds and what it costs: items and serialized size per collection,
the store file size and the Go heap after loading it, plus what the history retention
policy (DZIECIOL_RETENTION_*) would remove on the next start. Read-only: nothing is written,
so it is safe next to a running server. In PostgreSQL mode it lists table sizes instead.`

type storeStatsReport struct {
	Backend       string              `json:"backend"`
	Path          string              `json:"path,omitempty"`
	FileBytes     int64               `json:"file_bytes,omitempty"`
	HeapAfterLoad uint64              `json:"heap_after_load_bytes,omitempty"`
	Retention     string              `json:"retention"`
	Collections   []db.CollectionStat `json:"collections"`
	WouldCompact  string              `json:"would_compact,omitempty"`
	BytesAfter    int64               `json:"json_bytes_after_retention,omitempty"`
}

func cmdStoreStats(args []string) error {
	fs := newFlagSet("store-stats", storeStatsUsage)
	dataDir := fs.String("data-dir", "", "data directory (default ~/.dzieciol)")
	jsonOut := fs.Bool("json", false, "JSON output")
	heapProfile := fs.String("heap-profile", "", "write a pprof heap profile taken right after loading to this file")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	quietLogs(false)
	ctx := context.Background()
	rt, err := openRuntime(ctx, runtimeOptions{DataDir: *dataDir, Command: "store-stats", ReadOnly: true})
	if err != nil {
		return err
	}
	defer rt.Close()
	warnIfServerRunning(rt)

	rep := storeStatsReport{Retention: rt.Retention.String()}
	if rt.Postgres {
		pg, ok := rt.Store.(*db.PostgresStore)
		if !ok {
			return fmt.Errorf("unexpected store type %T", rt.Store)
		}
		rep.Backend = "postgresql"
		if rep.Collections, err = pg.TableStats(ctx); err != nil {
			return err
		}
	} else {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		rep.Backend, rep.Path, rep.HeapAfterLoad = "file-encrypted", rt.FileStore.Path(), ms.HeapAlloc
		if st, err := os.Stat(rep.Path); err == nil {
			rep.FileBytes = st.Size()
		}
		if *heapProfile != "" {
			f, err := os.Create(*heapProfile)
			if err != nil {
				return err
			}
			err = pprof.Lookup("heap").WriteTo(f, 0)
			f.Close()
			if err != nil {
				return err
			}
		}
		rep.Collections = rt.FileStore.CollectionStats()
		// Dry run on the read-only copy in memory: the file is never written.
		if cr, err := rt.FileStore.Compact(ctx, rt.Retention); err == nil {
			rep.WouldCompact = cr.String()
			rep.BytesAfter = totalBytes(rt.FileStore.CollectionStats())
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	total := totalBytes(rep.Collections)
	if rep.Path != "" {
		fmt.Printf("Store:           %s\n", rep.Path)
		fmt.Printf("File size:       %s (JSON inside: %s)\n", humanBytes(rep.FileBytes), humanBytes(total))
		fmt.Printf("Heap after load: %s\n", humanBytes(int64(rep.HeapAfterLoad)))
	} else {
		fmt.Printf("Store:           PostgreSQL (DATABASE_URL), %s on disk\n", humanBytes(total))
	}
	fmt.Printf("Retention:       %s\n\n", rep.Retention)
	tw := newTable(os.Stdout)
	fmt.Fprintln(tw, "COLLECTION\tITEMS\tSIZE\tSHARE")
	for _, c := range rep.Collections {
		name := c.Name
		if c.Part {
			name = "  " + name
		}
		share := 0.0
		if total > 0 {
			share = 100 * float64(c.Bytes) / float64(total)
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%.1f%%\n", name, c.Items, humanBytes(c.Bytes), share)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if rep.WouldCompact != "" {
		fmt.Printf("\nOn the next start retention would apply: %s\n", rep.WouldCompact)
		if rep.BytesAfter > 0 && rep.BytesAfter < total {
			fmt.Printf("JSON inside the store after retention: %s\n", humanBytes(rep.BytesAfter))
		}
	}
	return nil
}

func totalBytes(stats []db.CollectionStat) int64 {
	var t int64
	for _, s := range stats {
		if !s.Part {
			t += s.Bytes
		}
	}
	return t
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
