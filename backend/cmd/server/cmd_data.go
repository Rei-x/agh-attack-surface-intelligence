package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/localdata"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// scanTypeImportNmap marks runs imported from nmap XML via the CLI.
const scanTypeImportNmap = domain.ScanTypeImportNmap

func lockedHint(err error) error {
	var le *localdata.ErrLocked
	if errors.As(err, &le) {
		return fmt.Errorf("%v\n  stop `aegis serve` first, or upload the file in the web UI (Skaner) / API: POST /api/v1/ingest/import", err)
	}
	return err
}

func warnIfServerRunning(rt *appRuntime) {
	if rt.ServerBusy != nil {
		msg := "note: aegis serve is running on this data dir; showing data from its last autosave (a few seconds old at most)"
		if rt.ServerBusy.URL != "" {
			msg += " - live view: " + rt.ServerBusy.URL
		}
		fmt.Fprintln(os.Stderr, msg)
	}
}

// ---------------------------------------------------------------------------
// import
// ---------------------------------------------------------------------------

const importUsage = `Usage: aegis import <file> [flags]

Imports scan results into the store through the same pipeline as live scans
(diffing, lifecycle tracking, fingerprinting, encryption at rest).
Formats: csv, json (AegisASI / generic host lists) and nmap XML (-oX). Use - for stdin.`

func cmdImport(args []string) error {
	fs := newFlagSet("import", importUsage)
	format := fs.String("format", "", "csv | json | nmap (default: from extension/content)")
	name := fs.String("name", "", "scan run name")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.aegis)")
	verbose := fs.Bool("verbose", false, "show internal log output")
	files, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		fs.Usage()
		return errors.New("exactly one input file is required")
	}
	quietLogs(*verbose)
	path := files[0]
	var data []byte
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return err
	}
	f := strings.ToLower(strings.TrimSpace(*format))
	if f == "" {
		f = detectImportFormat(path, data)
	}

	var obs []domain.ObservedHost
	runType := domain.ScanTypeImportJSON
	rawXML := ""
	switch f {
	case "csv":
		runType = domain.ScanTypeImportCSV
		obs, err = ingest.ParseCSV(bytes.NewReader(data))
	case "json":
		obs, err = ingest.ParseJSON(bytes.NewReader(data))
	case "nmap", "xml":
		runType = scanTypeImportNmap
		rawXML = string(data)
		obs, err = scanner.ParseNmapXML(data)
	default:
		return fmt.Errorf("unsupported format %q (use csv, json or nmap)", f)
	}
	if err != nil {
		return fmt.Errorf("parse %s as %s: %w", path, f, err)
	}

	rt, err := openRuntime(context.Background(), runtimeOptions{DataDir: *dataDir, Command: "import", Seed: true, SeedDemo: seedDemoDefault()})
	if err != nil {
		return lockedHint(err)
	}
	defer rt.Close()

	scanName := strings.TrimSpace(*name)
	if scanName == "" {
		scanName = "Import " + filepath.Base(path) + " " + time.Now().Format("2006-01-02 15:04")
	}
	res, err := rt.newPipeline(nil).ProcessObservations(context.Background(), ingest.IngestRequest{
		RunType:      runType,
		ScanName:     scanName,
		TriggeredBy:  "cli",
		RawNmapXML:   rawXML,
		Observations: obs,
	})
	if err != nil {
		return err
	}
	if rt.FileStore != nil {
		if err := rt.FileStore.Flush(); err != nil {
			return err
		}
	}
	fmt.Printf("Imported %s (%s): %d hosts, %d services, %d changes -> run %s\n",
		path, f, res.HostsProcessed, res.ServicesUpserted, res.ChangesDetected, res.ScanRun.ID)
	return nil
}

func detectImportFormat(path string, data []byte) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv":
		return "csv"
	case ".json":
		return "json"
	case ".xml":
		return "nmap"
	}
	trimmed := bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(trimmed, []byte("<")):
		return "nmap"
	case len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{'):
		return "json"
	}
	return "csv"
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

const exportUsage = `Usage: aegis export [flags]

Exports the current inventory (decrypted) as JSON, CSV, nmap XML, a URL list
(httpx/nuclei/gowitness) or ECS NDJSON (ELK/Splunk). Writes to stdout unless -o is given.`

func cmdExport(args []string) error {
	fs := newFlagSet("export", exportUsage)
	format := fs.String("format", "json", "json | csv | nmap | urls | ecs")
	out := fs.String("o", "", "output file (default stdout)")
	scanID := fs.String("scan", "", "export the inventory snapshot taken at this scan run")
	state := fs.String("state", "", "filter by lifecycle state (NEW, ACTIVE, MISSING, ...)")
	tag := fs.String("tag", "", "filter by tag")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.aegis)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	quietLogs(false)
	f := strings.ToLower(*format)
	switch f {
	case "json", "csv", "nmap", "urls", "ecs":
	default:
		return fmt.Errorf("--format must be json, csv, nmap, urls or ecs")
	}
	ctx := context.Background()
	rt, err := openRuntime(ctx, runtimeOptions{DataDir: *dataDir, Command: "export", ReadOnly: true})
	if err != nil {
		return err
	}
	defer rt.Close()
	warnIfServerRunning(rt)

	var hosts []domain.Host
	if *scanID != "" {
		id, err := resolveRunID(ctx, rt.Store, *scanID)
		if err != nil {
			return err
		}
		hosts, err = rt.Store.GetScanSnapshot(ctx, id)
		if err != nil {
			return fmt.Errorf("no inventory snapshot for run %s: %w", id, err)
		}
		filtered := hosts[:0]
		for _, h := range hosts {
			if *state != "" && !strings.EqualFold(h.LifecycleState, *state) {
				continue
			}
			if *tag != "" && !hasTag(h.Tags, *tag) {
				continue
			}
			filtered = append(filtered, h)
		}
		hosts = filtered
	} else {
		hosts, _, err = rt.Store.ListHosts(ctx, db.HostFilter{State: *state, Tag: *tag})
		if err != nil {
			return err
		}
	}

	var w io.Writer = os.Stdout
	var file *os.File
	if *out != "" {
		file, err = os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		w = file
	}
	switch f {
	case "csv":
		err = ingest.ExportCSV(w, hosts)
	case "nmap":
		err = ingest.ExportNmapXML(w, hosts)
	case "urls":
		err = ingest.ExportURLs(w, hosts)
	case "ecs":
		err = ingest.ExportECS(w, hosts)
	default:
		err = ingest.ExportJSON(w, hosts)
	}
	if err != nil {
		return err
	}
	if file != nil {
		fmt.Fprintf(os.Stderr, "exported %d hosts to %s (%s, plaintext - handle with care)\n", len(hosts), *out, f)
	}
	return nil
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if strings.EqualFold(x, t) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// runs
// ---------------------------------------------------------------------------

func cmdRuns(args []string) error {
	fs := newFlagSet("runs", "Usage: aegis runs [flags]\n\nLists recent scan runs (newest first).")
	limit := fs.Int("n", 20, "number of runs to show")
	jsonOut := fs.Bool("json", false, "JSON output")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.aegis)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	quietLogs(false)
	ctx := context.Background()
	rt, err := openRuntime(ctx, runtimeOptions{DataDir: *dataDir, Command: "runs", ReadOnly: true})
	if err != nil {
		return err
	}
	defer rt.Close()
	warnIfServerRunning(rt)
	runs, err := rt.Store.ListScanRuns(ctx, *limit)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(runs)
	}
	if len(runs) == 0 {
		fmt.Println("No scan runs yet.")
		return nil
	}
	tw := newTable(os.Stdout)
	fmt.Fprintln(tw, "ID\tSTARTED\tTYPE\tSTATUS\tIPS\tLIVE\tSERVICES\tCHANGES\tNAME")
	for _, r := range runs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n", r.ID, r.StartedAt.Local().Format("2006-01-02 15:04"),
			r.RunType, r.Status, r.TotalIPs, r.ActiveHosts, r.ServicesFound, r.ChangesDetected, truncate(r.Name, 50))
	}
	return tw.Flush()
}

// resolveRunID accepts a full ID, a unique ID prefix, or "last"/"latest".
func resolveRunID(ctx context.Context, store db.Store, ref string) (string, error) {
	runs, err := store.ListScanRuns(ctx, 0)
	if err != nil {
		return "", err
	}
	ref = strings.TrimSpace(ref)
	if strings.EqualFold(ref, "last") || strings.EqualFold(ref, "latest") {
		if len(runs) == 0 {
			return "", errors.New("no scan runs yet")
		}
		return runs[0].ID, nil
	}
	var match []string
	for _, r := range runs {
		if r.ID == ref {
			return r.ID, nil
		}
		if strings.HasPrefix(r.ID, ref) {
			match = append(match, r.ID)
		}
	}
	switch len(match) {
	case 1:
		return match[0], nil
	case 0:
		return "", fmt.Errorf("scan run %q not found (see `aegis runs`)", ref)
	}
	return "", fmt.Errorf("scan run prefix %q is ambiguous", ref)
}

// ---------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------

const diffUsage = `Usage: aegis diff [runA runB] [flags]

Compares the inventory snapshots of two scan runs. Without arguments compares the two most
recent completed runs; with one argument compares that run with the completed run before it.
Run IDs may be abbreviated to a unique prefix (see 'aegis runs').`

func cmdDiff(args []string) error {
	fs := newFlagSet("diff", diffUsage)
	jsonOut := fs.Bool("json", false, "JSON output")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.aegis)")
	refs, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(refs) > 2 {
		fs.Usage()
		return errors.New("expected zero, one or two run IDs")
	}
	quietLogs(false)
	ctx := context.Background()
	rt, err := openRuntime(ctx, runtimeOptions{DataDir: *dataDir, Command: "diff", ReadOnly: true})
	if err != nil {
		return err
	}
	defer rt.Close()
	warnIfServerRunning(rt)
	store := rt.Store

	runs, err := store.ListScanRuns(ctx, 0)
	if err != nil {
		return err
	}
	var completed []domain.ScanRun
	for _, r := range runs {
		if r.Status == domain.ScanStatusCompleted {
			completed = append(completed, r)
		}
	}
	var fromID, toID string
	switch len(refs) {
	case 2:
		if fromID, err = resolveRunID(ctx, store, refs[0]); err != nil {
			return err
		}
		if toID, err = resolveRunID(ctx, store, refs[1]); err != nil {
			return err
		}
	case 1:
		if toID, err = resolveRunID(ctx, store, refs[0]); err != nil {
			return err
		}
		found := false
		for _, r := range completed {
			if found {
				fromID = r.ID
				break
			}
			if r.ID == toID {
				found = true
			}
		}
		if fromID == "" {
			return fmt.Errorf("no completed run before %s to compare with", toID)
		}
	default:
		if len(completed) < 2 {
			return fmt.Errorf("need at least two completed scan runs to diff (have %d); run `aegis scan` again later", len(completed))
		}
		toID, fromID = completed[0].ID, completed[1].ID
	}

	fromHosts, err := store.GetScanSnapshot(ctx, fromID)
	if err != nil {
		fromHosts = []domain.Host{}
	}
	toHosts, err := store.GetScanSnapshot(ctx, toID)
	if err != nil {
		toHosts = []domain.Host{}
	}
	toChanges, _ := store.ListChangeEvents(ctx, db.ChangeFilter{ScanRunID: toID, Limit: 500})
	diff := api.ComputeScanDiff(fromID, toID, fromHosts, toHosts, toChanges)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(diff)
	}
	name := func(id string) string {
		for _, r := range runs {
			if r.ID == id {
				return fmt.Sprintf("%s (%s, %s)", r.Name, r.ID[:min(8, len(r.ID))], r.StartedAt.Local().Format("2006-01-02 15:04"))
			}
		}
		return id
	}
	w := os.Stdout
	fmt.Fprintf(w, "DIFF  from %s\n      to   %s\n\n", name(fromID), name(toID))
	s := diff.Summary
	fmt.Fprintf(w, "  +%d new hosts   -%d missing hosts   +%d new services   -%d closed services   ~%d changed services   %d time anomalies\n\n",
		s.NewHostsCount, s.MissingHostsCount, s.NewServicesCount, s.ClosedServicesCount, s.ChangedServicesCount, s.TimeAnomaliesCount)
	for _, h := range diff.NewHosts {
		fmt.Fprintf(w, "  + host     %-16s %s  %s\n", h.IP, dash(h.Hostname), portList(h.Services, 8))
	}
	for _, h := range diff.MissingHosts {
		fmt.Fprintf(w, "  - host     %-16s %s\n", h.IP, dash(h.Hostname))
	}
	for _, sv := range diff.NewServices {
		fmt.Fprintf(w, "  + service  %s:%d/%s %s %s\n", sv.HostIP, sv.Port, sv.Protocol, sv.ServiceName, strings.TrimSpace(sv.Product+" "+sv.Version))
	}
	for _, sv := range diff.ClosedServices {
		fmt.Fprintf(w, "  - service  %s:%d/%s %s\n", sv.HostIP, sv.Port, sv.Protocol, sv.ServiceName)
	}
	for _, c := range diff.ChangedServices {
		fmt.Fprintf(w, "  ~ service  %s:%d/%s %s\n", c.HostIP, c.Port, c.Protocol, truncate(c.Summary, 100))
	}
	for _, ev := range diff.TimeAnomalies {
		fmt.Fprintf(w, "  ! anomaly  %s %s\n", ev.HostIP, truncate(ev.Summary, 100))
	}
	if s.NewHostsCount+s.MissingHostsCount+s.NewServicesCount+s.ClosedServicesCount+s.ChangedServicesCount+s.TimeAnomaliesCount == 0 {
		fmt.Fprintln(w, "  no differences")
	}
	return nil
}
