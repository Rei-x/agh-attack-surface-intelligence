// Command aegis is the AegisASI single binary: web UI + API server, headless scanner and
// data tools, all sharing one encrypted local store (or PostgreSQL when DATABASE_URL is set).
//
// Build: go build -o aegis ./cmd/server   (see Makefile: make build / make release)
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
)

// Set via -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = ""
	commit  = "dev"
	date    = "unknown"
)

func init() {
	if version != "" {
		api.AppVersion = strings.TrimPrefix(version, "v")
	}
}

func appVersion() string { return api.AppVersion }

const usageText = `AegisASI - cyclic attack surface discovery for large networks (CBI AGH)

Usage:
  aegis <command> [flags]

Commands:
  serve                     Start the web UI + REST API (default http://localhost:8080)
  scan <targets...|-f file> Run a headless scan in the terminal (results land in the same store)
  import <file>             Import CSV / JSON / nmap XML results
  export                    Export the inventory as JSON or CSV
  diff [runA runB]          Compare two scan runs (default: the last two)
  runs                      List recent scan runs
  version                   Print version information

Common flags:
  --data-dir DIR            Data directory (default ~/.aegis, env ASI_DATA_DIR)

Examples:
  aegis serve
  aegis scan 192.168.1.0/24 -p 22,80,443,8080
  aegis scan -f targets.txt --rate 300 --json -o report.json
  aegis import nmap-results.xml
  aegis export --format csv -o inventory.csv
  aegis diff

Run 'aegis <command> --help' for details. Data is stored encrypted (AES-256-GCM) in the
data directory; set DATABASE_URL to use PostgreSQL instead.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "serve", "server":
		err = cmdServe(rest)
	case "scan":
		err = cmdScan(rest)
	case "import":
		err = cmdImport(rest)
	case "export":
		err = cmdExport(rest)
	case "diff":
		err = cmdDiff(rest)
	case "runs", "scans":
		err = cmdRuns(rest)
	case "version", "--version", "-v":
		printVersion(os.Stdout)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usageText)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "aegis: unknown command %q\n\n%s", cmd, usageText)
		return 2
	}
	if err != nil {
		if err == errUsage {
			return 2
		}
		fmt.Fprintf(os.Stderr, "aegis %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "aegis %s (commit %s, built %s, %s, %s/%s)\n",
		appVersion(), commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
