package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/localdata"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/screenshot"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb"
)

var errUsage = errors.New("usage")

// parseInterspersed parses flags that may appear before, between or after positional
// arguments (e.g. `dzieciol scan 10.0.0.0/24 -p 22,80`), which stdlib flag does not do alone.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, errUsage
			}
			return nil, errUsage
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if rest[0] == "--" {
			return append(positional, rest[1:]...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func newFlagSet(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\nFlags:\n", strings.TrimSpace(usage))
		fs.PrintDefaults()
	}
	return fs
}

// runtimeOptions selects how the shared store is opened.
type runtimeOptions struct {
	DataDir  string
	Command  string // recorded in the lock file
	ReadOnly bool   // export/diff/runs: no lock, never write
	Seed     bool   // run SeedDefaults (roles, demo users, starter profiles)
	SeedDemo bool
}

// appRuntime is an opened store + vault, shared by all subcommands.
type appRuntime struct {
	Dir        *localdata.Dir
	Vault      *crypto.Vault
	Store      db.Store
	FileStore  *db.FileStore // nil in PostgreSQL mode
	Lock       *localdata.Lock
	KeySource  localdata.KeySource
	Postgres   bool
	Retention  db.RetentionPolicy // history limits (DZIECIOL_RETENTION_*), applied on open and after every ingest
	FirstRun   bool               // no users existed before seeding (fresh installation)
	ServerBusy *localdata.LockInfo

	shotsOnce sync.Once
	shots     *screenshot.Store // see screenshots.go
}

func openRuntime(ctx context.Context, opts runtimeOptions) (*appRuntime, error) {
	dirPath, err := localdata.DefaultDir(opts.DataDir)
	if err != nil {
		return nil, err
	}
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	rt := &appRuntime{Postgres: dbURL != "", Retention: db.RetentionFromEnv()}

	// The data dir holds master.key even in PostgreSQL mode (unless DZIECIOL_MASTER_KEY is set).
	dir, err := localdata.Open(dirPath)
	if err != nil {
		if !rt.Postgres || os.Getenv("DZIECIOL_MASTER_KEY") == "" {
			return nil, err
		}
	}
	rt.Dir = dir
	if dir != nil {
		vulndb.SetOverlayPath(vulndbOverlayPath(dir.Path)) // `dzieciol vulndb update` output
	}

	if !rt.Postgres && opts.ReadOnly && !dir.StoreExists() {
		return nil, fmt.Errorf("no Dzięcioł data in %s yet - run `dzieciol scan ...` or `dzieciol serve` first", dir.Path)
	}

	// Exclusive lock for writers on the local file store (PostgreSQL handles concurrency itself).
	if !rt.Postgres && !opts.ReadOnly {
		lock, err := dir.Acquire(localdata.LockInfo{Command: opts.Command})
		if err != nil {
			return nil, err
		}
		rt.Lock = lock
	}
	if !rt.Postgres && opts.ReadOnly {
		// Report (but tolerate) a running server: we read its last autosave.
		if probe, err := dir.Acquire(localdata.LockInfo{Command: opts.Command}); err == nil {
			probe.Release()
		} else {
			var le *localdata.ErrLocked
			if errors.As(err, &le) {
				rt.ServerBusy = le.Holder
				if rt.ServerBusy == nil {
					rt.ServerBusy = &localdata.LockInfo{}
				}
			}
		}
	}

	fail := func(err error) (*appRuntime, error) {
		rt.Close()
		return nil, err
	}

	var masterKey string
	if dir != nil {
		masterKey, rt.KeySource, err = dir.MasterKey()
		if err != nil {
			return fail(err)
		}
	} else {
		masterKey, rt.KeySource = os.Getenv("DZIECIOL_MASTER_KEY"), localdata.KeyFromEnv
	}
	rt.Vault, err = crypto.NewVault(masterKey)
	if err != nil {
		return fail(fmt.Errorf("initialize encryption vault: %w", err))
	}

	if rt.Postgres {
		pg, err := db.NewPostgresStore(ctx, dbURL, rt.Vault)
		if err != nil {
			return fail(fmt.Errorf("connect PostgreSQL: %w", err))
		}
		rt.Store = pg
		if !opts.ReadOnly {
			cctx, cancelCompact := context.WithTimeout(ctx, 2*time.Minute)
			db.CompactAndLog(cctx, pg, rt.Retention, "startup")
			cancelCompact()
		}
	} else {
		// Retention runs on load (writable stores) and the compacted file is written back
		// before the store is used.
		fsStore, err := db.OpenFileStore(dir.StorePath(), rt.Vault, db.FileStoreOptions{ReadOnly: opts.ReadOnly, Retention: &rt.Retention})
		if err != nil {
			return fail(err)
		}
		rt.FileStore = fsStore
		rt.Store = fsStore
	}

	if opts.Seed && !opts.ReadOnly {
		users, _ := rt.Store.ListUsers(ctx)
		rt.FirstRun = len(users) == 0
		if err := db.SeedDefaults(ctx, rt.Store, opts.SeedDemo); err != nil {
			return fail(fmt.Errorf("seed defaults: %w", err))
		}
		if opts.SeedDemo {
			seedDemoPolicies(ctx, rt.Store)
		}
		boot, err := secureAccounts(ctx, rt.Store, opts.SeedDemo)
		if err != nil {
			return fail(fmt.Errorf("secure accounts: %w", err))
		}
		printBootstrap(os.Stderr, boot)
	}
	return rt, nil
}

// Close flushes the store and releases the data-dir lock.
func (rt *appRuntime) Close() {
	if rt == nil {
		return
	}
	if rt.Store != nil {
		rt.Store.Close()
		rt.Store = nil
	}
	if rt.Lock != nil {
		rt.Lock.Release()
		rt.Lock = nil
	}
}

func (rt *appRuntime) storeDescription() string {
	if rt.Postgres {
		return "PostgreSQL (DATABASE_URL)"
	}
	return rt.FileStore.Path() + " (AES-256-GCM)"
}

func (rt *appRuntime) newPipeline(hub *api.SSEHub) *ingest.Pipeline {
	var emit func(domain.LiveEvent)
	if hub != nil {
		emit = hub.Publish
	}
	p := ingest.NewPipeline(rt.Store, NewIntelligenceAnalyzer(), emit)
	p.SetRetention(rt.Retention)
	rt.attachScreenshots(p, emit)
	return p
}

// printBootstrap shows a generated admin password exactly once (terminal only, not the log).
func printBootstrap(w io.Writer, b bootstrapResult) {
	if len(b.DemoDeactivated) > 0 {
		fmt.Fprintf(w, "\n  Demo mode is off: deactivated demo accounts still using their public passwords: %s\n",
			strings.Join(b.DemoDeactivated, ", "))
	}
	if b.AdminPassword != "" {
		fmt.Fprintf(w, "\n  ============================================================\n")
		fmt.Fprintf(w, "  Administrator account created:  admin / %s\n", b.AdminPassword)
		fmt.Fprintf(w, "  This password is shown ONCE. Log in and change it in Admin > Users.\n")
		fmt.Fprintf(w, "  ============================================================\n\n")
	} else if b.AdminCreated {
		fmt.Fprintf(w, "\n  Administrator account 'admin' created with the password from DZIECIOL_ADMIN_PASSWORD.\n\n")
	}
}

func seedDemoDefault() bool {
	return strings.EqualFold(envOrDefault("DZIECIOL_SEED_DEMO", "true"), "true")
}

// quietLogs silences the standard logger (used by terminal-oriented commands) unless verbose.
func quietLogs(verbose bool) {
	if verbose {
		log.SetOutput(os.Stderr)
		return
	}
	log.SetOutput(io.Discard)
}
