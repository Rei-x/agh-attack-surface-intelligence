package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/localdata"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scheduler"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/webui"
)

const serveUsage = `Usage: dzieciol serve [flags]

Starts the Dzięcioł SOC dashboard (embedded web UI) and REST API.
Without DATABASE_URL, data is kept in an AES-256-GCM encrypted file in the data directory.

Environment (all optional): DZIECIOL_LISTEN_ADDR, PORT, DATABASE_URL, DZIECIOL_MASTER_KEY,
DZIECIOL_JWT_SECRET, DZIECIOL_SEED_DEMO (default true), DZIECIOL_STATIC_DIR, DZIECIOL_DATA_DIR.`

func cmdServe(args []string) error {
	defaultListen := strings.TrimSpace(os.Getenv("DZIECIOL_LISTEN_ADDR"))
	if defaultListen == "" {
		defaultListen = ":" + envOrDefault("PORT", "8080")
	}
	fs := newFlagSet("serve", serveUsage)
	listen := fs.String("listen", defaultListen, "listen address (use 127.0.0.1:8080 to restrict to this machine)")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.dzieciol, env DZIECIOL_DATA_DIR)")
	staticDir := fs.String("static-dir", os.Getenv("DZIECIOL_STATIC_DIR"), "serve the UI from this directory instead of the embedded build")
	seedDemo := fs.Bool("seed-demo", seedDemoDefault(), "create demo accounts (admin/operator/analyst/viewer)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Bind first so a busy port fails fast, before touching the store.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w (port busy? try --listen :8081)", *listen, err)
	}
	defer ln.Close()

	rt, err := openRuntime(ctx, runtimeOptions{
		DataDir: *dataDir, Command: "serve", Seed: true, SeedDemo: *seedDemo,
	})
	if err != nil {
		var le *localdata.ErrLocked
		if errors.As(err, &le) {
			return fmt.Errorf("%w\n  another dzieciol process is using this data directory; stop it first or pass a different --data-dir", err)
		}
		return err
	}
	defer rt.Close()
	vault, store := rt.Vault, rt.Store
	log.Printf("[INFO] Encryption vault active (algo=%s, kid=%s, key=%s)", vault.Status().Algorithm, vault.ActiveKID(), rt.KeySource)
	log.Printf("[INFO] Store backend: %s", rt.storeDescription())

	hub := api.NewSSEHub()
	pipeline := rt.newPipeline(hub)
	runner := NewLiveScanRunner(store, pipeline, hub)
	// Remote scanning agents (dzieciol agent): runs of agent-bound profiles are queued for the
	// agent and ingested through the same pipeline when it uploads results.
	agents := agenthub.New(store, pipeline, hub.Publish, agenthub.Options{
		OfflineAfter:   envDuration("DZIECIOL_AGENT_OFFLINE_AFTER", 90*time.Second),
		OnRunCompleted: func(runID string) { runner.autoPushDefectDojo(context.Background(), runID) },
		TrackedHosts:   runner.collectTrackedHostIPs,
	})
	runner.isRemoteRun = agents.IsAgentRun
	agents.StartSweeper(ctx)
	dispatch := api.NewAgentAwareRunner(runner, agents)
	runner.StartWindowWatcher(ctx)
	scheduler.Start(ctx, store, dispatch) // recurring scans from ScanProfile.ScheduleCron

	cfg := api.Config{
		JWTSecret: vault.JWTSecret(os.Getenv("DZIECIOL_JWT_SECRET")),
		TokenTTL:  24 * time.Hour,
		SeedDemo:  *seedDemo,
		StaticDir: strings.TrimSpace(*staticDir),
		// Comma-separated extra origins allowed to call the API cross-origin (default: none,
		// the bundled UI is same-origin).
		AllowedOrigin: os.Getenv("DZIECIOL_CORS_ORIGINS"),
		Agents:        agents,
	}
	uiSource := "embedded"
	if cfg.StaticDir != "" {
		uiSource = cfg.StaticDir
	} else {
		cfg.StaticFS = webui.FS()
		cfg.StaticFallback = webui.PlaceholderHTML
		if !webui.Available() {
			uiSource = "placeholder (binary built without UI - run `make build`)"
		}
	}
	srv := api.NewServer(cfg, store, vault, pipeline, dispatch, hub)

	url := displayURL(ln.Addr(), *listen)
	if rt.Lock != nil {
		_ = rt.Lock.Update(localdata.LockInfo{PID: os.Getpid(), Command: "serve", URL: url, StartedAt: time.Now()})
	}
	// Timeouts against slow-client (slowloris) exhaustion. No WriteTimeout: the SSE stream and
	// large exports are long-lived responses by design.
	httpServer := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // a 64 MB import over a slow VPN
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	printServeBanner(rt, url, uiSource, *seedDemo)
	log.Printf("[INFO] Dzięcioł v%s listening on %s (seed_demo=%v, ui=%s)", api.AppVersion, ln.Addr(), *seedDemo, uiSource)
	if *seedDemo {
		log.Printf("[WARN] DEMO MODE: demo accounts with publicly known passwords are enabled (set DZIECIOL_SEED_DEMO=false outside a lab demo)")
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	}
	log.Printf("[INFO] Shutting down Dzięcioł server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	return nil
}

// envDuration reads a Go duration ("90s", "5m") from the environment.
func envDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		log.Printf("[WARN] ignoring invalid %s=%q (want a duration like 90s)", key, v)
	}
	return def
}

func displayURL(addr net.Addr, listen string) string {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "http://" + listen
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func printServeBanner(rt *appRuntime, url, uiSource string, seedDemo bool) {
	w := os.Stderr
	fmt.Fprintln(w)
	printWoodpecker(w, "Dzięcioł "+appVersion(), "Attack Surface Intelligence - CBI AGH")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Open:     %s\n", url)
	fmt.Fprintf(w, "  UI:       %s\n", uiSource)
	fmt.Fprintf(w, "  Store:    %s\n", rt.storeDescription())
	if rt.Dir != nil {
		switch rt.KeySource {
		case localdata.KeyFileGenerated:
			fmt.Fprintf(w, "  Key:      %s (generated now, 0600 - back it up; without it the data cannot be decrypted)\n", rt.Dir.KeyPath())
		case localdata.KeyFromFile:
			fmt.Fprintf(w, "  Key:      %s\n", rt.Dir.KeyPath())
		default:
			fmt.Fprintf(w, "  Key:      from DZIECIOL_MASTER_KEY\n")
		}
	}
	si := detectScanner()
	fmt.Fprintf(w, "  Scanner:  %s\n", si.Engine())
	if rt.FirstRun && seedDemo {
		fmt.Fprintf(w, "\n  First run - demo accounts created:\n")
		for _, a := range auth.DemoAccounts {
			fmt.Fprintf(w, "    %-9s / %-14s %s\n", a.Username, a.Password, a.RoleName)
		}
		fmt.Fprintf(w, "  (disable with --seed-demo=false or DZIECIOL_SEED_DEMO=false)\n")
	} else if seedDemo {
		fmt.Fprintf(w, "  Login:    admin / Admin123! (demo accounts enabled)\n")
	}
	if seedDemo {
		fmt.Fprintf(w, "\n  WARNING: DEMO MODE - accounts with publicly known passwords are active.\n")
		fmt.Fprintf(w, "  For a lab demo only. For real use start with DZIECIOL_SEED_DEMO=false (or --seed-demo=false):\n")
		fmt.Fprintf(w, "  demo accounts are then disabled and a random admin password is printed once.\n")
	}
	fmt.Fprintf(w, "\n  Press Ctrl+C to stop.\n\n")
}
