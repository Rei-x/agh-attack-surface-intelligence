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

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/localdata"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/webui"
)

const serveUsage = `Usage: aegis serve [flags]

Starts the AegisASI SOC dashboard (embedded web UI) and REST API.
Without DATABASE_URL, data is kept in an AES-256-GCM encrypted file in the data directory.

Environment (all optional): ASI_LISTEN_ADDR, PORT, DATABASE_URL, ASI_MASTER_KEY,
ASI_JWT_SECRET, ASI_SEED_DEMO (default true), ASI_STATIC_DIR, ASI_DATA_DIR.`

func cmdServe(args []string) error {
	defaultListen := strings.TrimSpace(os.Getenv("ASI_LISTEN_ADDR"))
	if defaultListen == "" {
		defaultListen = ":" + envOrDefault("PORT", "8080")
	}
	fs := newFlagSet("serve", serveUsage)
	listen := fs.String("listen", defaultListen, "listen address (use 127.0.0.1:8080 to restrict to this machine)")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.aegis, env ASI_DATA_DIR)")
	staticDir := fs.String("static-dir", os.Getenv("ASI_STATIC_DIR"), "serve the UI from this directory instead of the embedded build")
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
			return fmt.Errorf("%v\n  another aegis process is using this data directory; stop it first or pass a different --data-dir", err)
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
	runner.StartWindowWatcher(ctx)
	// Recurring scans: start the scheduler here, e.g.
	//   scheduler.Start(ctx, store, runner)

	cfg := api.Config{
		JWTSecret: vault.JWTSecret(os.Getenv("ASI_JWT_SECRET")),
		TokenTTL:  24 * time.Hour,
		SeedDemo:  *seedDemo,
		StaticDir: strings.TrimSpace(*staticDir),
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
	srv := api.NewServer(cfg, store, vault, pipeline, runner, hub)

	url := displayURL(ln.Addr(), *listen)
	if rt.Lock != nil {
		_ = rt.Lock.Update(localdata.LockInfo{PID: os.Getpid(), Command: "serve", URL: url, StartedAt: time.Now()})
	}
	httpServer := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	printServeBanner(rt, url, uiSource, *seedDemo)
	log.Printf("[INFO] AegisASI v%s listening on %s (seed_demo=%v, ui=%s)", api.AppVersion, ln.Addr(), *seedDemo, uiSource)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	}
	log.Printf("[INFO] Shutting down AegisASI server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	return nil
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
	fmt.Fprintf(w, "\n  AegisASI %s - Attack Surface Intelligence\n\n", appVersion())
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
			fmt.Fprintf(w, "  Key:      from ASI_MASTER_KEY\n")
		}
	}
	si := detectScanner()
	fmt.Fprintf(w, "  Scanner:  %s\n", si.Engine())
	if rt.FirstRun && seedDemo {
		fmt.Fprintf(w, "\n  First run - demo accounts created:\n")
		for _, a := range auth.DemoAccounts {
			fmt.Fprintf(w, "    %-9s / %-14s %s\n", a.Username, a.Password, a.RoleName)
		}
		fmt.Fprintf(w, "  (disable with --seed-demo=false or ASI_SEED_DEMO=false)\n")
	} else if seedDemo {
		fmt.Fprintf(w, "  Login:    admin / Admin123! (demo accounts enabled)\n")
	}
	fmt.Fprintf(w, "\n  Press Ctrl+C to stop.\n\n")
}
