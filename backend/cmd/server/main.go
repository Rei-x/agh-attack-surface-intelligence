package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scheduler"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listenAddr := strings.TrimSpace(os.Getenv("ASI_LISTEN_ADDR"))
	if listenAddr == "" {
		listenAddr = ":" + envOrDefault("PORT", "8080")
	}
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	masterKey := os.Getenv("ASI_MASTER_KEY")
	jwtSecretOverride := os.Getenv("ASI_JWT_SECRET")
	seedDemo := strings.EqualFold(envOrDefault("ASI_SEED_DEMO", "true"), "true")
	staticDir := os.Getenv("ASI_STATIC_DIR")

	vault, err := crypto.NewVault(masterKey)
	if err != nil {
		log.Fatalf("fatal: initialize encryption vault: %v", err)
	}
	log.Printf("[INFO] Encryption vault active (algo=%s, kid=%s)", vault.Status().Algorithm, vault.ActiveKID())

	var store db.Store
	if dbURL != "" {
		pgStore, err := db.NewPostgresStore(ctx, dbURL, vault)
		if err != nil {
			log.Fatalf("fatal: connect PostgreSQL: %v", err)
		}
		store = pgStore
		log.Printf("[INFO] Connected to PostgreSQL with automatic migrations applied")
	} else {
		store = db.NewMemoryStore(vault)
		log.Printf("[WARN] DATABASE_URL is empty; running with AES-256-GCM encrypted in-memory store")
	}
	defer store.Close()

	if err := db.SeedDefaults(ctx, store, seedDemo); err != nil {
		log.Fatalf("fatal: seed default roles/users: %v", err)
	}

	hub := api.NewSSEHub()
	analyzer := NewIntelligenceAnalyzer()
	pipeline := ingest.NewPipeline(store, analyzer, hub.Publish)
	runner := NewLiveScanRunner(store, pipeline, hub)
	runner.StartWindowWatcher(ctx)
	scheduler.Start(ctx, store, runner) // recurring scans from ScanProfile.ScheduleCron

	srv := api.NewServer(api.Config{
		JWTSecret: vault.JWTSecret(jwtSecretOverride),
		TokenTTL:  24 * time.Hour,
		SeedDemo:  seedDemo,
		StaticDir: staticDir,
	}, store, vault, pipeline, runner, hub)

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("[INFO] AegisASI v%s listening on %s (seed_demo=%v, static_dir=%q)", api.AppVersion, listenAddr, seedDemo, staticDir)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("fatal: http server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("[INFO] Shutting down AegisASI server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
