package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"thorngate/internal/admin"
	"thorngate/internal/auth"
	"thorngate/internal/blacklist"
	"thorngate/internal/config"
	"thorngate/internal/proxy"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	bl, err := blacklist.New(cfg.BlacklistFile, cfg.WhitelistSpecs())
	if err != nil {
		log.Fatalf("blacklist: %v", err)
	}

	waf, err := proxy.New(cfg, bl)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}

	// Optional stats persistence: pull the previous run's counters and recent
	// requests back in, then re-save on an interval (and once more on shutdown).
	statsFile := ""
	if st := waf.Stats(); st != nil && cfg.Stats.File != "" {
		statsFile = cfg.Stats.File
		if err := st.Load(statsFile); err != nil {
			log.Printf("stats: load %s: %v (starting fresh)", statsFile, err)
		}
		go func() {
			for range time.Tick(cfg.Stats.SaveIntervalDur()) {
				if err := st.Save(statsFile); err != nil {
					log.Printf("stats: save %s: %v", statsFile, err)
				}
			}
		}()
	}

	mux := http.NewServeMux()
	// Liveness/readiness probe — not proxied, not honeypot-able.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/", waf)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("thorngate listening on %s (blacklisted=%d, routes=%d)",
			cfg.Listen, bl.Count(), len(cfg.Routes))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	// Optional admin API + web page on a separate, cluster-internal port.
	var adminSrv *http.Server
	if cfg.Admin != nil && cfg.Admin.Enabled {
		au, err := auth.New(cfg.Admin.CredentialsFile)
		if err != nil {
			log.Fatalf("admin credentials: %v", err)
		}
		adminSrv = &http.Server{
			Addr:              cfg.Admin.Listen,
			Handler:           admin.Handler(bl, waf.Stats(), au, cfg.Admin.Token),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			log.Printf("admin listening on %s", cfg.Admin.Listen)
			if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("admin server: %v", err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if adminSrv != nil {
		_ = adminSrv.Shutdown(ctx)
	}
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	if statsFile != "" {
		if err := waf.Stats().Save(statsFile); err != nil {
			log.Printf("stats: final save %s: %v", statsFile, err)
		}
	}
}
