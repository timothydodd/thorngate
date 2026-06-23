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

	bl, err := blacklist.New(cfg.BlacklistFile, cfg.Whitelist)
	if err != nil {
		log.Fatalf("blacklist: %v", err)
	}

	waf, err := proxy.New(cfg, bl)
	if err != nil {
		log.Fatalf("proxy: %v", err)
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
		adminSrv = &http.Server{
			Addr:              cfg.Admin.Listen,
			Handler:           admin.Handler(bl, waf.Stats(), cfg.Admin.Token),
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
}
