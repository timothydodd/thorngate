package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"thorngate/internal/activity"
	"thorngate/internal/admin"
	"thorngate/internal/archive"
	"thorngate/internal/auth"
	"thorngate/internal/blacklist"
	"thorngate/internal/config"
	"thorngate/internal/feeds"
	"thorngate/internal/proxy"
)

// version is stamped at build time (-ldflags "-X main.version=v1.2.3"); see
// buildVersion for the fallback.
var version = ""

// buildVersion reports the running version: the stamped one, else the module
// version or VCS revision Go recorded in the binary, else "dev".
func buildVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 {
			return "dev-" + s.Value[:7]
		}
	}
	return "dev"
}

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	ver := buildVersion()
	if *showVersion {
		fmt.Println(ver)
		return
	}

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

	// Activity log: bans, feed updates, reloads, logins, start/stop. A nil log
	// (disabled) records nothing.
	var act *activity.Log
	if cfg.Activity.Enabled() {
		if act, err = activity.New(cfg.Activity.MaxEvents, cfg.Activity.File); err != nil {
			log.Fatalf("activity: %v", err)
		}
		waf.SetActivity(act)
	}
	act.Addf(activity.System, activity.Info, "", "system", "thorngate %s started (%d bans loaded)", ver, bl.Count())

	// Published IP-range feeds (e.g. search crawlers) merged into the
	// whitelist, each as its own group refreshed on its interval.
	feedMgr := feeds.New(bl, act)
	feedMgr.Apply(cfg.WhitelistFeeds)

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
					act.Addf(activity.System, activity.Error, "", "system", "Saving stats to %s failed: %v", statsFile, err)
				}
			}
		}()
	}

	// Optional on-disk request history, for searching well past what the
	// in-memory feed holds.
	var arch *archive.Archive
	if waf.Stats() != nil && cfg.Stats.Archive != nil {
		a := cfg.Stats.Archive
		if arch, err = archive.Open(a.Dir, a.Retention()); err != nil {
			log.Fatalf("archive: %v", err)
		}
		waf.SetArchive(arch)
		log.Printf("archive: request history in %s, kept %d days", a.Dir, a.RetentionDays)
	}

	// Live config reload (SIGHUP or the admin portal). Settings that need a
	// restart are compared against the config the process started with, so
	// they keep being reported until it restarts.
	var (
		cfgMu   sync.Mutex
		current = cfg
	)
	reload := func() ([]string, error) {
		cfgMu.Lock()
		defer cfgMu.Unlock()
		next, err := config.Load(*configPath)
		if err != nil {
			act.Addf(activity.Config, activity.Error, "", "system", "Config reload failed, kept the running config: %v", err)
			return nil, err
		}
		waf.Reload(next)
		feedMgr.Apply(next.WhitelistFeeds)
		current = next
		restart := next.ReloadBlocked(cfg)
		log.Printf("config reloaded (honeypots=%d, whitelist=%d)", len(next.Honeypots), len(next.Whitelist))
		if len(restart) > 0 {
			log.Printf("config: changes to %s take effect on restart", strings.Join(restart, ", "))
			act.Addf(activity.Config, activity.Warn, "", "system",
				"Config reloaded; changes to %s take effect on restart", strings.Join(restart, ", "))
		} else {
			act.Addf(activity.Config, activity.Info, "", "system", "Config reloaded (%d honeypots, %d whitelist entries, %d feeds)",
				len(next.Honeypots), len(next.Whitelist), len(next.WhitelistFeeds))
		}
		return restart, nil
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if _, err := reload(); err != nil {
				log.Printf("config: reload failed, keeping the running config: %v", err)
			}
		}
	}()

	// Drop expired temp-bans for IPs that never come back, so they don't linger
	// in the file or the admin list.
	go func() {
		for range time.Tick(time.Minute) {
			if n := bl.Sweep(); n > 0 {
				log.Printf("blacklist: swept %d expired ban(s)", n)
				act.Addf(activity.Unban, activity.Info, "", "system", "%d expired temporary ban(s) removed", n)
			}
		}
	}()

	// Not an http.ServeMux: it answers unclean paths ("//x", "/a/../x") with a
	// 301 before any handler runs, so a blacklisted client would get a response
	// instead of being denied.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Liveness/readiness probe — not proxied, not honeypot-able.
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		waf.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Tarpitted connections are held for up to tarpit_duration; let them go as
	// soon as shutdown starts so they don't outlast its timeout.
	srv.RegisterOnShutdown(waf.ReleaseTarpits)

	go func() {
		log.Printf("thorngate %s listening on %s (blacklisted=%d, routes=%d)",
			ver, cfg.Listen, bl.Count(), len(cfg.Routes))
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
			Addr: cfg.Admin.Listen,
			Handler: admin.Handler(admin.Options{
				Blacklist: bl,
				Stats:     waf.Stats(),
				Archive:   arch,
				Auth:      au,
				APIToken:  cfg.Admin.Token,
				Whitelist: func() []config.WhitelistEntry {
					cfgMu.Lock()
					defer cfgMu.Unlock()
					return current.Whitelist
				},
				WhitelistFeeds: feedMgr.Statuses,
				Reload:         reload,
				Tarpitting:     waf.Tarpitting,
				Metrics:        !cfg.Admin.DisableMetrics,
				Activity:       act,
				Version:        ver,
			}),
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
	act.Addf(activity.System, activity.Info, "", "system", "thorngate %s shutting down", ver)
	feedMgr.Stop()
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
	if arch != nil {
		arch.Close()
	}
	act.Close()
}
