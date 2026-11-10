// Command phantomd runs the PHANTOM CALL Phase 1 server.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"phantomcall/server/internal/api"
	"phantomcall/server/internal/store"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address; put a TLS 1.3 reverse proxy in front")
	trustXFF := flag.Bool("trust-forwarded-for", false, "use X-Forwarded-For for rate limiting (only behind your own proxy)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	log.Warn("development storage: all accounts are kept in memory and lost on restart")

	cfg := api.DefaultConfig()
	cfg.TrustForwardedFor = *trustXFF
	srv := api.New(cfg, store.NewMemory(), log, nil)

	hs := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.Maintain(ctx)
			}
		}
	}()

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()

	log.Info("listening", "addr", *addr)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "err", err.Error())
		os.Exit(1)
	}
}
