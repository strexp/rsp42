package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

// startGC runs fn periodically until the process exits.
func startGC(log *slog.Logger, fn func()) {
	startTicker(10*time.Minute, fn)
}

// startTicker runs fn every interval until the process exits.
func startTicker(interval time.Duration, fn func()) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			fn()
		}
	}()
}

func serveAll(log *slog.Logger, servers ...namedServer) int {
	g, ctx := errgroup.WithContext(context.Background())
	for _, ns := range servers {
		g.Go(func() error {
			if err := ns.srv.Serve(ns.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("%s: %w", ns.name, err)
			}
			return nil
		})
		log.Info("listening", "server", ns.name, "addr", ns.ln.Addr().String())
	}

	// A SIGINT/SIGTERM shuts every listener down; the Serve goroutines then
	// return http.ErrServerClosed, so the group finishes without an error. The
	// loop keeps listening: a second signal (e.g. a shutdown that cannot finish
	// within the timeout) forces the process down instead of being ignored, so
	// the process is never unkillable short of SIGKILL.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		forced := false
		for {
			select {
			case sig := <-sigCh:
				if forced {
					log.Error("second signal, forcing exit", "signal", sig.String())
					os.Exit(1)
				}
				forced = true
				log.Info("shutting down", "signal", sig.String())
				shutdown(log, servers)
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := g.Wait(); err != nil {
		log.Error("server failed", "err", err)
		shutdown(log, servers)
		return 1
	}
	return 0
}

func shutdown(log *slog.Logger, servers []namedServer) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, ns := range servers {
		if err := ns.srv.Shutdown(ctx); err != nil {
			log.Warn("shutdown", "server", ns.name, "err", err)
		}
	}
}
