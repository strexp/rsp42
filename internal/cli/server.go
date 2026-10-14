package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"rsp42/internal/cert"
	"rsp42/internal/config"
	"rsp42/internal/kms"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 15 * time.Second
	// adminBodyLimit bounds management-API request bodies. It is larger than the
	// protocol default because it carries SAIP template uploads and inventory
	// CSV imports, which are not SGP.22 messages.
	adminBodyLimit = 8 << 20
)

type namedServer struct {
	name string
	srv  *http.Server
	ln   net.Listener
}

func buildServer(log *slog.Logger, name, bind string, l config.ListenerCfg, h http.Handler) (namedServer, error) {
	addr := net.JoinHostPort(bind, fmt.Sprintf("%d", l.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return namedServer{}, fmt.Errorf("%s: listen %s: %w", name, addr, err)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	if l.TLS.Enabled {
		tc, err := buildTLSConfig(l.TLS)
		if err != nil {
			_ = ln.Close()
			return namedServer{}, fmt.Errorf("%s: %w", name, err)
		}
		srv.TLSConfig = tc
		ln = tls.NewListener(ln, tc)
	}
	return namedServer{name: name, srv: srv, ln: ln}, nil
}

func buildTLSConfig(l config.TLSCfg) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(l.CertFile, l.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls cert: %w", err)
	}
	min := uint16(tls.VersionTLS12)
	switch l.MinVersion {
	case "", "1.2":
		min = tls.VersionTLS12
	case "1.3":
		min = tls.VersionTLS13
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   min,
	}
	if l.ClientCAFile != "" {
		pool, err := loadCAPool(l.ClientCAFile)
		if err != nil {
			return nil, err
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tc, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		// Try DER.
		if parsed, err := x509.ParseCertificate(pem); err == nil {
			pool.AddCert(parsed)
			return pool, nil
		}
		return nil, fmt.Errorf("ca %s: no certificates found", path)
	}
	return pool, nil
}

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

// mtlsClient builds an mTLS HTTP client from a TLS config.
func mtlsClient(c config.TLSCfg) (*http.Client, error) {
	crt, err := tls.LoadX509KeyPair(c.ClientCertFile, c.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	pool, err := loadCAPool(c.CAFile)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{Certificates: []tls.Certificate{crt}, RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 30 * time.Second}, nil
}

// smdsHTTPClient builds an mTLS HTTP client for the ES15 cascade to the Root
// SM-DS.
func smdsHTTPClient(c config.CascadeConfig) (*http.Client, error) {
	crt, err := tls.LoadX509KeyPair(c.TLS.ClientCertFile, c.TLS.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("cascade client cert: %w", err)
	}
	pool, err := loadCAPool(c.TLS.CAFile)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{crt},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 30 * time.Second}, nil
}

// loadCertificates builds the KMS provider and validates the configured
// certificate material at startup.
func loadCertificates(cfg *config.Config, log *slog.Logger) (*cert.Manager, *kms.FileProvider, error) {
	provider, err := newKMSProvider(&cfg.KMS)
	if err != nil {
		return nil, nil, err
	}
	m, err := cert.LoadSets(cert.OptionsListFromConfig(cfg), provider)
	if err != nil {
		return nil, nil, err
	}
	for _, w := range m.Warnings() {
		log.Warn("certificate", "detail", w)
	}
	return m, provider, nil
}

// newKMSProvider builds the software KMS from the configured key source
// (kek_hex preferred, else kek_file).
func newKMSProvider(cfg *config.KMSConfig) (*kms.FileProvider, error) {
	if cfg.KEKHex != "" {
		return kms.NewFileProviderFromHex(cfg.KEKHex)
	}
	return kms.NewFileProvider(cfg.KEKFile)
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
	// return http.ErrServerClosed, so the group finishes without an error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case sig := <-sigCh:
			log.Info("shutting down", "signal", sig.String())
			shutdown(log, servers)
		case <-ctx.Done():
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
