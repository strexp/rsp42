package cli

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"rsp42/internal/config"
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
