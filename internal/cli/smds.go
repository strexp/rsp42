package cli

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api"
	adminapi "rsp42/internal/api/admin"
	"rsp42/internal/api/es11"
	"rsp42/internal/api/es12"
	"rsp42/internal/api/middleware"
	"rsp42/internal/audit"
	"rsp42/internal/config"
	"rsp42/internal/logging"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

func cmdSMDS(prog string, args []string) int {
	cfgPath, fs := globalFlags(prog+" smds", args)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath, config.RoleDS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s smds: %v\n", prog, err)
		return 1
	}
	if !cfg.SMDS.Enabled {
		fmt.Fprintf(os.Stderr, "%s smds: smds.enabled is false\n", prog)
		return 1
	}
	log := logging.New(cfg.Log.Level, cfg.Log.Format)
	slog.SetDefault(log)

	certs, provider, err := loadCertificates(cfg, log)
	if err != nil {
		log.Error("certificate validation", "err", err)
		return 1
	}

	st, err := store.Open(cfg.SMDS.Store.DSN)
	if err != nil {
		log.Error("open smds store", "err", err)
		return 1
	}
	defer func() { _ = st.Close() }()
	sessions := service.NewSessionService(st.Sessions, provider, cfg.SMDS.EventTTL.Duration())
	eventSvc := service.NewEventService(st.Events, cfg.SMDS.Role, cfg.SMDS.FQDN, cfg.SMDS.EventTTL.Duration())
	eventSvc.Log = log
	startGC(log, func() {
		if n, err := st.Events.GCExpired(time.Now().UTC()); err == nil && n > 0 {
			log.Info("event gc", "removed", n)
		}
	})
	if cfg.SMDS.Cascade.Enabled && cfg.SMDS.Role == "alternative" {
		hc, err := smdsHTTPClient(cfg.SMDS.Cascade)
		if err != nil {
			log.Error("cascade tls", "err", err)
			return 1
		}
		eventSvc.Cascade = service.NewSMDSCClient("https://"+cfg.SMDS.Cascade.RootAddress+":9444", cfg.SMDS.OID, hc)
	}
	ds, err := service.NewDSService(service.DSConfig{
		FQDN: cfg.SMDS.FQDN, OID: cfg.SMDS.OID, Role: cfg.SMDS.Role,
		TransactionIDLen: 16, SessionTTL: cfg.SMDpp.SessionTTL.Duration(),
	}, certs, sessions, eventSvc, log)
	if err != nil {
		log.Error("ds service", "err", err)
		return 1
	}
	es11Handler := es11.New(log, ds)
	es12Handler := es12.New(log, eventSvc)

	var auditLog *audit.Logger
	if cfg.Audit.Enabled {
		auditLog, err = audit.New(st.Audit, cfg.Audit.Sink, cfg.Audit.File)
		if err != nil {
			log.Error("audit", "err", err)
			return 1
		}
		defer func() { _ = auditLog.Close() }()
	}
	wrap := func(h http.Handler, iface string) http.Handler {
		if auditLog == nil {
			return h
		}
		return middleware.Chain(h, middleware.Audit(auditLog, iface))
	}

	apiOpts := api.Options{CORS: cfg.SMDS.Server.CORS.AllowedOrigins}
	es11, err := buildServer(log, "es11", cfg.SMDS.Server.Bind, cfg.SMDS.Server.ES11, wrap(api.NewES11Router(log, es11Handler, apiOpts), "es11"))
	if err != nil {
		log.Error("es11 listener", "err", err)
		return 1
	}
	es12, err := buildServer(log, "es12", cfg.SMDS.Server.Bind, cfg.SMDS.Server.ES12, wrap(api.NewES12Router(log, es12Handler, apiOpts), "es12"))
	if err != nil {
		log.Error("es12 listener", "err", err)
		return 1
	}
	admin, err := buildServer(log, "admin", cfg.SMDS.Server.Bind, cfg.SMDS.Server.Admin,
		api.NewAdminRouter(log, func() bool { return true }, func(r chi.Router) { adminapi.MountDS(r, st.Events) }, apiOpts))
	if err != nil {
		log.Error("admin listener", "err", err)
		return 1
	}

	log.Info("starting SM-DS", "role", cfg.SMDS.Role, "fqdn", cfg.SMDS.FQDN, "es11_port", cfg.SMDS.Server.ES11.Port, "es12_port", cfg.SMDS.Server.ES12.Port)
	return serveAll(log, es11, es12, admin)
}
