package cli

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api"
	"rsp42/internal/api/dsadmin"
	"rsp42/internal/api/es11"
	"rsp42/internal/api/es12"
	"rsp42/internal/audit"
	"rsp42/internal/config"
	"rsp42/internal/logging"
	"rsp42/internal/metrics"
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
	// The session store fallback TTL is the SM-DS session TTL, not the event
	// TTL: the two govern different lifetimes.
	sessions := service.NewSessionService(st.Sessions, provider, cfg.SMDS.SessionTTL.Duration())
	eventSvc := service.NewEventService(st.Events, cfg.SMDS.Role, cfg.SMDS.FQDN, cfg.SMDS.EventTTL.Duration())
	eventSvc.Log = log
	reg := newDSMetricsRegistry()
	startGC(log, func() {
		if n, err := st.Events.GCExpired(time.Now().UTC()); err == nil {
			if n > 0 {
				log.Info("event gc", "removed", n)
			}
			reg.Add("rsp42_smds_event_gc_total", nil, float64(n))
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
		TransactionIDLen: 16, SessionTTL: cfg.SMDS.SessionTTL.Duration(),
	}, certs, sessions, eventSvc, log)
	if err != nil {
		log.Error("ds service", "err", err)
		return 1
	}
	es11Handler := es11.New(log, ds)
	es12Handler := es12.New(log, eventSvc)
	es12Handler.Tenants = service.NewTenantResolver(requesterPairs(cfg.SMDS.ES12.RequesterTenants))
	es12Handler.Audit = st.Audit

	var auditLog *audit.Logger
	if cfg.Audit.Enabled {
		auditLog, err = audit.New(st.Audit, cfg.Audit.Sink, cfg.Audit.File)
		if err != nil {
			log.Error("audit", "err", err)
			return 1
		}
		defer func() { _ = auditLog.Close() }()
	}
	// Audit is applied inside the router (api.Options.Audit) so that it runs
	// after middleware.RequestScope and can attribute every row to the request
	// scope. The admin router ignores it and audits its own writes.
	apiOpts := api.Options{CORS: cfg.SMDS.Server.CORS.AllowedOrigins, Audit: auditLog}
	adminOpts := api.Options{CORS: cfg.SMDS.Server.CORS.AllowedOrigins, BodyLimit: adminBodyLimit}
	es11, err := buildServer(log, "es11", cfg.SMDS.Server.Bind, cfg.SMDS.Server.ES11, api.NewES11Router(log, es11Handler, apiOpts))
	if err != nil {
		log.Error("es11 listener", "err", err)
		return 1
	}
	es12, err := buildServer(log, "es12", cfg.SMDS.Server.Bind, cfg.SMDS.Server.ES12, api.NewES12Router(log, es12Handler, apiOpts))
	if err != nil {
		log.Error("es12 listener", "err", err)
		return 1
	}
	dsAdmin := dsadmin.Config{Events: st.Events, Audit: st.Audit, DefaultTTL: cfg.SMDS.EventTTL.Duration()}
	if err := dsAdmin.Validate(); err != nil {
		log.Error("ds admin", "err", err)
		return 1
	}
	admin, err := buildServer(log, "admin", cfg.SMDS.Server.Bind, cfg.SMDS.Server.Admin,
		api.NewAdminRouter(log, func() bool { return true }, func(r chi.Router) {
			dsadmin.Mount(r, dsAdmin)
			r.Get("/metrics", metrics.Handler(reg, eventCollector(st.Events)))
		}, adminOpts))
	if err != nil {
		log.Error("admin listener", "err", err)
		return 1
	}

	log.Info("starting SM-DS", "role", cfg.SMDS.Role, "fqdn", cfg.SMDS.FQDN, "es11_port", cfg.SMDS.Server.ES11.Port, "es12_port", cfg.SMDS.Server.ES12.Port)
	return serveAll(log, es11, es12, admin)
}

// newDSMetricsRegistry builds the SM-DS metrics registry.
func newDSMetricsRegistry() *metrics.Registry {
	reg := metrics.NewRegistry()
	reg.Describe("rsp42_smds_event_gc_total", metrics.Counter, "Expired SM-DS events reclaimed.")
	reg.Describe("rsp42_smds_events", metrics.Gauge, "SM-DS events by lifecycle status.")
	return reg
}

// eventCollector refreshes the event-count gauges at scrape time.
func eventCollector(events *store.EventRepo) metrics.Collector {
	return func(reg *metrics.Registry) {
		if events == nil {
			return
		}
		now := time.Now().UTC()
		for _, status := range []string{"active", "expired", "deleted"} {
			_, total, err := events.ListFiltered(store.EventFilter{Status: status}, 1, 0, now)
			if err != nil {
				return
			}
			reg.Set("rsp42_smds_events", map[string]string{"status": status}, float64(total))
		}
	}
}
