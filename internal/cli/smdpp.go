package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api"
	adminapi "rsp42/internal/api/admin"
	"rsp42/internal/api/es2plus"
	"rsp42/internal/api/es9plus"
	"rsp42/internal/audit"
	"rsp42/internal/client/es12"
	"rsp42/internal/client/es2p"
	"rsp42/internal/config"
	"rsp42/internal/logging"
	"rsp42/internal/metrics"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

func cmdSMDpp(prog string, args []string) int {
	cfgPath, fs := globalFlags(prog+" smdpp", args)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath, config.RoleDP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s smdpp: %v\n", prog, err)
		return 1
	}
	if !cfg.SMDpp.Enabled {
		fmt.Fprintf(os.Stderr, "%s smdpp: smdpp.enabled is false\n", prog)
		return 1
	}
	log := logging.New(cfg.Log.Level, cfg.Log.Format)
	slog.SetDefault(log)

	dp, err := bootstrapDP(cfg, log)
	if err != nil {
		log.Error("smdpp bootstrap", "err", err)
		return 1
	}
	defer dp.close()
	st, cmae, notifs := dp.st, dp.cmae, dp.notifs
	orders, inventory, perso, reg := dp.orders, dp.inventory, dp.perso, dp.metrics

	es2pHandler := es2plus.New(es2plus.Deps{
		Log: log, Profiles: st.Profiles, Orders: orders, Inventory: inventory,
		UPP: st.UPP, Idem: st.Idem, AuditRepo: st.Audit,
		RequesterTenants: requesterResolver(cfg.SMDpp.ES2P.RequesterTenants, log),
		OrderAudit:       st.Orders,
		// Without the registry the ES2+ counters (unmapped requester, unparsed
		// profileType, ES12 registration failures) are described by the registry
		// but never incremented.
		Metrics: reg,
		// Table 26's optional smdpAddress: this SM-DP+ knows the FQDN every
		// Activation Code for it must carry.
		FQDN: cfg.SMDpp.FQDN,
	})

	// The Operator-facing ES2+ client is shared by the progress callbacks and
	// the ACR confirmation, but the two are independently configured.
	queue, err := wireOperatorES2P(cbCfgOf(cfg), cfg.SMDpp.OID, cmae, notifs, st, reg, log)
	if err != nil {
		log.Error("operator es2p client", "err", err)
		return 1
	}
	// ACR-0 hands out a redownload Activation Code, but SGP.22 §3.1.7 only makes
	// it usable once the Delete Notification for the Profile has been received.
	// Without allow_redownload_after_delete the code can never be used, so say so
	// instead of leaving a silently half-working feature.
	if cfg.Notifications.ES2PCallback.ACRURL != "" && !cfg.Profiles.AllowRedownloadAfterDelete {
		log.Warn("ACR is enabled but profiles.allow_redownload_after_delete is false: " +
			"an ACR-0 redownload Activation Code cannot be used until the Profile " +
			"leaves Installed")
	}
	if queue != nil {
		startTicker(cfg.Notifications.ES2PCallback.RetryInterval.Duration(), func() {
			if _, err := queue.RunOnce(context.Background()); err != nil {
				log.Warn("callback retry sweep", "err", err)
			}
		})
	}
	if cfg.SMDpp.ES12.Enabled && cfg.SMDpp.ES12.SMDSAddress != "" {
		hc, err := mtlsClient(cfg.SMDpp.ES12.TLS)
		if err != nil {
			log.Error("es12 client tls", "err", err)
			return 1
		}
		registrar := &service.Registrar{
			Repo:        st.Regs,
			Client:      es12.NewSMDSCClient("https://"+cfg.SMDpp.ES12.SMDSAddress+":9444", cfg.SMDpp.OID, hc),
			SMDPAddress: cfg.SMDpp.FQDN,
			Forwarding:  cfg.SMDpp.ES12.ForwardingIndicator,
			Log:         log,
			Metrics:     reg,
			Audit:       st.Audit,
		}
		es2pHandler.Registrar = registrar
		notifs.Deps.Registrar = registrar
		// The event is deleted once the Profile is installed unless the operator
		// asks to keep it discoverable (smdpp.es12.delete_on_install: false).
		notifs.Deps.KeepEventOnInstall = !cfg.SMDpp.ES12.DeleteOnInstall
		// The ACR-0 redownload rotates a Profile's MatchingID (§3.1.7); the
		// registration held under the previous one is stale, and the CMAE is the
		// only place that knows the rotation happened.
		cmae.MatchingIDChanged = func(profile *store.Profile, previousMatchingID string) {
			meta := es12.EventMeta{Tenant: profile.TenantID, ICCID: profile.ICCID, MatchingID: previousMatchingID}
			if err := registrar.DeleteEvent(profile.EID, previousMatchingID, meta); err != nil {
				log.Warn("ES12 delete stale event after an ACR-0 MatchingID rotation",
					"eid", profile.EID, "eventId", previousMatchingID, "err", err)
			}
		}
	}
	es9pHandler := es9plus.New(log, cmae)
	es9pHandler.Notifs = notifs

	var auditLog *audit.Logger
	if cfg.Audit.Enabled {
		auditLog, err = audit.New(st.Audit, cfg.Audit.Sink, cfg.Audit.File)
		if err != nil {
			log.Error("audit", "err", err)
			return 1
		}
		defer func() { _ = auditLog.Close() }()
	}

	mk := func(h http.Handler, l config.ListenerCfg) (namedServer, error) {
		return buildServer(log, "es9p", cfg.SMDpp.Server.Bind, l, h)
	}
	// Audit is applied inside the router (api.Options.Audit) so that it runs
	// after middleware.RequestScope and can attribute every row to the request
	// scope. The admin router ignores it and audits its own writes; it does get
	// the larger body budget, because template uploads and CSV imports are not
	// bounded by SGP.22 message sizes.
	apiOpts := api.Options{CORS: cfg.SMDpp.Server.CORS.AllowedOrigins, Audit: auditLog}
	adminOpts := api.Options{CORS: cfg.SMDpp.Server.CORS.AllowedOrigins, BodyLimit: adminBodyLimit}
	es9p, err := mk(api.NewES9PRouter(log, es9pHandler, apiOpts), cfg.SMDpp.Server.ES9P)
	if err != nil {
		log.Error("es9p listener", "err", err)
		return 1
	}
	es2p, err := buildServer(log, "es2p", cfg.SMDpp.Server.Bind, cfg.SMDpp.Server.ES2P, api.NewES2PRouter(log, es2pHandler, apiOpts))
	if err != nil {
		log.Error("es2p listener", "err", err)
		return 1
	}
	saipPolicy, err := service.NewSAIPVersionPolicy(cfg.Profiles.AllowedSAIPVersions)
	if err != nil {
		log.Error("saip version policy", "err", err)
		return 1
	}
	adminH := &adminapi.Handler{
		Log: log, Tenants: st.Tenants, Profiles: st.Profiles, Orders: orders, Inventory: inventory,
		UPP: st.UPP, Perso: perso, Audit: st.Audit, Batch: st.Batch,
		OrderRepo: st.Orders, Notifs: st.Notifs, Sessions: st.Sessions, Pool: st.Pool,
		Callbacks: st.Callbacks,
		Idem:      st.Idem, AllowedSAIP: saipPolicy,
		DefaultReserveTTL: cfg.Profiles.Personalization.ReserveTTL.Duration(),
		FQDN:              cfg.SMDpp.FQDN, OID: cfg.SMDpp.OID,
	}
	if err := adminH.Validate(); err != nil {
		log.Error("admin handler", "err", err)
		return 1
	}
	admin, err := buildServer(log, "admin", cfg.SMDpp.Server.Bind, cfg.SMDpp.Server.Admin,
		api.NewAdminRouter(log, func() bool { return true }, func(r chi.Router) {
			adminapi.Mount(r, adminH)
			r.Get("/metrics", metrics.Handler(reg, poolCollector(st.Pool), callbackCollector(st.Callbacks)))
		}, adminOpts))
	if err != nil {
		log.Error("admin listener", "err", err)
		return 1
	}

	if n := es2pHandler.RequesterTenants.Len(); n > 0 {
		log.Info("ES2+ tenant mapping configured", "requesters", n)
	} else {
		log.Warn("no smdpp.es2p.requester_tenants mapping: every ES2+ caller maps to the platform-default tenant")
	}
	log.Info("starting SM-DP+", "fqdn", cfg.SMDpp.FQDN, "es9p_port", cfg.SMDpp.Server.ES9P.Port, "es2p_port", cfg.SMDpp.Server.ES2P.Port)
	return serveAll(log, es9p, es2p, admin)
}

// requesterResolver builds the ES2+ requester -> tenant resolver, warning about
// duplicate mappings.
func requesterResolver(pairs []config.RequesterTenantConfig, log *slog.Logger) *service.TenantResolver {
	return service.NewTenantResolver(requesterPairs(pairs))
}

// requesterPairs converts config mappings into service-level pairs, dropping
// entries with an empty requester.
func requesterPairs(pairs []config.RequesterTenantConfig) []service.RequesterTenant {
	out := make([]service.RequesterTenant, 0, len(pairs))
	for _, p := range pairs {
		if p.Requester == "" {
			continue
		}
		out = append(out, service.RequesterTenant{Requester: p.Requester, Tenant: p.Tenant})
	}
	return out
}

// newMetricsRegistry builds the process metrics registry with the metric help
// text declared up front (so the series exist even before the first event).
//
// The vocabulary of the packages that emit metrics is declared by those
// packages (service.DescribeMetrics, es2plus.DescribeMetrics); only the metrics
// the composition root itself maintains are described here. The registry refuses
// an undeclared name, so a missing declaration fails loudly.
func newMetricsRegistry() *metrics.Registry {
	reg := metrics.NewRegistry()
	service.DescribeMetrics(reg)
	es2plus.DescribeMetrics(reg)
	reg.Describe("rsp42_session_gc_total", metrics.Counter, "Expired download sessions removed.")
	reg.Describe("rsp42_iccid_reservation_gc_total", metrics.Counter, "Expired ICCID pool reservations reclaimed.")
	reg.Describe("rsp42_iccid_pool", metrics.Gauge, "ICCID pool entries by state (tenant=all).")
	reg.Describe("rsp42_es2p_callback_queue", metrics.Gauge, "Outbound ES2+ callback rows by status.")
	return reg
}

// poolCollector refreshes ICCID pool gauges at scrape time.
func poolCollector(pool *store.PoolRepo) metrics.Collector {
	return func(reg *metrics.Registry) {
		if pool == nil {
			return
		}
		counts, _, err := pool.Stats(nil)
		if err != nil {
			return
		}
		for state, n := range counts {
			reg.Set("rsp42_iccid_pool", map[string]string{"state": state}, float64(n))
		}
	}
}

// callbackCollector refreshes callback queue gauges at scrape time.
func callbackCollector(repo *store.CallbackRepo) metrics.Collector {
	return func(reg *metrics.Registry) {
		if repo == nil {
			return
		}
		counts, err := repo.Stats()
		if err != nil {
			return
		}
		for status, n := range counts {
			reg.Set("rsp42_es2p_callback_queue", map[string]string{"status": status}, float64(n))
		}
	}
}

// cbCfgOf returns the Operator ES2+ configuration.
func cbCfgOf(cfg *config.Config) config.CallbackConfig { return cfg.Notifications.ES2PCallback }

// wireOperatorES2P builds the Operator-facing ES2+ client and installs the
// hooks it backs:
//
//   - the outbound progress notifications (notifications.es2p_callback.enabled +
//     .url), whose queue is returned so the caller can start its retry ticker;
//   - the ACR confirmation (ES2+.HandleAcrRequest, notifications.es2p_callback
//     .acr_url), which is deliberately independent of the progress callbacks:
//     G13 requires ACR to work when only acr_url is configured (and vice versa).
//
// The returned queue is nil when progress callbacks are disabled.
func wireOperatorES2P(
	cbCfg config.CallbackConfig,
	oid string,
	cmae *service.CMAE,
	notifs *service.NotificationService,
	st *store.Store,
	reg *metrics.Registry,
	log *slog.Logger,
) (*es2p.CallbackQueue, error) {
	wantCallbacks := cbCfg.Enabled && cbCfg.URL != ""
	wantACR := cbCfg.ACRURL != ""
	if !wantCallbacks && !wantACR {
		return nil, nil
	}

	var hc *http.Client
	if cbCfg.ClientCertFile != "" {
		client, err := mtlsClient(config.TLSCfg{
			ClientCertFile: cbCfg.ClientCertFile,
			ClientKeyFile:  cbCfg.ClientKeyFile,
			CAFile:         cbCfg.CAFile,
		})
		if err != nil {
			return nil, err
		}
		hc = client
	}

	cb := es2p.NewCallbackClient(cbCfg.URL, oid, hc)
	cb.ACRURL = cbCfg.ACRURL
	if n := cbCfg.MaxAttempts; n > 0 {
		cb.MaxAttempts = n
	}

	if wantACR {
		checker := &service.ACRChecker{
			Operator: cb,
			Timeout:  cbCfg.ACRTimeout.Duration(),
			Metrics:  reg,
			Audit:    st.Audit,
			Log:      log,
		}
		cmae.ACRCheck = checker.Check
		log.Info("ES2+ handleAcrRequest confirmation enabled",
			"acr_url", cbCfg.ACRURL, "timeout", cbCfg.ACRTimeout.Duration().String())
	}

	if !wantCallbacks {
		return nil, nil
	}
	queue := es2p.NewCallbackQueue(st.Callbacks, cb, es2p.QueueOptions{
		Metrics: reg,
		Log:     log,
		URLForTenant: func(tenant string) string {
			url, err := st.Tenants.CallbackURLForTenant(tenant)
			if err != nil {
				log.Warn("tenant callback url", "tenant", tenant, "err", err)
				return ""
			}
			return url
		},
		MaxAttempts: cbCfg.MaxAttempts,
	})
	notifs.Callback = queue.Deliver
	cmae.Notify = queue.Deliver
	return queue, nil
}
