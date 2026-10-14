package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api"
	adminapi "rsp42/internal/api/admin"
	"rsp42/internal/api/es2plus"
	"rsp42/internal/api/es9plus"
	"rsp42/internal/api/middleware"
	"rsp42/internal/audit"
	"rsp42/internal/config"
	"rsp42/internal/logging"
	"rsp42/internal/metrics"
	"rsp42/internal/rsp"
	"rsp42/internal/saip/personalization"
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

	certs, provider, err := loadCertificates(cfg, log)
	if err != nil {
		log.Error("certificate validation", "err", err)
		return 1
	}

	st, err := store.Open(cfg.Profiles.Store.DSN)
	if err != nil {
		log.Error("open store", "err", err)
		return 1
	}
	defer func() { _ = st.Close() }()
	orders := service.NewOrderService(st.Profiles)
	orders.Pool = st.Pool
	inventory := service.NewInventory(st.Profiles, cfg.Profiles.Personalization.ICCIDPoolPrefix, cfg.Profiles.Personalization.IMSIPoolPrefix)
	inventory.Pool = st.Pool
	inventory.ReserveTTL = cfg.Profiles.Personalization.ReserveTTL.Duration()
	inventory.ProfileQuota = func(tenant string) (*int, error) {
		t, err := st.Tenants.Get(tenant)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return t.ProfileQuota, nil
	}
	inventory.CountProfiles = func(tenant string) (int, error) {
		_, total, err := st.Profiles.ListFiltered(store.ProfileFilter{Tenant: &tenant}, 1, 0, "")
		return total, err
	}
	es2pHandler := es2plus.New(log, st.Profiles, orders, inventory)
	es2pHandler.UPP = st.UPP
	es2pHandler.Idem = st.Idem
	es2pHandler.AuditRepo = st.Audit
	es2pHandler.RequesterTenants = requesterResolver(cfg.SMDpp.ES2P.RequesterTenants, log)

	reg := newMetricsRegistry()
	sessions := service.NewSessionService(st.Sessions, provider, cfg.SMDpp.SessionTTL.Duration())
	startGC(log, func() {
		if n, err := sessions.GC(time.Now().UTC()); err == nil {
			if n > 0 {
				log.Info("session gc", "removed", n)
			}
			reg.Add("rsp42_session_gc_total", nil, float64(n))
		}
		if n, err := st.Pool.ReleaseExpired(time.Now().UTC()); err == nil {
			if n > 0 {
				log.Info("iccid reservation gc", "released", n)
				// G6: an expired reservation must be traceable in the audit
				// trail, not only in the process log.
				detail, _ := json.Marshal(map[string]any{"released": n})
				_ = st.Audit.Insert(&store.AuditEntry{
					Interface: "gc", Function: "releaseExpiredReservations", Subject: "iccid_pool",
					Outcome: "Executed-Success", DetailJSON: string(detail),
				})
			}
			reg.Add("rsp42_iccid_reservation_gc_total", nil, float64(n))
		}
		if ttl := cfg.Profiles.Personalization.IdempotencyTTL.Duration(); ttl > 0 {
			if n, err := st.Idem.DeleteBefore(time.Now().UTC().Add(-ttl).Unix()); err == nil && n > 0 {
				log.Info("idempotency gc", "removed", n)
			}
		}
	})
	hostID, err := hex.DecodeString(cfg.SMDpp.HostID)
	if err != nil {
		log.Error("bad smdpp.host_id", "err", err)
		return 1
	}
	perso := service.NewPersonalizationService(st.Perso, provider)
	cmae, err := service.NewCMAE(service.CMAEConfig{
		FQDN:                cfg.SMDpp.FQDN,
		OID:                 cfg.SMDpp.OID,
		HostID:              hostID,
		TransactionIDLen:    cfg.SMDpp.TransactionIDLen,
		MaxDownloadAttempts: cfg.SMDpp.MaxDownloadAttempts,
		MaxCCAttempts:       cfg.SMDpp.MaxCCAttempts,
		SessionTTL:          cfg.SMDpp.SessionTTL.Duration(),
		DownloadTTL:         cfg.SMDpp.DownloadTTL.Duration(),
		PPRIds:              rsp.PPRIDBits(cfg.Profiles.PPRIds),
	}, certs, sessions, st.Profiles, perso, st.UPP, cfg.Profiles.DefaultUPP, &personalization.Engine{Algorithm: cfg.Profiles.Personalization.DefaultAlgorithm}, log)
	cmae.Tenants = st.Tenants
	if err != nil {
		log.Error("cmae", "err", err)
		return 1
	}
	notifs := service.NewNotificationService(log, st.Notifs, st.Profiles, orders)
	notifs.Sessions = sessions
	notifs.Certs = certs
	es2pHandler.OrderAudit = st.Orders

	// The Operator-facing ES2+ client is shared by the progress callbacks and
	// the ACR confirmation, but the two are independently configured.
	queue, err := wireOperatorES2P(cbCfgOf(cfg), cfg.SMDpp.OID, cmae, notifs, st, reg, log)
	if err != nil {
		log.Error("operator es2p client", "err", err)
		return 1
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
		reg := &service.Registrar{
			Repo:        st.Regs,
			Client:      service.NewSMDSCClient("https://"+cfg.SMDpp.ES12.SMDSAddress+":9444", cfg.SMDpp.OID, hc),
			SMDPAddress: cfg.SMDpp.FQDN,
			Forwarding:  cfg.SMDpp.ES12.ForwardingIndicator,
			Log:         log,
		}
		es2pHandler.Registrar = reg
		notifs.Registrar = reg
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
	wrap := func(h http.Handler, iface string) http.Handler {
		if auditLog == nil {
			return h
		}
		return middleware.Chain(h, middleware.Audit(auditLog, iface))
	}

	mk := func(h http.Handler, l config.ListenerCfg) (namedServer, error) {
		return buildServer(log, "es9p", cfg.SMDpp.Server.Bind, l, h)
	}
	apiOpts := api.Options{CORS: cfg.SMDpp.Server.CORS.AllowedOrigins}
	es9p, err := mk(wrap(api.NewES9PRouter(log, es9pHandler, apiOpts), "es9p"), cfg.SMDpp.Server.ES9P)
	if err != nil {
		log.Error("es9p listener", "err", err)
		return 1
	}
	es2p, err := buildServer(log, "es2p", cfg.SMDpp.Server.Bind, cfg.SMDpp.Server.ES2P, wrap(api.NewES2PRouter(log, es2pHandler, apiOpts), "es2p"))
	if err != nil {
		log.Error("es2p listener", "err", err)
		return 1
	}
	adminH := &adminapi.Handler{
		Log: log, Tenants: st.Tenants, Profiles: st.Profiles, Orders: orders, Inventory: inventory,
		UPP: st.UPP, Perso: perso, Audit: st.Audit, Batch: st.Batch,
		OrderRepo: st.Orders, Notifs: st.Notifs, Sessions: st.Sessions, Pool: st.Pool, Events: st.Events,
		Idem: st.Idem, DefaultReserveTTL: cfg.Profiles.Personalization.ReserveTTL.Duration(),
		FQDN: cfg.SMDpp.FQDN, OID: cfg.SMDpp.OID,
	}
	admin, err := buildServer(log, "admin", cfg.SMDpp.Server.Bind, cfg.SMDpp.Server.Admin,
		api.NewAdminRouter(log, func() bool { return true }, func(r chi.Router) {
			adminapi.Mount(r, adminH)
			r.Get("/metrics", metrics.Handler(reg, poolCollector(st.Pool), callbackCollector(st.Callbacks)))
		}, apiOpts))
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
func newMetricsRegistry() *metrics.Registry {
	reg := metrics.NewRegistry()
	reg.Describe("rsp42_progress_notifications_total", metrics.Counter,
		"ES2+ download-progress notifications by tenant, notification point and status.")
	reg.Describe("rsp42_session_gc_total", metrics.Counter, "Expired download sessions removed.")
	reg.Describe("rsp42_iccid_reservation_gc_total", metrics.Counter, "Expired ICCID pool reservations reclaimed.")
	reg.Describe("rsp42_iccid_pool", metrics.Gauge, "ICCID pool entries by state (tenant=all).")
	reg.Describe("rsp42_es2p_callback_queue", metrics.Gauge, "Outbound ES2+ callback rows by status.")
	reg.Describe("rsp42_es12_register_failures_total", metrics.Counter,
		"SM-DS event registration failures by tenant.")
	reg.Describe("rsp42_acr_requests_total", metrics.Counter,
		"ES2+ HandleAcrRequest confirmations by tenant and outcome (allowed|refused|error).")
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
) (*es2plus.CallbackQueue, error) {
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

	cb := es2plus.NewCallbackClient(cbCfg.URL, oid, hc)
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
	queue := es2plus.NewCallbackQueue(st.Callbacks, cb, log)
	queue.Metrics = reg
	queue.URLForTenant = func(tenant string) string {
		url, err := st.Tenants.CallbackURLForTenant(tenant)
		if err != nil {
			log.Warn("tenant callback url", "tenant", tenant, "err", err)
			return ""
		}
		return url
	}
	if n := cbCfg.MaxAttempts; n > 0 {
		queue.MaxAttempts = n
	}
	notifs.Callback = queue.Deliver
	cmae.Notify = queue.Deliver
	return queue, nil
}
