package cli

import (
	"context"
	"encoding/hex"
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
	inventory := service.NewInventory(st.Profiles, cfg.Profiles.Personalization.ICCIDPoolPrefix, cfg.Profiles.Personalization.IMSIPoolPrefix)
	inventory.Pool = st.Pool
	es2pHandler := es2plus.New(log, st.Profiles, orders, inventory)

	sessions := service.NewSessionService(st.Sessions, provider, cfg.SMDpp.SessionTTL.Duration())
	startGC(log, func() {
		if n, err := sessions.GC(time.Now().UTC()); err == nil && n > 0 {
			log.Info("session gc", "removed", n)
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
	if err != nil {
		log.Error("cmae", "err", err)
		return 1
	}
	notifs := service.NewNotificationService(log, st.Notifs, st.Profiles, orders)
	notifs.Sessions = sessions
	notifs.Certs = certs
	es2pHandler.OrderAudit = st.Orders

	if cfg.Notifications.ES2PCallback.Enabled && cfg.Notifications.ES2PCallback.URL != "" {
		var hc *http.Client
		if cfg.Notifications.ES2PCallback.ClientCertFile != "" {
			hc, err = mtlsClient(config.TLSCfg{
				ClientCertFile: cfg.Notifications.ES2PCallback.ClientCertFile,
				ClientKeyFile:  cfg.Notifications.ES2PCallback.ClientKeyFile,
				CAFile:         cfg.Notifications.ES2PCallback.CAFile,
			})
			if err != nil {
				log.Error("callback client tls", "err", err)
				return 1
			}
		}
		cb := es2plus.NewCallbackClient(cfg.Notifications.ES2PCallback.URL, cfg.SMDpp.OID, hc)
		cb.ACRURL = cfg.Notifications.ES2PCallback.ACRURL
		if cb.ACRURL != "" {
			cmae.ACRCheck = cb.HandleAcrRequest
		}
		queue := es2plus.NewCallbackQueue(st.Callbacks, cb, log)
		if n := cfg.Notifications.ES2PCallback.MaxAttempts; n > 0 {
			queue.MaxAttempts = n
		}
		notifs.Callback = queue.Deliver
		cmae.Notify = queue.Deliver
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
		return buildServer(log, "es9p", cfg.Server.Bind, l, h)
	}
	es9p, err := mk(wrap(api.NewES9PRouter(log, es9pHandler), "es9p"), cfg.Server.ES9P)
	if err != nil {
		log.Error("es9p listener", "err", err)
		return 1
	}
	es2p, err := buildServer(log, "es2p", cfg.Server.Bind, cfg.Server.ES2P, wrap(api.NewES2PRouter(log, es2pHandler), "es2p"))
	if err != nil {
		log.Error("es2p listener", "err", err)
		return 1
	}
	adminH := &adminapi.Handler{
		Log: log, Profiles: st.Profiles, Orders: orders, Inventory: inventory,
		UPP: st.UPP, Perso: perso, Audit: st.Audit, Batch: st.Batch,
		OrderRepo: st.Orders, Notifs: st.Notifs, Pool: st.Pool, FQDN: cfg.SMDpp.FQDN, OID: cfg.SMDpp.OID,
	}
	admin, err := buildServer(log, "admin", cfg.Server.Bind, cfg.Server.Admin, api.NewAdminRouter(log, func() bool { return true }, func(r chi.Router) { adminapi.Mount(r, adminH) }))
	if err != nil {
		log.Error("admin listener", "err", err)
		return 1
	}

	log.Info("starting SM-DP+", "fqdn", cfg.SMDpp.FQDN, "es9p_port", cfg.Server.ES9P.Port, "es2p_port", cfg.Server.ES2P.Port)
	return serveAll(log, es9p, es2p, admin)
}
