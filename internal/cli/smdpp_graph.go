package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"rsp42/internal/cert"
	"rsp42/internal/config"
	"rsp42/internal/kms"
	"rsp42/internal/metrics"
	"rsp42/internal/rsp"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// dpGraph is the assembled SM-DP+ object graph: the certificate material, the
// SQLite store and the services built on them. cmdSMDpp builds it with
// bootstrapDP, then wires the HTTP handlers on top.
type dpGraph struct {
	cfg      *config.Config
	log      *slog.Logger
	certs    *cert.Manager
	provider *kms.FileProvider
	st       *store.Store
	metrics  *metrics.Registry

	sessions  *service.SessionService
	orders    *service.OrderService
	inventory *service.Inventory
	perso     *service.PersonalizationService
	cmae      *service.CMAE
	notifs    *service.NotificationService
}

// close releases the store. The caller defers it once bootstrapDP succeeds.
func (g *dpGraph) close() { _ = g.st.Close() }

// bootstrapDP loads the certificate material, opens the store and builds the
// SM-DP+ services, including the background GC. It leaves the object graph
// ready for the HTTP wiring, so cmdSMDpp reads as config → bootstrap → wire →
// serve instead of doing all four inline.
func bootstrapDP(cfg *config.Config, log *slog.Logger) (*dpGraph, error) {
	certs, provider, err := loadCertificates(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("certificate validation: %w", err)
	}
	st, err := store.Open(cfg.Profiles.Store.DSN)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	g := &dpGraph{cfg: cfg, log: log, certs: certs, provider: provider, st: st}

	g.orders = service.NewOrderService(st.Profiles)
	g.orders.Pool = st.Pool
	g.inventory = service.NewInventory(st.Profiles,
		cfg.Profiles.Personalization.ICCIDPoolPrefix, cfg.Profiles.Personalization.IMSIPoolPrefix)
	g.inventory.Pool = st.Pool
	g.inventory.ReserveTTL = cfg.Profiles.Personalization.ReserveTTL.Duration()
	g.inventory.ProfileQuota = func(tenant string) (*int, error) {
		t, err := st.Tenants.Get(tenant)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return t.ProfileQuota, nil
	}
	g.inventory.CountProfiles = func(tenant string) (int, error) {
		_, total, err := st.Profiles.ListFiltered(store.ProfileFilter{Tenant: &tenant}, 1, 0, "")
		return total, err
	}

	g.metrics = newMetricsRegistry()
	g.sessions = service.NewSessionService(st.Sessions, provider, cfg.SMDpp.SessionTTL.Duration())
	startGC(log, func() { g.runGC() })

	hostID, err := hex.DecodeString(cfg.SMDpp.HostID)
	if err != nil {
		g.close()
		return nil, fmt.Errorf("bad smdpp.host_id: %w", err)
	}
	g.perso = service.NewPersonalizationService(st.Perso, provider)
	g.cmae, err = service.NewCMAE(service.CMAEConfig{
		FQDN:                cfg.SMDpp.FQDN,
		OID:                 cfg.SMDpp.OID,
		HostID:              hostID,
		TransactionIDLen:    cfg.SMDpp.TransactionIDLen,
		MaxDownloadAttempts: cfg.SMDpp.MaxDownloadAttempts,
		MaxCCAttempts:       cfg.SMDpp.MaxCCAttempts,
		SessionTTL:          cfg.SMDpp.SessionTTL.Duration(),
		DownloadTTL:         cfg.SMDpp.DownloadTTL.Duration(),
		PPRIds:              rsp.PPRIDBits(cfg.Profiles.PPRIds),
	}, certs, g.sessions, st.Profiles, g.perso, st.UPP, cfg.Profiles.DefaultUPP,
		&personalization.Engine{Algorithm: cfg.Profiles.Personalization.DefaultAlgorithm}, log)
	if err != nil {
		g.close()
		return nil, fmt.Errorf("cmae: %w", err)
	}
	g.cmae.Tenants = st.Tenants
	g.cmae.Audit = st.Audit
	g.cmae.Metrics = g.metrics

	g.notifs = service.NewNotificationService(log, st.Notifs, st.Profiles, g.orders)
	g.notifs.Sessions = g.sessions
	g.notifs.Certs = certs
	return g, nil
}

// runGC performs the periodic maintenance: expired sessions, lapsed ICCID
// reservations (recorded in the audit trail for G6) and stale idempotency
// records.
func (g *dpGraph) runGC() {
	st, cfg, log := g.st, g.cfg, g.log
	if n, err := g.sessions.GC(time.Now().UTC()); err == nil {
		if n > 0 {
			log.Info("session gc", "removed", n)
		}
		g.metrics.Add("rsp42_session_gc_total", nil, float64(n))
	}
	if n, err := st.Pool.ReleaseExpired(time.Now().UTC()); err == nil {
		if n > 0 {
			log.Info("iccid reservation gc", "released", n)
			// G6: an expired reservation must be traceable in the audit trail,
			// not only in the process log.
			detail, _ := json.Marshal(map[string]any{"released": n})
			_ = st.Audit.Insert(&store.AuditEntry{
				Interface: "gc", Function: "releaseExpiredReservations", Subject: "iccid_pool",
				Outcome: "Executed-Success", DetailJSON: string(detail),
			})
		}
		g.metrics.Add("rsp42_iccid_reservation_gc_total", nil, float64(n))
	}
	if ttl := cfg.Profiles.Personalization.IdempotencyTTL.Duration(); ttl > 0 {
		if n, err := st.Idem.DeleteBefore(time.Now().UTC().Add(-ttl).Unix()); err == nil && n > 0 {
			log.Info("idempotency gc", "removed", n)
		}
	}
}
