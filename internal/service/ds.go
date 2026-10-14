package service

import (
	"fmt"
	"log/slog"
	"time"

	"rsp42/internal/cert"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// DSConfig holds the SM-DS mutual-authentication parameters.
type DSConfig struct {
	FQDN             string
	OID              string
	Role             string
	TransactionIDLen int
	SessionTTL       time.Duration
}

// DSService implements ES11 mutual authentication for the SM-DS. It composes
// the shared cmaeCore and adds event discovery.
type DSService struct {
	Cfg      DSConfig
	Certs    *cert.Manager
	Sessions *SessionService
	Events   *EventService
	Log      *slog.Logger

	core *cmaeCore
}

// NewDSService builds an SM-DS service using CERT.DSauth for server signatures.
func NewDSService(cfg DSConfig, certs *cert.Manager, sessions *SessionService, events *EventService, log *slog.Logger) (*DSService, error) {
	if certs.DSAuth() == nil || certs.DSAuthKey() == nil {
		return nil, fmt.Errorf("ds: CERT.DSauth/SK.DSauth not configured")
	}
	return &DSService{
		Cfg: cfg, Certs: certs, Sessions: sessions, Events: events, Log: log,
		core: newCMAECore(cfg.FQDN, certs.DSAuth(), certs.DSAuthKey(), certs, sessions, cfg.TransactionIDLen, cfg.SessionTTL, true, log),
	}, nil
}

// DSAuthResult is the ES11 AuthenticateClient response.
type DSAuthResult struct {
	TransactionID string
	EventEntries  [][2]string // {eventID, rspServerAddress}
}

// Initiate implements ES11.InitiateAuthentication (as ES9+, SGP.22 §5.8.1).
func (d *DSService) Initiate(euiccChallenge, euiccInfo1 []byte, address string) (*InitiateResult, error) {
	res, err := d.core.initiate(euiccChallenge, euiccInfo1, address)
	if err != nil {
		return nil, mapDSStatus(err)
	}
	return res, nil
}

// AuthenticateClient implements ES11.AuthenticateClient with event discovery
// (SGP.22 §3.6.2, §5.8.2).
func (d *DSService) AuthenticateClient(transactionID string, authenticateServerResponse []byte) (*DSAuthResult, error) {
	ca, err := d.core.verify(transactionID, authenticateServerResponse)
	if err != nil {
		return nil, mapDSStatus(err)
	}

	var records []*store.EventRecord
	if ca.MatchingID == "" {
		records, err = d.Events.ListForEID(ca.EID)
	} else {
		records, err = d.Events.LookupByEventID(ca.EID, ca.MatchingID)
		if err == nil && len(records) == 0 {
			return nil, rsp.CodeEventNotFound.Status("Event not found")
		}
	}
	if err != nil {
		return nil, err
	}

	entries := make([][2]string, 0, len(records))
	for _, rec := range records {
		entries = append(entries, [2]string{rec.EventID, rec.RSPServerAddress})
	}
	sess := ca.Session
	sess.State = "authenticated"
	sess.EID = ca.EID
	_ = d.Sessions.Put(sess)
	return &DSAuthResult{TransactionID: transactionID, EventEntries: entries}, nil
}

// mapDSStatus translates a typed CMAE error into the ES11 status codes.
func mapDSStatus(err error) error {
	switch {
	case isCM(err, cmAddress):
		return rsp.CodeDSAddress.Status("Invalid SM-DS address")
	case isCM(err, cmChallenge):
		return rsp.CodeDSChallengeInvalid.Status("euiccChallenge must be 16 bytes")
	case isCM(err, cmCI):
		return rsp.CodeDSCIUnsupported.Status("None of the proposed CI key identifiers is supported")
	case isCM(err, cmUnknownTxn):
		return rsp.CodeEventNotFound.Status("Unknown TransactionID")
	case isCM(err, cmCertChain), isCM(err, cmSignature), isCM(err, cmBadResponse), isCM(err, cmTxnMismatch), isCM(err, cmChallengeMismatch), isCM(err, cmEID):
		return rsp.CodeDSAuthFailed.Status(err.Error())
	}
	return err
}
