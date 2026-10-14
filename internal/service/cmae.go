package service

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"rsp42/internal/activationcode"
	"rsp42/internal/cert"
	"rsp42/internal/crypto"
	"rsp42/internal/rsp"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/store"
)

// CMAEConfig holds the SM-DP+ mutual authentication parameters.
type CMAEConfig struct {
	FQDN                string
	OID                 string
	HostID              []byte
	TransactionIDLen    int
	MaxDownloadAttempts int
	MaxCCAttempts       int
	SessionTTL          time.Duration
	DownloadTTL         time.Duration
	// PPRIds is the default PprIds BIT STRING content applied to downloaded
	// profiles when the order does not override it (SGP.22 §2.4a).
	PPRIds []byte
}

// CMAE implements the SM-DP+ ES9+ authentication and download flow (SGP.22
// §5.6). The shared handshake logic lives in cmaeCore.
type CMAE struct {
	Cfg             CMAEConfig
	Certs           *cert.Manager
	Sessions        *SessionService
	Profiles        ProfileStore
	Personalization PersonalizationResolver
	UPP             UPPStore
	DefaultUPP      string
	Engine          *personalization.Engine
	Log             *slog.Logger
	// Notify, when set, delivers ES2+ progress notifications (SGP.22 §5.3.5).
	Notify OperatorCallback
	// ACRCheck, when set, calls the Operator's ES2+.HandleAcrRequest to confirm
	// an Activation Code Retrieval (SGP.22 §5.3.8).
	ACRCheck func(ctx context.Context, iccid string) error

	core *cmaeCore
}

// NewCMAE builds an SM-DP+ CMAE using CERT.DPauth for server signatures.
func NewCMAE(cfg CMAEConfig, certs *cert.Manager, sessions *SessionService, profiles ProfileStore, perso PersonalizationResolver, upp UPPStore, defaultUPP string, engine *personalization.Engine, log *slog.Logger) (*CMAE, error) {
	if certs.DPAuth() == nil || certs.DPAuthKey() == nil {
		return nil, fmt.Errorf("cmae: CERT.DPAuth/SK.DPAuth not configured")
	}
	if upp == nil {
		return nil, fmt.Errorf("cmae: UPP template store not configured")
	}
	c := &CMAE{
		Cfg: cfg, Certs: certs, Sessions: sessions, Profiles: profiles,
		Personalization: perso, UPP: upp, DefaultUPP: defaultUPP, Engine: engine, Log: log,
	}
	c.core = newCMAECore(cfg.FQDN, certs.DPAuth(), certs.DPAuthKey(), certs, sessions, cfg.TransactionIDLen, cfg.SessionTTL, false, log)
	return c, nil
}

// identityFor returns the certificate identity selected for a session, or nil
// when the primary identity applies.
func (c *CMAE) identityFor(sess *store.Session) *cert.Identity {
	if sess == nil || len(sess.CICertID) == 0 {
		return nil
	}
	return c.Certs.IdentityByCIKeyID(sess.CICertID)
}

// pbFor returns the profile-binding certificate/key for a session's identity.
func (c *CMAE) pbFor(sess *store.Session) (*x509.Certificate, stdcrypto.Signer) {
	if id := c.identityFor(sess); id != nil && id.DPPbCert != nil {
		return id.DPPbCert, id.DPPbKey
	}
	return c.Certs.DPPb(), c.Certs.DPPbKey()
}

// notify delivers an operator progress notification if configured.
func (c *CMAE) notify(ctx context.Context, eid, iccid string, point int, status string) {
	if c.Notify != nil {
		if err := c.Notify(ctx, eid, iccid, point, status); err != nil && c.Log != nil {
			c.Log.Warn("operator callback", "point", point, "err", err)
		}
	}
}

// Initiate implements ES9+.InitiateAuthentication (SGP.22 §5.6.1).
func (c *CMAE) Initiate(euiccChallenge, euiccInfo1 []byte, smdpAddress string) (*InitiateResult, error) {
	res, err := c.core.initiate(euiccChallenge, euiccInfo1, smdpAddress)
	if err != nil {
		return nil, mapDPStatus(err)
	}
	return res, nil
}

// AuthenticateResult is the ES9+.AuthenticateClient response.
type AuthenticateResult struct {
	TransactionID   string
	ProfileMetadata []byte
	SmdpSigned2     []byte
	SmdpSignature2  []byte
	SmdpCertificate []byte
	// ACROnly indicates the response is an Activation Code Retrieval response
	// carrying only transactionId and profileMetadata (SGP.22 §4.9.2).
	ACROnly bool
}

// AuthenticateClient implements ES9+.AuthenticateClient (SGP.22 §5.6.3).
func (c *CMAE) AuthenticateClient(transactionID string, authenticateServerResponse []byte) (*AuthenticateResult, error) {
	ca, err := c.core.verify(transactionID, authenticateServerResponse)
	if err != nil {
		return nil, mapDPStatus(err)
	}

	// Activation Code Retrieval (§3.1.7/§3.1.8).
	if activationcode.IsACR(ca.MatchingID) {
		return c.handleACR(transactionID, ca)
	}

	profile, err := c.lookupProfile(ca.MatchingID, ca.EID)
	if err != nil {
		return nil, err
	}
	if err := c.registerDownloadAttempt(profile); err != nil {
		return nil, err
	}

	smdpSigned2 := (&rsp.SmdpSigned2{TransactionID: ca.Signed1.TransactionID, CCRequiredFlag: profile.CCRequired}).Encode()
	pbCert, pbSigner := c.pbFor(ca.Session)
	dpPbKey, err := ecdsaKey(pbSigner)
	if err != nil {
		return nil, err
	}
	toSign := append(append([]byte{}, smdpSigned2...), rsp.WrapSignature(rsp.SignatureValue(ca.Response.EuiccSignature1))...)
	sig2, err := crypto.SignRaw(dpPbKey, toSign)
	if err != nil {
		return nil, err
	}
	smdpSignature2 := rsp.WrapSignature(sig2)

	meta, err := c.buildStoreMetadata(profile)
	if err != nil {
		return nil, err
	}

	sess := ca.Session
	sess.State = "authenticated"
	sess.EID = ca.EID
	sess.EuiccCert = ca.Response.EuiccCertificate
	sess.EumCert = ca.Response.EumCertificate
	sess.ProfileID = profile.ID
	sess.SmdpSignature2 = smdpSignature2
	// Select a UPP template compatible with the eUICC's advertised profile
	// version when the order does not pin one explicitly.
	if profile.UPPTemplate == "" && ca.Signed1.EuiccInfo2 != nil {
		if tpl := c.pickUPP(ca.Signed1.EuiccInfo2.ProfileVersion); tpl != "" {
			sess.UPPTemplate = tpl
		}
	}
	if err := c.Sessions.Put(sess); err != nil {
		return nil, err
	}

	return &AuthenticateResult{
		TransactionID:   transactionID,
		ProfileMetadata: meta,
		SmdpSigned2:     smdpSigned2,
		SmdpSignature2:  smdpSignature2,
		SmdpCertificate: pbCert.Raw,
	}, nil
}

func (c *CMAE) lookupProfile(matchingID, eid string) (*store.Profile, error) {
	if matchingID == "" {
		return nil, rsp.CodeProfileNotEligible.Status("Refused")
	}
	p, err := c.Profiles.GetByMatchingID(matchingID)
	if err != nil {
		return nil, rsp.CodeProfileNotEligible.Status("Refused")
	}
	if p.EID != "" && p.EID != eid {
		return nil, rsp.CodeProfileNotEligible.Status("EID mismatch")
	}
	switch p.State {
	case store.StateReleased, store.StateDownloaded:
	default:
		return nil, rsp.CodeProfileNotFound.Status("Profile not eligible for download")
	}
	// Download order TTL: an order that is older than the configured window is
	// no longer eligible for download.
	if c.Cfg.DownloadTTL > 0 && !p.CreatedAt.IsZero() && time.Since(p.CreatedAt) > c.Cfg.DownloadTTL {
		return nil, rsp.CodeProfileNotFound.Status("Download order expired")
	}
	return p, nil
}

// registerDownloadAttempt increments the per-Profile download attempt counter
// (SGP.22 §3.1.3 step 3) and, once the configured maximum is exceeded,
// terminates the order (Error) and notifies the Operator.
func (c *CMAE) registerDownloadAttempt(p *store.Profile) error {
	p.DownloadAttempts++
	if c.Cfg.MaxDownloadAttempts > 0 && p.DownloadAttempts > c.Cfg.MaxDownloadAttempts {
		p.State = store.StateError
		p.ErrorReason = "download attempts exceeded"
		if err := c.Profiles.Update(p); err != nil {
			return err
		}
		c.notify(context.Background(), p.EID, p.ICCID, 1, "Failed")
		return rsp.CodeProfileNotFound.Status("Download attempts exceeded")
	}
	return c.Profiles.Update(p)
}

// mapDPStatus translates a typed CMAE error into the ES9+ status codes.
func mapDPStatus(err error) error {
	switch {
	case isCM(err, cmAddress):
		return rsp.CodeSMDPAddress.Status("Invalid SM-DP+ address")
	case isCM(err, cmChallenge):
		return rsp.CodeChallengeInvalid.Status("euiccChallenge must be 16 bytes")
	case isCM(err, cmCI):
		return rsp.CodeCIUnsupported.Status("None of the proposed CI key identifiers is supported")
	case isCM(err, cmUnknownTxn):
		return rsp.CodeUnknownTransaction.Status("Unknown TransactionID")
	case isCM(err, cmCertChain):
		return rsp.CodeCertChainFailed.Status(err.Error())
	case isCM(err, cmSignature), isCM(err, cmBadResponse), isCM(err, cmTxnMismatch), isCM(err, cmChallengeMismatch):
		return rsp.CodeVerificationFailed.Status(err.Error())
	case isCM(err, cmEID):
		return rsp.CodeEIDNotPermitted.Status(err.Error())
	}
	return err
}

func randomToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}

func normalizeICCID(iccid string) string { return strings.TrimRight(iccid, "fF") }
