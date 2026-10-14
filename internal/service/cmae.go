package service

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"rsp42/internal/activationcode"
	"rsp42/internal/cert"
	"rsp42/internal/crypto"
	"rsp42/internal/metrics"
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
// CMAEDeps is the dependency set of the SM-DP+ authentication/download service.
// Everything needed at construction time is here; Notify and ACRCheck are the
// exception because they deliver through the operator callback queue, which is
// built from the CMAE (and the notification service), and are installed by the
// composition root's callback wiring.
type CMAEDeps struct {
	Certs           *cert.Manager
	Sessions        *SessionService
	Profiles        ProfileStore
	Personalization PersonalizationResolver
	UPP             UPPStore
	DefaultUPP      string
	Engine          *personalization.Engine
	Log             *slog.Logger
	// Tenants resolves the tenant default template; optional.
	Tenants TenantLookup
	// Audit, when set, records eUICC-capability failures that the HTTP audit
	// middleware cannot observe (ES9+ answers HTTP 200 with an RSP status).
	Audit *store.AuditRepo
	// Metrics, when set, counts V3-capable eUICCs and version failures (N11/N12).
	Metrics *metrics.Registry
}

type CMAE struct {
	Cfg  CMAEConfig
	Deps CMAEDeps
	// Notify, when set, delivers ES2+ progress notifications (SGP.22 §5.3.5).
	Notify OperatorCallback
	// ACRCheck, when set, calls the Operator's ES2+.HandleAcrRequest to confirm
	// an Activation Code Retrieval (SGP.22 §5.3.8). It is invoked for both ACR
	// types (redownload and availability check) and its refusal fails the
	// retrieval.
	ACRCheck func(ctx context.Context, profile *store.Profile) error

	core *cmaeCore
}

// NewCMAE builds an SM-DP+ CMAE using CERT.DPauth for server signatures.
func NewCMAE(cfg CMAEConfig, d CMAEDeps) (*CMAE, error) {
	if d.Certs == nil || d.Certs.DPAuth() == nil || d.Certs.DPAuthKey() == nil {
		return nil, fmt.Errorf("cmae: CERT.DPAuth/SK.DPAuth not configured")
	}
	if d.UPP == nil {
		return nil, fmt.Errorf("cmae: UPP template store not configured")
	}
	c := &CMAE{Cfg: cfg, Deps: d}
	c.core = newCMAECore(cfg.FQDN, d.Certs.DPAuth(), d.Certs.DPAuthKey(), d.Certs, d.Sessions,
		cfg.TransactionIDLen, cfg.SessionTTL, false, d.Log)
	return c, nil
}

// identityFor returns the certificate identity selected for a session, or nil
// when the primary identity applies.
func (c *CMAE) identityFor(sess *store.Session) *cert.Identity {
	if sess == nil || len(sess.CICertID) == 0 {
		return nil
	}
	return c.Deps.Certs.IdentityByCIKeyID(sess.CICertID)
}

// pbFor returns the profile-binding certificate/key for a session's identity.
func (c *CMAE) pbFor(sess *store.Session) (*x509.Certificate, stdcrypto.Signer) {
	if id := c.identityFor(sess); id != nil && id.DPPbCert != nil {
		return id.DPPbCert, id.DPPbKey
	}
	return c.Deps.Certs.DPPb(), c.Deps.Certs.DPPbKey()
}

// notify delivers an operator progress notification if configured.
func (c *CMAE) notify(ctx context.Context, info ProgressInfo) {
	if c.Notify != nil {
		if err := c.Notify(ctx, info); err != nil && c.Deps.Log != nil {
			c.Deps.Log.Warn("operator callback", "point", info.NotificationPointID, "err", err)
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

// AuthenticateClient implements ES9+.AuthenticateClient (SGP.22 §5.6.3). ctx
// bounds any outbound call made on behalf of the request (currently the
// Operator's ES2+.HandleAcrRequest confirmation).
func (c *CMAE) AuthenticateClient(ctx context.Context, transactionID string, authenticateServerResponse []byte) (*AuthenticateResult, error) {
	ca, err := c.core.verify(transactionID, authenticateServerResponse)
	if err != nil {
		return nil, mapDPStatus(err)
	}

	// Activation Code Retrieval (§3.1.7/§3.1.8).
	if activationcode.IsACR(ca.MatchingID) {
		return c.handleACR(ctx, transactionID, ca)
	}

	profile, err := c.lookupProfile(ca.MatchingID, ca.EID)
	if err != nil {
		return nil, err
	}
	// Bind the profile to the eUICC that actually performs the download (G4):
	// an anonymously claimed profile has no EID until the LPA authenticates,
	// and without this the same activation code could be downloaded by several
	// devices. registerDownloadAttempt persists the change.
	if profile.EID == "" && ca.EID != "" {
		profile.EID = ca.EID
		if profile.State == store.StateAllocated {
			profile.State = store.StateLinked
		}
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
	// N11: persist the eUICC's advertised SAIP versions (profileVersion plus
	// additionalEuiccProfilePackageVersions) so the template compatibility
	// check can run again at GetBoundProfilePackage.
	if info := ca.Signed1.EuiccInfo2; info != nil {
		c.recordEuiccVersions(profile.TenantID, sess, info)
	}
	// N12: resolve the template now and fail cleanly when nothing compatible
	// exists, rather than letting the eUICC reject the package at the very end
	// of the download. The resolved template is remembered on the session.
	tpl, err := c.resolveUPPTemplate(profile, sess)
	if err != nil {
		var vErr *ErrProfileVersionNotSupported
		if errors.As(err, &vErr) {
			c.noteVersionFailure(profile.TenantID, profile, vErr)
			return nil, rsp.CodeProfileVersionNotSupported.Status(vErr.Error())
		}
		return nil, rsp.CodeProfileLoadFailed.Status(err.Error())
	}
	sess.UPPTemplate = tpl.Name
	if err := c.Deps.Sessions.Put(sess); err != nil {
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

// recordEuiccVersions stores the eUICC's advertised SAIP versions and V3
// capability on the session (N11). The version set drives the template
// compatibility check; the V3 marker is surfaced as a counter for the SEC
// qualification work on the esim42 side.
func (c *CMAE) recordEuiccVersions(tenant string, sess *store.Session, info *rsp.EUICCInfo2) {
	if v, ok := info.ProfilePackageVersion(); ok {
		sess.EuiccProfileVersion = v.String()
	}
	for _, v := range info.SupportedVersions() {
		sess.EuiccSupportedVersions = append(sess.EuiccSupportedVersions, v.String())
	}
	if len(info.UICCCapability) > 0 {
		sess.UICCCapability = hex.EncodeToString(info.UICCCapability)
	}
	if info.IsV3Capable() && c.Deps.Metrics != nil {
		c.Deps.Metrics.Inc("rsp42_euicc_v3_capable_total", map[string]string{"tenant": tenant})
	}
}

// noteVersionFailure makes an N12 clean failure observable. The ES9+ audit
// middleware cannot see it because ES9+ answers HTTP 200 with an RSP status
// code in the body, so the failure is recorded explicitly.
func (c *CMAE) noteVersionFailure(tenant string, profile *store.Profile, rej *ErrProfileVersionNotSupported) {
	if c.Deps.Metrics != nil {
		c.Deps.Metrics.Inc("rsp42_profile_version_not_supported_total", map[string]string{"tenant": tenant})
	}
	if c.Deps.Log != nil {
		c.Deps.Log.Warn("profile version not supported",
			"iccid", profile.ICCID, "tenant", tenant,
			"euiccProfileVersion", rej.EuiccProfileVersion, "supportedVersions", rej.SupportedVersions)
	}
	if c.Deps.Audit == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"iccid":                 profile.ICCID,
		"euiccProfileVersion":   rej.EuiccProfileVersion,
		"supportedVersions":     rej.SupportedVersions,
		"lowestTemplateVersion": rej.LowestTemplateVersion,
	})
	_ = c.Deps.Audit.Insert(&store.AuditEntry{
		TenantID: tenant, Interface: "es9p", Function: "authenticateClient",
		Subject: profile.ICCID, Outcome: "Failed", DetailJSON: string(detail),
	})
}

func (c *CMAE) lookupProfile(matchingID, eid string) (*store.Profile, error) {
	if matchingID == "" {
		return nil, rsp.CodeProfileNotEligible.Status("Refused")
	}
	p, err := c.Deps.Profiles.GetByMatchingID(matchingID)
	if err != nil {
		return nil, rsp.CodeProfileNotEligible.Status("Refused")
	}
	if p.EID != "" && p.EID != eid {
		return nil, rsp.CodeProfileNotEligible.Status("EID mismatch")
	}
	switch p.State {
	case store.StateReleased, store.StateDownloaded:
	default:
		return nil, rsp.CodeProfileNotEligible.Status("Profile not eligible for download")
	}
	// Download order TTL: an order that is older than the configured window is
	// no longer eligible for download.
	if c.Cfg.DownloadTTL > 0 && !p.CreatedAt.IsZero() && time.Since(p.CreatedAt) > c.Cfg.DownloadTTL {
		return nil, rsp.CodeProfileNotEligible.Status("Download order expired")
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
		if err := c.Deps.Profiles.Update(p); err != nil {
			return err
		}
		c.notify(context.Background(), progressFor(p, p.EID, 1, "Failed"))
		return rsp.CodeProfileNotEligible.Status("Download attempts exceeded")
	}
	return c.Deps.Profiles.Update(p)
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
