package service

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"rsp42/internal/asn1"
	"rsp42/internal/cert"
	"rsp42/internal/crypto"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

// certProvider is the minimal certificate interface the CMAE core needs. Both
// the SM-DP+ and SM-DS provide it (via cert.Manager).
type certProvider interface {
	// SelectIdentity picks the certificate identity whose CI matches one of the
	// eUICC-proposed CI key identifiers.
	SelectIdentity(proposed [][]byte) (*cert.Identity, error)
	// IdentityByCIKeyID returns the identity owning a CI SubjectKeyIdentifier.
	IdentityByCIKeyID(ski []byte) *cert.Identity
	CI() *x509.Certificate
}

// ecdsaKey asserts that a crypto.Signer is an ECDSA private key.
//
// It wraps cert.ECDSAKey because the message reaches the ES9+ client through
// common.WriteStatusFailure, which renders a non-StatusCode error as the
// failure message: the text and its "service:" prefix are part of the observed
// response and must not move with the helper.
func ecdsaKey(s stdcrypto.Signer) (*ecdsa.PrivateKey, error) {
	k, ok := cert.ECDSAKey(s)
	if !ok {
		return nil, fmt.Errorf("service: key is not ECDSA")
	}
	return k, nil
}

// cmKind classifies a CMAE failure so each role can map it to its own
// interface-specific status code (ES9+ 8.x vs ES11 8.9.x).
type cmKind int

const (
	cmAddress cmKind = iota
	cmChallenge
	cmCI
	cmUnknownTxn
	cmBadResponse
	cmCertChain
	cmSignature
	cmEID
	cmTxnMismatch
	cmChallengeMismatch
)

// cmError is a typed CMAE error.
type cmError struct {
	kind   cmKind
	detail string
}

func (e *cmError) Error() string { return "cmae: " + e.detail }

func cmErr(kind cmKind, detail string) *cmError { return &cmError{kind: kind, detail: detail} }
func cmErrf(kind cmKind, format string, a ...any) *cmError {
	return &cmError{kind: kind, detail: fmt.Sprintf(format, a...)}
}

func isCM(err error, kind cmKind) bool {
	var e *cmError
	return errors.As(err, &e) && e.kind == kind
}

// InitiateResult is the response to InitiateAuthentication (ES9+/ES11).
type InitiateResult struct {
	TransactionID       string
	ServerSigned1       []byte
	ServerSignature1    []byte
	EuiccCiPKIDToBeUsed []byte
	ServerCertificate   []byte
}

// clientAuth is the verified outcome of AuthenticateClient, before any
// service-specific processing.
type clientAuth struct {
	Session    *store.Session
	Response   *rsp.AuthenticateResponseOk
	EID        string
	MatchingID string
	Signed1    *rsp.EuiccSigned1
	EuiccCert  *x509.Certificate
	EumCert    *x509.Certificate
}

// cmaeCore implements the Common Mutual Authentication handshake shared by the
// SM-DP+ (ES9+) and SM-DS (ES11).
type cmaeCore struct {
	fqdn       string
	port       int
	authCert   *x509.Certificate
	authKey    stdcrypto.Signer
	certs      certProvider
	sessions   *SessionService
	txnLen     int
	sessionTTL time.Duration
	useDSAuth  bool
	log        *slog.Logger
}

// port is the ES9+/ES11 listening port, so a request carrying "FQDN:port" is
// accepted when the port is the one this server actually serves (SGP.22 §4.1).
func newCMAECore(fqdn string, port int, authCert *x509.Certificate, authKey stdcrypto.Signer, certs certProvider, sessions *SessionService, txnLen int, ttl time.Duration, useDSAuth bool, log *slog.Logger) *cmaeCore {
	if txnLen <= 0 {
		txnLen = 16
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &cmaeCore{fqdn: fqdn, port: port, authCert: authCert, authKey: authKey, certs: certs, sessions: sessions, txnLen: txnLen, sessionTTL: ttl, useDSAuth: useDSAuth, log: log}
}

// authFor returns the authentication certificate/key of the identity for the
// core's role, falling back to the configured primary pair.
func (c *cmaeCore) authFor(id *cert.Identity) (*x509.Certificate, stdcrypto.Signer) {
	if id != nil {
		if c.useDSAuth && id.DSAuthCert != nil {
			return id.DSAuthCert, id.DSAuthKey
		}
		if !c.useDSAuth && id.DPAuthCert != nil {
			return id.DPAuthCert, id.DPAuthKey
		}
	}
	return c.authCert, c.authKey
}

// initiate implements InitiateAuthentication (SGP.22 §5.6.1 / §5.8.1).
func (c *cmaeCore) initiate(euiccChallenge, euiccInfo1 []byte, address string) (*InitiateResult, error) {
	if !addressMatches(address, c.fqdn, c.port) {
		return nil, cmErr(cmAddress, "server address mismatch")
	}
	if len(euiccChallenge) != 16 {
		return nil, cmErr(cmChallenge, "euiccChallenge must be 16 bytes")
	}
	info, err := rsp.ParseEUICCInfo1(euiccInfo1)
	if err != nil {
		return nil, cmErr(cmBadResponse, "invalid euiccInfo1: "+err.Error())
	}
	proposed := append(append([][]byte{}, info.CiPKIDListForSigning...), info.CiPKIDListForSigningV3...)
	id, err := c.certs.SelectIdentity(proposed)
	if err != nil {
		return nil, cmErr(cmCI, "none of the proposed CI key identifiers is supported")
	}
	ci := id.CI

	transactionID := make([]byte, c.txnLen)
	if _, err := rand.Read(transactionID); err != nil {
		return nil, err
	}
	serverChallenge := make([]byte, 16)
	if _, err := rand.Read(serverChallenge); err != nil {
		return nil, err
	}

	authCert, authSigner := c.authFor(id)
	authKey, err := ecdsaKey(authSigner)
	if err != nil {
		return nil, err
	}
	ss := &rsp.ServerSigned1{
		TransactionID:   transactionID,
		EuiccChallenge:  euiccChallenge,
		ServerAddress:   c.fqdn,
		ServerChallenge: serverChallenge,
	}
	serverSigned1 := ss.Encode()
	sig, err := crypto.SignRaw(authKey, serverSigned1)
	if err != nil {
		return nil, err
	}

	txnHex := strings.ToUpper(hex.EncodeToString(transactionID))
	if err := c.sessions.Put(&store.Session{
		TransactionID:   txnHex,
		State:           "initiated",
		ServerChallenge: serverChallenge,
		ServerSigned1:   serverSigned1,
		CICertID:        ci.SubjectKeyId,
		ExpiresAt:       time.Now().UTC().Add(c.sessionTTL),
	}); err != nil {
		return nil, err
	}

	return &InitiateResult{
		TransactionID:       txnHex,
		ServerSigned1:       serverSigned1,
		ServerSignature1:    rsp.WrapSignature(sig),
		EuiccCiPKIDToBeUsed: append([]byte{0x04, 0x14}, ci.SubjectKeyId...),
		ServerCertificate:   authCert.Raw,
	}, nil
}

// verify performs the full AuthenticateClient verification (SGP.22 §5.6.3 /
// §5.8.2) and returns the verified material without any service-specific
// processing.
func (c *cmaeCore) verify(transactionID string, authenticateServerResponse []byte) (*clientAuth, error) {
	sess, err := c.sessions.Get(transactionID)
	if err != nil {
		return nil, cmErr(cmUnknownTxn, "unknown TransactionID")
	}
	ok, errResp, err := rsp.DecodeAuthenticateServerResponse(authenticateServerResponse)
	if err != nil {
		return nil, cmErr(cmBadResponse, err.Error())
	}
	if ok == nil {
		code := int64(127)
		if errResp != nil {
			code = errResp.AuthenticateErrorCode
		}
		return nil, cmErrf(cmBadResponse, "authenticateResponseError %d", code)
	}

	euiccCert, err := x509.ParseCertificate(ok.EuiccCertificate)
	if err != nil {
		return nil, cmErr(cmCertChain, "invalid eUICC certificate")
	}
	eumCert, err := x509.ParseCertificate(ok.EumCertificate)
	if err != nil {
		return nil, cmErr(cmCertChain, "invalid EUM certificate")
	}
	intermediates, err := cert.ParseCertificates(ok.OtherCertsInChain)
	if err != nil {
		return nil, cmErr(cmCertChain, "invalid certificate in otherCertsInChain")
	}
	ci := c.certs.CI()
	if id := c.certs.IdentityByCIKeyID(sess.CICertID); id != nil {
		ci = id.CI
	}
	if err := cert.ValidateEUICCChain(euiccCert, eumCert, intermediates, ci, sess.CICertID); err != nil {
		return nil, cmErr(cmCertChain, err.Error())
	}

	euiccSigned1Raw, err := rsp.ExtractEuiccSigned1(authenticateServerResponse)
	if err != nil {
		return nil, cmErr(cmSignature, err.Error())
	}
	pub, okPub := euiccCert.PublicKey.(*ecdsa.PublicKey)
	if !okPub || !crypto.VerifyRaw(pub, euiccSigned1Raw, rsp.SignatureValue(ok.EuiccSignature1)) {
		return nil, cmErr(cmSignature, "eUICC signature verification failed")
	}

	tlv, _, err := asn1.ReadTLV(euiccSigned1Raw)
	if err != nil {
		return nil, cmErr(cmBadResponse, err.Error())
	}
	signed1, err := rsp.DecodeEuiccSigned1(tlv)
	if err != nil {
		return nil, cmErr(cmBadResponse, err.Error())
	}
	if !strings.EqualFold(hex.EncodeToString(signed1.TransactionID), transactionID) {
		return nil, cmErr(cmTxnMismatch, "transactionId mismatch")
	}
	if !bytes.Equal(signed1.ServerChallenge, sess.ServerChallenge) {
		return nil, cmErr(cmChallengeMismatch, "serverChallenge mismatch")
	}

	eid := cert.EIDFromCert(euiccCert)
	if eid == "" {
		return nil, cmErr(cmEID, "eUICC certificate has no EID")
	}
	if constraints, err := cert.ParseEUMConstraints(eumCert); err == nil && constraints != nil {
		if err := constraints.ValidateEID(eid); err != nil {
			return nil, cmErr(cmEID, err.Error())
		}
	}

	ca := &clientAuth{Session: sess, Response: ok, EID: eid, Signed1: signed1, EuiccCert: euiccCert, EumCert: eumCert}
	if signed1.CtxParams1 != nil {
		ca.MatchingID = signed1.CtxParams1.MatchingID
	}
	return ca, nil
}
