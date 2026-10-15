package es9plus

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"rsp42/internal/uppio"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"rsp42/internal/api/asn1bind"
	"rsp42/internal/api/common"
	"rsp42/internal/api/middleware"
	"rsp42/internal/asn1"
	"rsp42/internal/cert"
	"rsp42/internal/kms"
	"rsp42/internal/rsp"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/service"
	"rsp42/internal/store"
	"rsp42/internal/testutil"
)

const testRoot = "../../../testdata/sgp26"

func newTestHandler(t *testing.T) (*Handler, *cert.Manager) {
	t.Helper()
	provider, err := kms.NewFileProviderFromKEK([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	certs, err := cert.Load(cert.Options{
		RootDir: testRoot, CI: "CertificateIssuer", EUM: "EUM", EUICC: "eUICC",
		DPAuth: "SM-DP+/DPauth", DPPb: "SM-DP+/DPpb", DPTLS: "SM-DP+/DPtls",
		DSAuth: "SM-DS/DSauth", DSTLS: "SM-DS/DStls", Curve: "nist",
		DPFQDN: "testsmdpplus1.example.com", DPOID: "2.999.10",
		DSFQDN: "testrootsmds.example.com", DSOID: "2.999.15",
	}, provider)
	require.NoError(t, err)

	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "asn1.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	policy, err := service.NewSAIPVersionPolicy([]string{"2.3"})
	require.NoError(t, err)
	_, err = uppio.Import("../../../testdata/upp", st.UPP, policy.CheckVersionErr)
	require.NoError(t, err)

	cmae, err := service.NewCMAE(service.CMAEConfig{
		FQDN: "testsmdpplus1.example.com", ServerPort: 8443, OID: "2.999.10", HostID: make([]byte, 8),
		TransactionIDLen: 16, MaxDownloadAttempts: 5, MaxCCAttempts: 3,
		SessionTTL: 30 * time.Minute, DownloadTTL: 24 * time.Hour,
	}, service.CMAEDeps{
		Certs: certs, Sessions: service.NewSessionService(st.Sessions, provider, 30*time.Minute),
		Profiles: st.Profiles, UPP: st.UPP, DefaultUPP: "TS48v1_A.der",
		Engine: &personalization.Engine{Algorithm: "milenage"}, Log: slog.Default(),
	})
	require.NoError(t, err)
	return New(slog.Default(), cmae), certs
}

func newTestServer(t *testing.T, h *Handler) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Use(middleware.ContentType)
	Mount(r, h)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func euiccInfo1(ski []byte) []byte {
	return asn1.Marshal(asn1.New(asn1.Ctx(32, true),
		asn1.Prim(asn1.Ctx(2, false), []byte{0x02, 0x02, 0x00}),
		asn1.New(asn1.Ctx(9, true), asn1.Octet(ski)),
		asn1.New(asn1.Ctx(10, true), asn1.Octet(ski)),
	))
}

func envelope(inner []byte) []byte { return rsp.EncodeRemoteProfileProvisioningResponse(inner) }

func TestES9PlusErrorEnums(t *testing.T) {
	// F4/F6: each reason code under a shared subject maps to its own
	// AuthenticateClientResponseEs9 member (§6.6.2.2, Table 43).
	require.EqualValues(t, 7, asn1bind.CodeFor(rsp.CodeEIDMismatch.Status("x"), authenticateErrorCodes, 127))           // eidMismatch
	require.EqualValues(t, 6, asn1bind.CodeFor(rsp.CodeProfileNotEligible.Status("x"), authenticateErrorCodes, 127))    // matchingIdRefused
	require.EqualValues(t, 8, asn1bind.CodeFor(rsp.CodeNoEligibleProfile.Status("x"), authenticateErrorCodes, 127))     // noEligibleProfile
	require.EqualValues(t, 3, asn1bind.CodeFor(rsp.CodeCertChainFailed.Status("x"), authenticateErrorCodes, 127))       // euiccCertificateInvalid
	require.EqualValues(t, 5, asn1bind.CodeFor(rsp.CodeVerificationFailed.Status("x"), authenticateErrorCodes, 127))    // euiccSignatureInvalid
	require.EqualValues(t, 10, asn1bind.CodeFor(rsp.CodeUnknownTransaction.Status("x"), authenticateErrorCodes, 127))   // invalidTransactionId
	require.EqualValues(t, 18, asn1bind.CodeFor(rsp.CodeDownloadOrderExpired.Status("x"), authenticateErrorCodes, 127)) // downloadOrderExpired
	// 8.2/1.2 (not yet released) and 8.8.5/6.4 (retries exceeded) have no enum
	// member: undefinedError(127).
	require.EqualValues(t, 127, asn1bind.CodeFor(rsp.CodeProfileNotReleased.Status("x"), authenticateErrorCodes, 127))
	require.EqualValues(t, 127, asn1bind.CodeFor(rsp.CodeDownloadRetriesExceeded.Status("x"), authenticateErrorCodes, 127))

	// F6: the GetBoundProfilePackage confirmation-code rows are distinguished
	// (§6.6.2.3, Table 40).
	require.EqualValues(t, 3, asn1bind.CodeFor(rsp.CodeConfirmationCodeRefused.Status("x"), getBPPErrorCodes, 127))
	require.EqualValues(t, 4, asn1bind.CodeFor(rsp.CodeConfirmationCode.Status("x"), getBPPErrorCodes, 127))
	require.EqualValues(t, 95, asn1bind.CodeFor(rsp.CodeUnknownTransaction.Status("x"), getBPPErrorCodes, 127))

	// F4: the InitiateAuthentication enum (§6.6.2.1, Table 37).
	require.EqualValues(t, 1, asn1bind.CodeFor(rsp.CodeSMDPAddress.Status("x"), initiateErrorCodes, 2))
	require.EqualValues(t, 3, asn1bind.CodeFor(rsp.CodeCIUnsupported.Status("x"), initiateErrorCodes, 2))
}

func TestASN1BindingContentNegotiation(t *testing.T) {
	h, _ := newTestHandler(t)
	srv := newTestServer(t, h)

	// JSON to the ASN.1 path is rejected by the handler.
	resp, err := http.Post(srv.URL+"/gsma/rsp2/asn1", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
	_ = resp.Body.Close()

	// Malformed ASN.1 body.
	resp, err = http.Post(srv.URL+"/gsma/rsp2/asn1", common.ContentTypeASN1, strings.NewReader("not-tlv"))
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestASN1BindingInitiateFlow(t *testing.T) {
	h, certs := newTestHandler(t)
	srv := newTestServer(t, h)

	challenge := bytes.Repeat([]byte{0x5a}, 16)
	req := testutil.TLV(asn1.Ctx(57, true), testutil.Concat(
		testutil.TLV(asn1.Ctx(1, false), challenge),
		testutil.TLV(asn1.Ctx(3, false), []byte("testsmdpplus1.example.com")),
		euiccInfo1(certs.CI().SubjectKeyId),
	))

	resp, err := http.Post(srv.URL+"/gsma/rsp2/asn1", common.ContentTypeASN1, bytes.NewReader(envelope(req)))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, common.ContentTypeASN1, resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	fn, inner, err := rsp.DecodeRemoteProfileProvisioningRequest(body)
	require.NoError(t, err)
	require.Equal(t, rsp.FuncInitiateAuthentication, fn)

	tlv, _, err := asn1.ReadTLV(inner)
	require.NoError(t, err)
	require.Equal(t, "bf39", testutil.HexTag(tlv.Tag))
	ok, found := tlv.Find(asn1.Ctx(0, true))
	require.True(t, found, "expected an A0 OK branch")
	txn, found := ok.Find(asn1.Ctx(0, false))
	require.True(t, found)
	require.Len(t, txn.Value, 16)
	// serverSigned1 (SEQUENCE), serverSignature1 (5F37), euiccCiPKIdToBeUsed (04)
	_, hasSeq := ok.Find([]byte{0x30})
	require.True(t, hasSeq)
	_, hasSig := ok.Find(asn1.App(55, false))
	require.True(t, hasSig)
	_, hasSKI := ok.Find(asn1.TagOctetStr)
	require.True(t, hasSKI)
}
