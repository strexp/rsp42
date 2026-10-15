package es11

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	"rsp42/internal/service"
	"rsp42/internal/store"
	"rsp42/internal/testutil"
)

const testRoot = "../../../testdata/sgp26"

func newTestServer(t *testing.T) *httptest.Server {
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
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "es11.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	events := service.NewEventService(st.Events, "root", "testrootsmds.example.com", time.Hour)
	ds, err := service.NewDSService(service.DSConfig{
		FQDN: "testrootsmds.example.com", ServerPort: 9443, OID: "2.999.15", Role: "root",
		TransactionIDLen: 16, SessionTTL: 30 * time.Minute,
	}, certs, service.NewSessionService(st.Sessions, provider, 30*time.Minute), events, slog.Default())
	require.NoError(t, err)

	h := New(slog.Default(), ds)
	r := chi.NewRouter()
	r.Use(middleware.ContentType)
	Mount(r, h)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func TestES11ErrorEnums(t *testing.T) {
	// F5: the Table 52 codes the DS service emits must land on the
	// AuthenticateClientResponseEs11 members (§6.6.2.7).
	require.EqualValues(t, 3, asn1bind.CodeFor(rsp.CodeCertChainFailed.Status("x"), dsAuthenticateErrorCodes, 127))    // euiccCertificateInvalid
	require.EqualValues(t, 5, asn1bind.CodeFor(rsp.CodeVerificationFailed.Status("x"), dsAuthenticateErrorCodes, 127)) // euiccSignatureInvalid
	require.EqualValues(t, 6, asn1bind.CodeFor(rsp.CodeEventNotFound.Status("x"), dsAuthenticateErrorCodes, 127))      // eventIdUnknown
	require.EqualValues(t, 7, asn1bind.CodeFor(rsp.CodeUnknownTransaction.Status("x"), dsAuthenticateErrorCodes, 127)) // invalidTransactionId

	// The ES11 enum has no ciPKUnknown member (unlike ES9+'s ciPKUnknown(9)), so
	// Table 52's 8.11.1/3.9 falls back to undefinedError(127).
	require.EqualValues(t, 127, asn1bind.CodeFor(rsp.Code{Subject: "8.11.1", Reason: "3.9"}.Status("x"), dsAuthenticateErrorCodes, 127))

	// Table 48a's InitiateAuthentication subjects map onto the reused ES9+
	// InitiateAuthenticationResponse enum (§6.6.2.6).
	require.EqualValues(t, 1, asn1bind.CodeFor(rsp.CodeDSAddress.Status("x"), dsInitiateErrorCodes, 2))
	require.EqualValues(t, 2, asn1bind.CodeFor(rsp.CodeDSSVNUnsupported.Status("x"), dsInitiateErrorCodes, 2))
	require.EqualValues(t, 3, asn1bind.CodeFor(rsp.CodeDSCIUnsupported.Status("x"), dsInitiateErrorCodes, 2))
	// Malformed euiccChallenge/euiccInfo1: generic 8.9.1/1.2 format code, mapped
	// to the same enum value as the invalid-address row.
	require.EqualValues(t, 1, asn1bind.CodeFor(rsp.CodeDSChallengeInvalid.Status("x"), dsInitiateErrorCodes, 2))
}

func TestES11ASN1BindingInitiate(t *testing.T) {
	srv := newTestServer(t)

	challenge := bytes.Repeat([]byte{0x33}, 16)
	info := asn1.Marshal(asn1.New(asn1.Ctx(32, true),
		asn1.Prim(asn1.Ctx(2, false), []byte{0x02, 0x02, 0x00}),
	))
	req := testutil.TLV(asn1.Ctx(57, true), testutil.Concat(
		testutil.TLV(asn1.Ctx(1, false), challenge),
		testutil.TLV(asn1.Ctx(3, false), []byte("testrootsmds.example.com")),
		info,
	))

	resp, err := http.Post(srv.URL+"/gsma/rsp2/asn1", common.ContentTypeASN1, bytes.NewReader(rsp.EncodeRemoteProfileProvisioningResponse(req)))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	fn, inner, err := rsp.DecodeRemoteProfileProvisioningRequest(body)
	require.NoError(t, err)
	require.Equal(t, rsp.FuncInitiateAuthentication, fn)
	tlv, _, err := asn1.ReadTLV(inner)
	require.NoError(t, err)
	require.Equal(t, "bf39", testutil.HexTag(tlv.Tag))

	// Malformed ASN.1 and JSON bodies are rejected.
	resp, err = http.Post(srv.URL+"/gsma/rsp2/asn1", common.ContentTypeASN1, strings.NewReader("nope"))
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()

	resp, err = http.Post(srv.URL+"/gsma/rsp2/asn1", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
	_ = resp.Body.Close()
}
