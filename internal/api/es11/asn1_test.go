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

	"rsp42/internal/api/common"
	"rsp42/internal/api/middleware"
	"rsp42/internal/asn1"
	"rsp42/internal/cert"
	"rsp42/internal/kms"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
	"rsp42/internal/store"
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
		FQDN: "testrootsmds.example.com", OID: "2.999.15", Role: "root",
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

func TestES11ASN1BindingInitiate(t *testing.T) {
	srv := newTestServer(t)

	challenge := bytes.Repeat([]byte{0x33}, 16)
	info := asn1.Marshal(asn1.New(asn1.Ctx(32, true),
		asn1.Prim(asn1.Ctx(2, false), []byte{0x02, 0x02, 0x00}),
	))
	req := tlvOf(asn1.Ctx(57, true), concat(
		tlvOf(asn1.Ctx(1, false), challenge),
		tlvOf(asn1.Ctx(3, false), []byte("testrootsmds.example.com")),
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
	require.Equal(t, "bf39", hexTagOf(tlv.Tag))

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

func tlvOf(tag, content []byte) []byte {
	out := append([]byte{}, tag...)
	out = append(out, asn1.EncodeLength(len(content))...)
	return append(out, content...)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func hexTagOf(tag []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, len(tag)*2)
	for _, b := range tag {
		out = append(out, h[b>>4], h[b&0x0f])
	}
	return string(out)
}
