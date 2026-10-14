package service

import (
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
	"rsp42/internal/cert"
	"rsp42/internal/crypto"
	"rsp42/internal/kms"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
	"rsp42/internal/testutil"
)

func setupDS(t *testing.T) (*DSService, *EventService, *store.Store) {
	t.Helper()
	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	certs, err := cert.Load(cert.Options{
		RootDir: testRoot, CI: "CertificateIssuer", EUM: "EUM", EUICC: "eUICC",
		DPAuth: "SM-DP+/DPauth", DPPb: "SM-DP+/DPpb", DPTLS: "SM-DP+/DPtls",
		DSAuth: "SM-DS/DSauth", DSTLS: "SM-DS/DStls", Curve: "nist",
		DPFQDN: testFQDN, DPOID: testOID, DSFQDN: "testrootsmds.example.com", DSOID: "2.999.15",
	}, provider)
	require.NoError(t, err)
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "ds.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	sessions := NewSessionService(st.Sessions, provider, 30*time.Minute)
	events := NewEventService(st.Events, "root", "testrootsmds.example.com", time.Hour)
	ds, err := NewDSService(
		DSConfig{FQDN: "testrootsmds.example.com", OID: "2.999.15", Role: "root", TransactionIDLen: 16, SessionTTL: 30 * time.Minute},
		certs, sessions, events, slog.Default())
	require.NoError(t, err)
	return ds, events, st
}

// euiccAuthenticate builds an AuthenticateServerResponse signed by the eUICC
// key for the given matching id (empty = none).
func euiccAuthenticate(t *testing.T, ds *DSService, matchingID string) (string, []byte) {
	t.Helper()
	euiccChallenge := make([]byte, 16)
	ciSKI := ds.Certs.CI().SubjectKeyId
	init, err := ds.Initiate(euiccChallenge, buildEUICCInfo1(ciSKI), "testrootsmds.example.com")
	require.NoError(t, err)

	ss1TLV, _, err := asn1.ReadTLV(init.ServerSigned1)
	require.NoError(t, err)
	ss1, err := rsp.DecodeServerSigned1(ss1TLV)
	require.NoError(t, err)

	txn := mustHexLower(t, init.TransactionID)
	ctxInner := tlv([]byte{0x80}, make([]byte, 8))
	var ctx []byte
	if matchingID != "" {
		ctx = tlv(tCtx0c, testutil.Concat(tlv([]byte{0x80}, []byte(matchingID)), tlv(tCtx1c, ctxInner)))
	} else {
		ctx = tlv(tCtx0c, tlv(tCtx1c, ctxInner))
	}
	euiccSigned1 := tlv(tSeq, testutil.Concat(
		tlv(tCtx0p, txn),
		tlv(tCtx3p, []byte("testrootsmds.example.com")),
		tlv(tCtx4p, ss1.ServerChallenge),
		buildEUICCInfo2(ciSKI),
		ctx,
	))
	euiccPriv, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	key, err := euiccPriv.ECDSAKey(testRoot + "/eUICC/SK_EUICC_NIST.pem")
	require.NoError(t, err)
	sig, err := crypto.SignRaw(key, euiccSigned1)
	require.NoError(t, err)
	asr := tlv(tBF38, tlv(tCtx0c, testutil.Concat(
		euiccSigned1, tlv(tSig, sig),
		readFile(t, testRoot+"/eUICC/CERT_EUICC_NIST.der"),
		readFile(t, testRoot+"/EUM/CERT_EUM_NIST.der"),
	)))
	return init.TransactionID, asr
}

func TestSMDSRegisterAndDiscover(t *testing.T) {
	ds, events, _ := setupDS(t)
	require.NoError(t, events.Register(testEID, "dp1.example.com", "EVT1", true, "2.999.10", EventMeta{}))
	require.NoError(t, events.Register(testEID, "dp2.example.com", "EVT2", true, "2.999.10", EventMeta{}))

	// Case a: empty matchingId returns all events in registration order.
	txn, asr := euiccAuthenticate(t, ds, "")
	res, err := ds.AuthenticateClient(txn, asr)
	require.NoError(t, err)
	require.Equal(t, [][2]string{{"EVT1", "dp1.example.com"}, {"EVT2", "dp2.example.com"}}, res.EventEntries)

	// Case b: matchingId = EventID returns the single event.
	txn, asr = euiccAuthenticate(t, ds, "EVT2")
	res, err = ds.AuthenticateClient(txn, asr)
	require.NoError(t, err)
	require.Equal(t, [][2]string{{"EVT2", "dp2.example.com"}}, res.EventEntries)

	// Unknown EventID -> 8.9.5/3.9.
	txn, asr = euiccAuthenticate(t, ds, "NOPE")
	_, err = ds.AuthenticateClient(txn, asr)
	require.Error(t, err)

	// Delete EVT1 and confirm it disappears.
	require.NoError(t, events.Delete(testEID, "EVT1", "2.999.10"))
	left, err := events.ListForEID(testEID)
	require.NoError(t, err)
	require.Len(t, left, 1)
	require.Equal(t, "EVT2", left[0].EventID)
}

func TestCascadeRollback(t *testing.T) {
	_, _, st := setupDS(t)
	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	_ = provider
	// An alternative DS with a failing cascade client must roll back locally.
	alt := NewEventService(st.Events, "alternative", "testsmds1.example.com", time.Hour)
	alt.Cascade = failCascade{}
	err = alt.Register(testEID, "dp.example.com", "EVT-C", true, "2.999.10", EventMeta{})
	require.Error(t, err)
	recs, err := st.Events.ListByEID(testEID)
	require.NoError(t, err)
	require.Empty(t, recs)
}

type failCascade struct{}

func (failCascade) Register(string, string, string, bool, EventMeta) error { return errCascade }
func (failCascade) Delete(string, string, EventMeta) error                 { return errCascade }
func (failCascade) IsNotFound(error) bool                                  { return false }

var errCascade = &cascadeErr{}

type cascadeErr struct{}

func (*cascadeErr) Error() string { return "cascade failed" }
