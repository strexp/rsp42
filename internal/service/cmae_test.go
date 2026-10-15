package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/activationcode"
	"rsp42/internal/asn1"
	"rsp42/internal/cert"
	"rsp42/internal/crypto"
	"rsp42/internal/kms"
	"rsp42/internal/rsp"
	"rsp42/internal/saip"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/store"
	"rsp42/internal/testutil"
	"rsp42/internal/uppio"
)

const (
	testEID  = "89049032123451234512345678901235"
	testFQDN = "testsmdpplus1.example.com"
	// testES9PPort is the port the test SM-DP+ pretends to listen on; an
	// SM-DP+ address carrying it must be accepted (SGP.22 §4.1).
	testES9PPort = 8443
	testOID      = "2.999.10"
	testRoot     = "../../testdata/sgp26"
)

// testKEK is a fixed 32-byte key-encryption key for tests.
var testKEK = []byte("0123456789abcdef0123456789abcdef")

func tlv(tag, content []byte) []byte {
	out := append([]byte{}, tag...)
	out = append(out, asn1.EncodeLength(len(content))...)
	return append(out, content...)
}

var (
	tCtx0p = []byte{0x80}
	tCtx3p = []byte{0x83}
	tCtx4p = []byte{0x84}
	tCtx1c = []byte{0xa1}
	tCtx0c = []byte{0xa0}
	tBF22  = []byte{0xbf, 0x22}
	tBF38  = []byte{0xbf, 0x38}
	tBF21  = []byte{0xbf, 0x21}
	tSeq   = []byte{0x30}
	tSig   = []byte{0x5f, 0x37}
	tOtpk  = []byte{0x5f, 0x49}
)

func buildEUICCInfo1(ski []byte) []byte {
	return tlv([]byte{0xbf, 0x20},
		testutil.Concat(
			tlv([]byte{0x82}, []byte{0x02, 0x02, 0x00}),
			tlv([]byte{0xa9}, tlv([]byte{0x04}, ski)),
			tlv([]byte{0xaa}, tlv([]byte{0x04}, ski)),
		))
}

func buildEUICCInfo2(ski []byte) []byte {
	return buildEUICCInfo2WithForbiddenPPR(ski, nil)
}

// buildEUICCInfo2WithForbiddenPPR is buildEUICCInfo2 plus the
// forbiddenProfilePolicyRules [25] BIT STRING (SGP.22 §5.7.5). forbidden is the
// raw bitmap in the form rsp.PPRIDBits produces; the BIT STRING unused-bits
// octet is prepended here.
func buildEUICCInfo2WithForbiddenPPR(ski, forbidden []byte) []byte {
	fields := [][]byte{
		tlv([]byte{0x81}, []byte{0x02, 0x02, 0x00}),
		tlv([]byte{0x82}, []byte{0x02, 0x02, 0x00}),
		tlv([]byte{0x83}, []byte{0x02, 0x02, 0x00}),
		tlv([]byte{0x84}, nil),
		tlv([]byte{0x85}, []byte{0x00}),
		tlv([]byte{0x88}, []byte{0x00}),
		tlv([]byte{0xa9}, tlv([]byte{0x04}, ski)),
		tlv([]byte{0xaa}, tlv([]byte{0x04}, ski)),
	}
	if forbidden != nil {
		fields = append(fields, tlv([]byte{0x99}, append([]byte{0x00}, forbidden...)))
	}
	fields = append(fields,
		tlv([]byte{0x04}, []byte{0x02, 0x00, 0x00}),
		tlv([]byte{0x0c}, []byte("x")),
	)
	return tlv(tBF22, testutil.Concat(fields...))
}

func setupCMAE(t *testing.T) (*CMAE, *store.Store) {
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

	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "cmae.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	// UPP templates live in the registry; seed it from the test fixtures.
	policy, err := NewSAIPVersionPolicy([]string{"2.3"})
	require.NoError(t, err)
	_, err = uppio.Import("../../testdata/upp", st.UPP, policy.CheckVersionErr)
	require.NoError(t, err)

	perso := NewPersonalizationService(st.Perso, provider)
	cmae, err := NewCMAE(CMAEConfig{
		FQDN: testFQDN, ServerPort: testES9PPort, OID: testOID, HostID: make([]byte, 8),
		TransactionIDLen: 16, MaxDownloadAttempts: 5, MaxCCAttempts: 3,
		SessionTTL: 30 * time.Minute, DownloadTTL: 24 * time.Hour,
	}, CMAEDeps{
		Certs: certs, Sessions: NewSessionService(st.Sessions, provider, 30*time.Minute),
		Profiles: st.Profiles, Personalization: perso, UPP: st.UPP, DefaultUPP: "TS48v1_A.der",
		Engine: &personalization.Engine{Algorithm: "milenage"}, Log: slog.Default(),
	})
	require.NoError(t, err)
	return cmae, st
}

// TestFullDownloadFlow drives initiate -> authenticate -> getBoundProfilePackage
// with a simulated eUICC and verifies the returned BPP decrypts to the UPP.
func TestFullDownloadFlow(t *testing.T) {
	cmae, st := setupCMAE(t)

	// Prepare a released profile with a matching id.
	inv := NewInventory(st.Profiles, "8900012", "00101")
	profile, err := inv.Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	profile.MatchingID = "MATCH-1"
	require.NoError(t, st.Profiles.Update(profile))
	orders := NewOrderService(st.Profiles)
	_, err = orders.Confirm(profile.ICCID, true)
	require.NoError(t, err)

	// --- InitiateAuthentication ---
	euiccChallenge := make([]byte, 16)
	_, _ = rand.Read(euiccChallenge)
	ciSKI := cmae.Deps.Certs.CI().SubjectKeyId
	init, err := cmae.Initiate(euiccChallenge, buildEUICCInfo1(ciSKI), testFQDN)
	require.NoError(t, err)

	// Verify serverSignature1 over serverSigned1 with CERT.DPauth.
	dpAuthPub := cmae.Deps.Certs.DPAuth().PublicKey.(*ecdsa.PublicKey)
	require.True(t, crypto.VerifyRaw(dpAuthPub, init.ServerSigned1, rsp.SignatureValue(init.ServerSignature1)))

	serverSigned1, _, err := asn1.ReadTLV(init.ServerSigned1)
	require.NoError(t, err)
	ss1, err := rsp.DecodeServerSigned1(serverSigned1)
	require.NoError(t, err)
	require.Equal(t, euiccChallenge, ss1.EuiccChallenge)

	// --- eUICC builds AuthenticateServerResponse ---
	txn := mustHexLower(t, init.TransactionID)
	euiccSigned1 := tlv(tSeq, testutil.Concat(
		tlv(tCtx0p, txn),
		tlv(tCtx3p, []byte(testFQDN)),
		tlv(tCtx4p, ss1.ServerChallenge),
		buildEUICCInfo2(ciSKI),
		tlv(tCtx0c, testutil.Concat(
			tlv([]byte{0x80}, []byte("MATCH-1")),
			tlv(tCtx1c, testutil.Concat(tlv([]byte{0x80}, make([]byte, 8)), tlv(tCtx1c, nil))),
		)),
	))
	euiccKey, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	euiccPriv, err := euiccKey.ECDSAKey(testRoot + "/eUICC/SK_EUICC_NIST.pem")
	require.NoError(t, err)
	euiccSig1, err := crypto.SignRaw(euiccPriv, euiccSigned1)
	require.NoError(t, err)

	euiccCertDER := readFile(t, testRoot+"/eUICC/CERT_EUICC_NIST.der")
	eumCertDER := readFile(t, testRoot+"/EUM/CERT_EUM_NIST.der")
	asr := tlv(tBF38, tlv(tCtx0c, testutil.Concat(
		euiccSigned1,
		tlv(tSig, euiccSig1),
		euiccCertDER,
		eumCertDER,
	)))

	auth, err := cmae.AuthenticateClient(context.Background(), init.TransactionID, asr)
	require.NoError(t, err)

	// Verify smdpSignature2 over smdpSigned2 || euiccSignature1.
	dpPbPub := cmae.Deps.Certs.DPPb().PublicKey.(*ecdsa.PublicKey)
	require.True(t, crypto.VerifyRaw(dpPbPub, testutil.Concat(auth.SmdpSigned2, tlv(tSig, euiccSig1)), rsp.SignatureValue(auth.SmdpSignature2)))

	// --- eUICC builds PrepareDownloadResponse ---
	euiccOtSK := make([]byte, 32)
	_, _ = rand.Read(euiccOtSK)
	euiccOtpk, err := crypto.ECPointFromPrivate(euiccOtSK)
	require.NoError(t, err)
	euiccSigned2 := tlv(tSeq, testutil.Concat(tlv(tCtx0p, txn), tlv(tOtpk, euiccOtpk)))
	euiccSig2, err := crypto.SignRaw(euiccPriv, testutil.Concat(euiccSigned2, auth.SmdpSignature2))
	require.NoError(t, err)
	pdr := tlv(tBF21, tlv(tCtx0c, testutil.Concat(euiccSigned2, tlv(tSig, euiccSig2))))

	got, err := cmae.GetBoundProfilePackage(init.TransactionID, pdr)
	require.NoError(t, err)

	// The Profile must be Downloaded so that a later install notification can
	// transition it to Installed (SGP.22 §3.1.6).
	after, err := st.Profiles.GetByICCID(profile.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateDownloaded, after.State)

	// --- Verify the BPP ---
	bpp, err := rsp.DecodeBoundProfilePackage(got.BoundProfilePackage)
	require.NoError(t, err)
	require.NotEmpty(t, bpp.FirstSequenceOf87)
	require.NotEmpty(t, bpp.SequenceOf88)
	require.NotEmpty(t, bpp.SecondSequenceOf87)
	require.NotEmpty(t, bpp.SequenceOf86)

	// BF23 signature verifies with CERT.DPpb.
	iscr := bpp.InitialiseSecureChannelRequest
	require.True(t, crypto.VerifyRaw(dpPbPub, iscr.SignedBytes(euiccOtpk), iscr.SmdpSign))
	// smdpOtpk must be a 65-byte uncompressed point.
	require.Len(t, iscr.SmdpOtpk, 65)
	require.Equal(t, byte(0x04), iscr.SmdpOtpk[0])

	// Decrypt: eUICC derives the same shared secret and PPK.
	shared, err := crypto.ECDHSharedSecret(euiccOtSK, iscr.SmdpOtpk)
	require.NoError(t, err)
	eidBytes, err := rsp.EIDBytes(testEID)
	require.NoError(t, err)

	// ConfigureISDP (BF24) and StoreMetadata (BF25) decrypt with the initial
	// keys, in order (BSP MAC chaining is sequential).
	initial, err := crypto.NewBSPInstance(crypto.BSPDerive(shared, 0x88, 16, make([]byte, 8), eidBytes, 16))
	require.NoError(t, err)

	cfgPlain, err := initial.DemacAndDecrypt(bpp.FirstSequenceOf87)
	require.NoError(t, err)
	require.Equal(t, "bf2407", hex.EncodeToString(cfgPlain[:3]))
	smdPlain, err := initial.DemacOnly(bpp.SequenceOf88)
	require.NoError(t, err)
	require.Equal(t, byte(0xbf), smdPlain[0])

	// ReplaceSessionKeys yields the PPK used for sequenceOf86.
	rsrPlain, err := initial.DemacAndDecrypt(bpp.SecondSequenceOf87)
	require.NoError(t, err)
	rsr, _, err := asn1.ReadTLV(rsrPlain)
	require.NoError(t, err)
	rsrKids, err := rsr.Children()
	require.NoError(t, err)
	require.Len(t, rsrKids, 3)
	ppk := crypto.BSPKeyMaterial{
		InitialMCV: rsrKids[0].Value,
		SEnc:       rsrKids[1].Value,
		SMac:       rsrKids[2].Value,
	}

	ppkInstance, err := crypto.NewBSPInstance(ppk)
	require.NoError(t, err)
	upp, err := ppkInstance.DemacAndDecrypt(bpp.SequenceOf86)
	require.NoError(t, err)
	// The UPP must parse and carry the personalized ICCID.
	seq, err := parseUPP(upp)
	require.NoError(t, err)
	require.NotZero(t, len(seq))
	require.Contains(t, hex.EncodeToString(upp), hex.EncodeToString(mustICCIDHeader(t, profile.ICCID)))
}

func parseUPP(b []byte) ([]*asn1.Node, error) { return asn1.ParseNodes(b) }

func mustICCIDHeader(t *testing.T, iccid string) []byte {
	t.Helper()
	// header iccid is plain BCD padded with F to 20 digits
	padded := iccid
	for len(padded) < 20 {
		padded += "F"
	}
	b, err := hex.DecodeString(padded)
	require.NoError(t, err)
	return b
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}

func TestNotificationInstalled(t *testing.T) {
	_, st := setupCMAE(t)
	orders := NewOrderService(st.Profiles)
	notifs := NewNotificationService(NotificationDeps{Log: slog.Default(), Notifs: st.Notifs, Profiles: st.Profiles, Orders: orders})

	inv := NewInventory(st.Profiles, "8900012", "00101")
	profile, err := inv.Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	profile.MatchingID = "MATCH-N"
	require.NoError(t, st.Profiles.Update(profile))
	_, err = orders.Confirm(profile.ICCID, true)
	require.NoError(t, err)
	_, err = orders.MarkDownloaded(profile.ICCID)
	require.NoError(t, err)

	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	euiccKey, err := provider.ECDSAKey(testRoot + "/eUICC/SK_EUICC_NIST.pem")
	require.NoError(t, err)
	euiccCertDER := readFile(t, testRoot+"/eUICC/CERT_EUICC_NIST.der")

	txn := mustHexLower(t, "00112233445566778899AABBCCDDEEFF")
	ss := NewSessionService(st.Sessions, provider, time.Hour)
	require.NoError(t, ss.Put(&store.Session{
		TransactionID: strings.ToUpper(hex.EncodeToString(txn)),
		State:         "downloaded", ProfileID: profile.ID, EuiccCert: euiccCertDER,
	}))
	notifs.Deps.Sessions = ss
	gotPoint := 0
	notifs.Callback = func(_ context.Context, info ProgressInfo) error {
		gotPoint = info.NotificationPointID
		return nil
	}

	meta := tlv([]byte{0xbf, 0x2f}, testutil.Concat(
		tlv([]byte{0x80}, []byte{0x01}),
		tlv([]byte{0x81}, []byte{0x00, 0x80}),
		tlv([]byte{0x0c}, []byte("x")),
	))
	success := tlv([]byte{0xa2}, tlv([]byte{0xa0}, testutil.Concat(
		tlv([]byte{0x4f}, testutil.MustHex(t, "a0000005591010ffffffff8900001000")),
		tlv([]byte{0x04}, nil),
	)))
	pird := tlv([]byte{0xbf, 0x27}, testutil.Concat(tlv(tCtx0p, txn), meta, success))
	sig, err := crypto.SignRaw(euiccKey, pird)
	require.NoError(t, err)
	pir := tlv([]byte{0xbf, 0x37}, testutil.Concat(pird, tlv(tSig, sig)))

	require.NoError(t, notifs.HandlePendingNotification(context.Background(), pir))

	p, err := st.Profiles.GetByICCID(profile.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateInstalled, p.State)
	require.Equal(t, 4, gotPoint)
}

// TestInstallEventDeletionIsGated covers smdpp.es12.delete_on_install: a
// successful installation deletes the SM-DS event by default, and keeps it when
// the option asks for that (the deployment then relies on the ACR-0 cleanup).
func TestInstallEventDeletionIsGated(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprintf("keep=%v", keep), func(t *testing.T) {
			_, st := setupCMAE(t)
			orders := NewOrderService(st.Profiles)
			notifs := NewNotificationService(NotificationDeps{
				Log: slog.Default(), Notifs: st.Notifs, Profiles: st.Profiles, Orders: orders,
			})

			inv := NewInventory(st.Profiles, "8900012", "00101")
			profile, err := inv.Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
			require.NoError(t, err)
			profile.MatchingID = "MATCH-GATED"
			require.NoError(t, st.Profiles.Update(profile))
			_, err = orders.Confirm(profile.ICCID, true)
			require.NoError(t, err)
			_, err = orders.MarkDownloaded(profile.ICCID)
			require.NoError(t, err)

			// A registration for this EID, and an SM-DS that accepts its deletion.
			require.NoError(t, st.Regs.Insert(testEID, "MATCH-GATED", "testrootsmds.example.com", false, ""))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"header":{"functionExecutionStatus":{"status":"Executed-Success"}}}`))
			}))
			defer srv.Close()
			notifs.Deps.Registrar = &Registrar{
				Repo: st.Regs, Client: NewSMDSCClient(srv.URL, "2.999.10", nil),
				SMDPAddress: "testsmdpplus1.example.com",
			}
			notifs.Deps.KeepEventOnInstall = keep

			provider, err := kms.NewFileProviderFromKEK(testKEK)
			require.NoError(t, err)
			euiccKey, err := provider.ECDSAKey(testRoot + "/eUICC/SK_EUICC_NIST.pem")
			require.NoError(t, err)
			ss := NewSessionService(st.Sessions, provider, time.Hour)
			txn := mustHexLower(t, "00112233445566778899AABBCCDDEEFF")
			require.NoError(t, ss.Put(&store.Session{
				TransactionID: strings.ToUpper(hex.EncodeToString(txn)),
				State:         "downloaded", ProfileID: profile.ID,
				EuiccCert: readFile(t, testRoot+"/eUICC/CERT_EUICC_NIST.der"),
			}))
			notifs.Deps.Sessions = ss

			meta := tlv([]byte{0xbf, 0x2f}, testutil.Concat(
				tlv([]byte{0x80}, []byte{0x01}),
				tlv([]byte{0x81}, []byte{0x00, 0x80}),
				tlv([]byte{0x0c}, []byte("x")),
			))
			success := tlv([]byte{0xa2}, tlv([]byte{0xa0}, testutil.Concat(
				tlv([]byte{0x4f}, testutil.MustHex(t, "a0000005591010ffffffff8900001000")),
				tlv([]byte{0x04}, nil),
			)))
			pird := tlv([]byte{0xbf, 0x27}, testutil.Concat(tlv(tCtx0p, txn), meta, success))
			sig, err := crypto.SignRaw(euiccKey, pird)
			require.NoError(t, err)
			pir := tlv([]byte{0xbf, 0x37}, testutil.Concat(pird, tlv(tSig, sig)))

			require.NoError(t, notifs.HandlePendingNotification(context.Background(), pir))

			regs, err := st.Regs.ListActiveByEID(testEID)
			require.NoError(t, err)
			if keep {
				require.Len(t, regs, 1, "delete_on_install: false must keep the event")
			} else {
				require.Empty(t, regs, "the event is deleted on install by default")
			}
		})
	}
}

// testCertificateManager builds the SGP.26 Variant O (NIST) certificate manager
// used by the notification tests.
func testCertificateManager(t *testing.T) *cert.Manager {
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
	return certs
}

func TestNotificationInstallRejectsBadSignature(t *testing.T) {
	_, st := setupCMAE(t)
	orders := NewOrderService(st.Profiles)
	notifs := NewNotificationService(NotificationDeps{Log: slog.Default(), Notifs: st.Notifs, Profiles: st.Profiles, Orders: orders})

	profile, err := NewInventory(st.Profiles, "8900012", "00101").Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	profile.MatchingID = "MATCH-BADSIG"
	require.NoError(t, st.Profiles.Update(profile))
	_, err = orders.Confirm(profile.ICCID, true)
	require.NoError(t, err)
	_, err = orders.MarkDownloaded(profile.ICCID)
	require.NoError(t, err)

	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	txn := mustHexLower(t, "00112233445566778899AABBCCDDEEFF")
	ss := NewSessionService(st.Sessions, provider, time.Hour)
	require.NoError(t, ss.Put(&store.Session{
		TransactionID: strings.ToUpper(hex.EncodeToString(txn)),
		State:         "downloaded", ProfileID: profile.ID,
		EuiccCert: readFile(t, testRoot+"/eUICC/CERT_EUICC_NIST.der"),
	}))
	notifs.Deps.Sessions = ss

	meta := tlv([]byte{0xbf, 0x2f}, testutil.Concat(
		tlv([]byte{0x80}, []byte{0x01}),
		tlv([]byte{0x81}, []byte{0x00, 0x80}),
		tlv([]byte{0x0c}, []byte("x")),
	))
	success := tlv([]byte{0xa2}, tlv([]byte{0xa0}, testutil.Concat(
		tlv([]byte{0x4f}, testutil.MustHex(t, "a0000005591010ffffffff8900001000")),
		tlv([]byte{0x04}, nil),
	)))
	pird := tlv([]byte{0xbf, 0x27}, testutil.Concat(tlv(tCtx0p, txn), meta, success))
	pir := tlv([]byte{0xbf, 0x37}, testutil.Concat(pird, tlv(tSig, make([]byte, 64))))

	require.NoError(t, notifs.HandlePendingNotification(context.Background(), pir))

	p, err := st.Profiles.GetByICCID(profile.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateDownloaded, p.State) // not installed
	got, err := st.Notifs.ListByEID(testEID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.False(t, got[0].SignatureOK)
	require.False(t, got[0].Processed)
}

func TestNotificationOtherSignedVerification(t *testing.T) {
	_, st := setupCMAE(t)
	orders := NewOrderService(st.Profiles)
	notifs := NewNotificationService(NotificationDeps{Log: slog.Default(), Notifs: st.Notifs, Profiles: st.Profiles, Orders: orders})
	notifs.Deps.Certs = testCertificateManager(t)

	profile, err := NewInventory(st.Profiles, "8900012", "00101").Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	_, err = orders.Confirm(profile.ICCID, true)
	require.NoError(t, err)
	_, err = orders.MarkDownloaded(profile.ICCID)
	require.NoError(t, err)
	_, err = orders.MarkInstalled(profile.ICCID)
	require.NoError(t, err)

	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	euiccKey, err := provider.ECDSAKey(testRoot + "/eUICC/SK_EUICC_NIST.pem")
	require.NoError(t, err)
	euiccCert := readFile(t, testRoot+"/eUICC/CERT_EUICC_NIST.der")
	eumCert := readFile(t, testRoot+"/EUM/CERT_EUM_NIST.der")

	iccidBCD, err := personalization.ICCIDEFBytes(profile.ICCID)
	require.NoError(t, err)
	meta := tlv([]byte{0xbf, 0x2f}, testutil.Concat(
		tlv([]byte{0x80}, []byte{0x01}),
		tlv([]byte{0x81}, []byte{0x00, 0x10}), // delete
		tlv([]byte{0x0c}, []byte("x")),
		tlv([]byte{0x5a}, iccidBCD),
	))
	sig, err := crypto.SignRaw(euiccKey, meta)
	require.NoError(t, err)

	// Valid notification (PendingNotification wraps the CHOICE in [0]).
	osn := tlv([]byte{0xa0}, tlv([]byte{0x30}, testutil.Concat(meta, tlv(tSig, sig), euiccCert, eumCert)))
	require.NoError(t, notifs.HandlePendingNotification(context.Background(), osn))

	got, err := st.Notifs.ListByEID(testEID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, got[0].SignatureOK)
	require.Equal(t, "delete", got[0].Operation)
	require.Equal(t, profile.ICCID, got[0].ICCID)

	// Tampered signature is recorded but not processed.
	bad := tlv([]byte{0xa0}, tlv([]byte{0x30}, testutil.Concat(meta, tlv(tSig, make([]byte, 64)), euiccCert, eumCert)))
	require.NoError(t, notifs.HandlePendingNotification(context.Background(), bad))
	got, err = st.Notifs.ListByEID(testEID)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.False(t, got[1].SignatureOK)
}

// TestNotificationDeleteReleasesForRedownload covers the second half of the ACR-0
// fix: SGP.22 §3.1.7 makes the redownload Activation Code usable only after the
// associated Delete Notification, so when the deployment opts in
// (profiles.allow_redownload_after_delete) a verified delete notification must
// return the Profile to Released. The default keeps Installed terminal.
func TestNotificationDeleteReleasesForRedownload(t *testing.T) {
	deleteNotificationState := func(t *testing.T, allow bool) store.ProfileState {
		t.Helper()
		_, st := setupCMAE(t)
		orders := NewOrderService(st.Profiles)
		notifs := NewNotificationService(NotificationDeps{
			Log: slog.Default(), Notifs: st.Notifs, Profiles: st.Profiles, Orders: orders,
			AllowRedownloadAfterDelete: allow,
		})
		notifs.Deps.Certs = testCertificateManager(t)

		profile, err := NewInventory(st.Profiles, "8900012", "00101").
			Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
		require.NoError(t, err)
		_, err = orders.Confirm(profile.ICCID, true)
		require.NoError(t, err)
		_, err = orders.MarkDownloaded(profile.ICCID)
		require.NoError(t, err)
		_, err = orders.MarkInstalled(profile.ICCID)
		require.NoError(t, err)

		provider, err := kms.NewFileProviderFromKEK(testKEK)
		require.NoError(t, err)
		euiccKey, err := provider.ECDSAKey(testRoot + "/eUICC/SK_EUICC_NIST.pem")
		require.NoError(t, err)
		iccidBCD, err := personalization.ICCIDEFBytes(profile.ICCID)
		require.NoError(t, err)
		meta := tlv([]byte{0xbf, 0x2f}, testutil.Concat(
			tlv([]byte{0x80}, []byte{0x01}),
			tlv([]byte{0x81}, []byte{0x00, 0x10}), // delete
			tlv([]byte{0x0c}, []byte("x")),
			tlv([]byte{0x5a}, iccidBCD),
		))
		sig, err := crypto.SignRaw(euiccKey, meta)
		require.NoError(t, err)
		osn := tlv([]byte{0xa0}, tlv([]byte{0x30}, testutil.Concat(
			meta, tlv(tSig, sig),
			readFile(t, testRoot+"/eUICC/CERT_EUICC_NIST.der"),
			readFile(t, testRoot+"/EUM/CERT_EUM_NIST.der"),
		)))
		require.NoError(t, notifs.HandlePendingNotification(context.Background(), osn))

		got, err := st.Profiles.GetByICCID(profile.ICCID)
		require.NoError(t, err)
		return got.State
	}

	require.Equal(t, store.StateInstalled, deleteNotificationState(t, false),
		"without the opt-in, Installed stays terminal")
	require.Equal(t, store.StateReleased, deleteNotificationState(t, true),
		"with the opt-in, a verified delete notification makes the Profile downloadable again")
}

func TestResolveUPPTemplateVersionSet(t *testing.T) {
	cmae, _ := setupCMAE(t)
	profile := &store.Profile{}

	// An empty version set is "unknown": no template may be selected silently.
	_, err := cmae.resolveUPPTemplate(profile, &store.Session{})
	var vErr *ErrProfileVersionNotSupported
	require.ErrorAs(t, err, &vErr)
	require.Empty(t, vErr.SupportedVersions)
	// The message prefix is the documented way to tell the N12 version failure
	// apart from the other 8.2.6/3.8 case (docs/interfaces.md, status codes).
	require.Contains(t, vErr.Error(), "no usable SAIP profile version")

	// An eUICC advertising 2.2 gets the highest compatible template (2.1).
	tpl, err := cmae.resolveUPPTemplate(profile, &store.Session{EuiccSupportedVersions: []string{"2.2"}})
	require.NoError(t, err)
	require.Equal(t, "TS48v1_A.der", tpl.Name)

	// 2.3 gets a 2.3 template.
	tpl, err = cmae.resolveUPPTemplate(profile, &store.Session{EuiccSupportedVersions: []string{"2.3"}})
	require.NoError(t, err)
	require.Equal(t, "TS48v2_SAIP2.3_BERTLV.der", tpl.Name)

	// Nothing qualifies below SAIP 2.1: a clean, distinguishable failure that
	// reports the lowest registered template version (N12).
	_, err = cmae.resolveUPPTemplate(profile, &store.Session{EuiccSupportedVersions: []string{"1.0"}})
	require.ErrorAs(t, err, &vErr)
	require.Equal(t, []string{"1.0"}, vErr.SupportedVersions)
	require.Equal(t, "2.1", vErr.LowestTemplateVersion)
	require.Contains(t, vErr.Error(), "no UPP template compatible with the eUICC's SAIP versions")
}

// TestResolveUPPTemplatePinnedIncompatible pins N12's strictness: an explicitly
// pinned template (order or session) that is above the eUICC's versions fails
// instead of silently substituting a compatible default template.
func TestResolveUPPTemplatePinnedIncompatible(t *testing.T) {
	cmae, _ := setupCMAE(t)

	profile := &store.Profile{UPPTemplate: "TS48v2_SAIP2.3_BERTLV.der"}
	_, err := cmae.resolveUPPTemplate(profile, &store.Session{EuiccSupportedVersions: []string{"2.1"}})
	var vErr *ErrProfileVersionNotSupported
	require.ErrorAs(t, err, &vErr)
	require.Equal(t, "2.3", vErr.LowestTemplateVersion)
	require.Equal(t, []string{"2.1"}, vErr.SupportedVersions)

	// The same pinned template is honoured when the eUICC supports it.
	tpl, err := cmae.resolveUPPTemplate(profile, &store.Session{EuiccSupportedVersions: []string{"2.3"}})
	require.NoError(t, err)
	require.Equal(t, "TS48v2_SAIP2.3_BERTLV.der", tpl.Name)

	// A pinned template that does not exist is a configuration error, not a
	// version failure.
	_, err = cmae.resolveUPPTemplate(&store.Profile{UPPTemplate: "nope.der"}, &store.Session{EuiccSupportedVersions: []string{"2.3"}})
	require.Error(t, err)
	require.NotErrorAs(t, err, &vErr)
}

func TestLoadUPPAppliesPersonalization(t *testing.T) {
	cmae, st := setupCMAE(t)
	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	perso := NewPersonalizationService(st.Perso, provider)
	require.NoError(t, perso.Put("", &personalization.Data{
		ICCID: "89000123456789012341", IMSI: "001010123456063", SPN: "TESTSPN",
	}))

	// Even without a record the order's ICCID must be applied; here a record
	// exists, so both the ICCID and the IMSI/SPN are written.
	profile := &store.Profile{ICCID: "89000123456789012341"}
	sess := &store.Session{UPPTemplate: "TS48v1_A.der", EuiccSupportedVersions: []string{"2.1"}}

	upp, err := cmae.loadUPP(profile, sess)
	require.NoError(t, err)
	seq, err := saip.ParseUPP(upp)
	require.NoError(t, err)
	h, err := saip.ParseHeader(seq.Header())
	require.NoError(t, err)
	require.Equal(t, mustICCIDHeader(t, profile.ICCID), h.ICCID)

	imsi := seq.FindFile(saip.FIDIMSI)
	require.NotNil(t, imsi)
	require.Equal(t, personalization.EncodeIMSI("001010123456063"), imsi.Body())
}

func TestBuildStoreMetadataPPR(t *testing.T) {
	cmae, _ := setupCMAE(t)
	profile := &store.Profile{ICCID: "89000123456789012341"}

	// No PPR -> no 0x99 element.
	raw, err := cmae.buildStoreMetadata(profile)
	require.NoError(t, err)
	require.NotContains(t, hex.EncodeToString(raw), "9902")

	// Config default PPR1 -> BIT STRING content 00 40 under tag 0x99.
	cmae.Cfg.PPRIds = rsp.PPRIDBits([]int{1})
	raw, err = cmae.buildStoreMetadata(profile)
	require.NoError(t, err)
	require.Contains(t, hex.EncodeToString(raw), "99020040")

	// Per-profile override PPR2 wins over the config default.
	profile.PPRIds = rsp.PPRIDBits([]int{2})
	raw, err = cmae.buildStoreMetadata(profile)
	require.NoError(t, err)
	require.Contains(t, hex.EncodeToString(raw), "99020020")
}

func TestACRRetrieval(t *testing.T) {
	cmae, st := setupCMAE(t)
	profile, err := NewInventory(st.Profiles, "8900012", "00101").Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	profile.MatchingID = "MATCH-ACR"
	require.NoError(t, st.Profiles.Update(profile))
	orders := NewOrderService(st.Profiles)
	_, err = orders.Confirm(profile.ICCID, true)
	require.NoError(t, err)
	_, err = orders.MarkDownloaded(profile.ICCID)
	require.NoError(t, err)
	_, err = orders.MarkInstalled(profile.ICCID)
	require.NoError(t, err)

	// Type 1: availability check.
	res, err := cmae.handleACR(context.Background(), "TXN1", &clientAuth{Session: &store.Session{TransactionID: "TXN1"}, EID: testEID, MatchingID: "ACR-1-" + profile.ICCID})
	require.NoError(t, err)
	require.True(t, res.ACROnly)
	require.Contains(t, hex.EncodeToString(res.ProfileMetadata), "8201ff") // BOOLEAN true

	// Type 0: redownload activation code. The rotation must tell the caller which
	// MatchingID was replaced, so the registration held under it (keyed by the
	// MatchingID, §3.6) can be dropped.
	var rotatedFrom string
	cmae.MatchingIDChanged = func(_ *store.Profile, previous string) { rotatedFrom = previous }
	res, err = cmae.handleACR(context.Background(), "TXN2", &clientAuth{Session: &store.Session{TransactionID: "TXN2"}, EID: testEID, MatchingID: "ACR-0-" + profile.ICCID})
	require.NoError(t, err)
	require.True(t, res.ACROnly)
	require.Contains(t, hex.EncodeToString(res.ProfileMetadata), "81") // UTF8String alternative
	require.Equal(t, "MATCH-ACR", rotatedFrom, "the ACR-0 rotation must report the previous MatchingID")

	// The availability check does not rotate, so it must not report a change.
	rotatedFrom = ""
	_, err = cmae.handleACR(context.Background(), "TXN4", &clientAuth{Session: &store.Session{TransactionID: "TXN4"}, EID: testEID, MatchingID: "ACR-1-" + profile.ICCID})
	require.NoError(t, err)
	require.Empty(t, rotatedFrom, "ACR-1 must not rotate the MatchingID")

	// Unknown ICCID -> 8.2.1/1.2.
	_, err = cmae.handleACR(context.Background(), "TXN3", &clientAuth{Session: &store.Session{TransactionID: "TXN3"}, EID: testEID, MatchingID: "ACR-1-9999999999999999999"})
	require.Error(t, err)
}

func TestACROperatorConfirmation(t *testing.T) {
	cmae, st := setupCMAE(t)
	profile, err := NewInventory(st.Profiles, "8900012", "00101").Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	profile.MatchingID = "MATCH-ACR-OP"
	require.NoError(t, st.Profiles.Update(profile))
	orders := NewOrderService(st.Profiles)
	_, err = orders.Confirm(profile.ICCID, true)
	require.NoError(t, err)
	_, err = orders.MarkDownloaded(profile.ICCID)
	require.NoError(t, err)
	_, err = orders.MarkInstalled(profile.ICCID)
	require.NoError(t, err)

	ca := func() *clientAuth {
		return &clientAuth{Session: &store.Session{TransactionID: "TXN"}, EID: testEID, MatchingID: "ACR-1-" + profile.ICCID}
	}

	// Operator refuses -> the retrieval is refused with the ACR-specific code
	// (8.2.1/1.2, §5.3.8 Table 32e) and the profile keeps its matching id.
	cmae.ACRCheck = func(context.Context, *store.Profile) error {
		return &rsp.ACRRefusedError{SubjectCode: "8.2.1", ReasonCode: "1.2", Message: "not allowed"}
	}
	_, err = cmae.handleACR(context.Background(), "TXN", ca())
	require.Error(t, err)
	var refused *rsp.StatusCode
	require.ErrorAs(t, err, &refused)
	require.Equal(t, "8.2.1", refused.SubjectCode)
	require.Equal(t, "1.2", refused.ReasonCode)

	// A transport failure is not an Operator decision: it is reported as an
	// input error rather than as an ACR refusal.
	cmae.ACRCheck = func(context.Context, *store.Profile) error { return errors.New("operator unreachable") }
	_, err = cmae.handleACR(context.Background(), "TXN", ca())
	require.Error(t, err)
	require.ErrorAs(t, err, &refused)
	require.Equal(t, "8.2.1", refused.SubjectCode)
	require.Equal(t, "1.2", refused.ReasonCode)

	// Operator confirms -> ACR proceeds, and the hook receives the profile.
	var seenICCID, seenTenant string
	cmae.ACRCheck = func(_ context.Context, p *store.Profile) error {
		seenICCID, seenTenant = p.ICCID, p.TenantID
		return nil
	}
	res, err := cmae.handleACR(context.Background(), "TXN", ca())
	require.NoError(t, err)
	require.True(t, res.ACROnly)
	require.Equal(t, profile.ICCID, seenICCID)
	require.Equal(t, profile.TenantID, seenTenant)

	// §5.3.8 requires the confirmation for both ACR types: the availability
	// check (ACR-1) and the activation code redownload (ACR-0). The redownload
	// also rotates the matching id.
	calls := 0
	cmae.ACRCheck = func(_ context.Context, p *store.Profile) error {
		calls++
		return nil
	}
	_, err = cmae.handleACR(context.Background(), "TXN0", &clientAuth{
		Session: &store.Session{TransactionID: "TXN0"}, EID: testEID, MatchingID: "ACR-0-" + profile.ICCID,
	})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	rotated, err := st.Profiles.GetByICCID(profile.ICCID)
	require.NoError(t, err)
	require.NotEqual(t, "MATCH-ACR-OP", rotated.MatchingID)
	// The redownload Activation Code must stay out of the ACR namespace: an
	// "ACR-"-prefixed MatchingID would be routed back into the ACR branch by
	// activationcode.IsACR and refused, making the code unusable.
	require.False(t, activationcode.IsACR(rotated.MatchingID),
		"rotated matching id %q must not be an ACR id", rotated.MatchingID)
	require.True(t, strings.HasPrefix(rotated.MatchingID, "MATCH-"))
}

// releasedProfile creates a profile in Released state with the given matching id.
func releasedProfile(t *testing.T, st *store.Store, matchingID string) *store.Profile {
	t.Helper()
	p, err := NewInventory(st.Profiles, "8900012", "00101").Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	p.MatchingID = matchingID
	require.NoError(t, st.Profiles.Update(p))
	_, err = NewOrderService(st.Profiles).Confirm(p.ICCID, true)
	require.NoError(t, err)
	p, err = st.Profiles.GetByICCID(p.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateReleased, p.State)
	return p
}

func TestDownloadAttemptLimit(t *testing.T) {
	cmae, st := setupCMAE(t)
	cmae.Cfg.MaxDownloadAttempts = 2
	p := releasedProfile(t, st, "MATCH-ATT")

	// The limit counts every attempt, including ones that never produce a BPP.
	require.NoError(t, cmae.registerDownloadAttempt(p))
	require.NoError(t, cmae.registerDownloadAttempt(p))
	require.Error(t, cmae.registerDownloadAttempt(p))

	got, err := st.Profiles.GetByICCID(p.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateError, got.State)
	require.Equal(t, 3, got.DownloadAttempts)
}

func TestDownloadOrderTTL(t *testing.T) {
	cmae, st := setupCMAE(t)
	cmae.Cfg.DownloadTTL = time.Nanosecond
	releasedProfile(t, st, "MATCH-TTL")

	_, err := cmae.lookupProfile("MATCH-TTL", testEID)
	require.Error(t, err)
}

func TestConfirmationCodeAttemptLimit(t *testing.T) {
	cmae, st := setupCMAE(t)
	cmae.Cfg.MaxCCAttempts = 2
	p := releasedProfile(t, st, "MATCH-CC")

	cmae.recordConfirmationFailure(p)
	require.Equal(t, store.StateReleased, p.State)
	cmae.recordConfirmationFailure(p)

	got, err := st.Profiles.GetByICCID(p.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateError, got.State)
	require.Equal(t, 2, got.CCAttempts)
}

func TestConfirmedProfileNotDownloadable(t *testing.T) {
	cmae, st := setupCMAE(t)
	p, err := NewInventory(st.Profiles, "8900012", "00101").Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	p.MatchingID = "MATCH-CONF"
	require.NoError(t, st.Profiles.Update(p))

	// ConfirmOrder without releaseFlag leaves the Profile Confirmed; per
	// SGP.22 §3.1.3 step 3 it is not yet eligible for download.
	_, err = NewOrderService(st.Profiles).Confirm(p.ICCID, false)
	require.NoError(t, err)
	_, err = cmae.lookupProfile("MATCH-CONF", testEID)
	require.Error(t, err)

	// ReleaseProfile moves it to Released, after which it is eligible.
	_, err = NewOrderService(st.Profiles).Release(p.ICCID)
	require.NoError(t, err)
	got, err := cmae.lookupProfile("MATCH-CONF", testEID)
	require.NoError(t, err)
	require.Equal(t, store.StateReleased, got.State)
}

// authenticateForTest drives InitiateAuthentication + AuthenticateClient for a
// matching id with the SGP.26 eUICC test certificate, returning the error.
func authenticateForTest(t *testing.T, cmae *CMAE, matchingID string) error {
	t.Helper()
	return authenticateWithForbiddenPPRForTest(t, cmae, matchingID, nil)
}

// authenticateWithForbiddenPPRForTest is authenticateForTest with the eUICC
// advertising forbiddenProfilePolicyRules (raw bitmap, nil = none).
func authenticateWithForbiddenPPRForTest(t *testing.T, cmae *CMAE, matchingID string, forbidden []byte) error {
	t.Helper()
	euiccChallenge := make([]byte, 16)
	_, _ = rand.Read(euiccChallenge)
	ciSKI := cmae.Deps.Certs.CI().SubjectKeyId
	init, err := cmae.Initiate(euiccChallenge, buildEUICCInfo1(ciSKI), testFQDN)
	require.NoError(t, err)

	serverSigned1, _, err := asn1.ReadTLV(init.ServerSigned1)
	require.NoError(t, err)
	ss1, err := rsp.DecodeServerSigned1(serverSigned1)
	require.NoError(t, err)

	txn := mustHexLower(t, init.TransactionID)
	euiccSigned1 := tlv(tSeq, testutil.Concat(
		tlv(tCtx0p, txn),
		tlv(tCtx3p, []byte(testFQDN)),
		tlv(tCtx4p, ss1.ServerChallenge),
		buildEUICCInfo2WithForbiddenPPR(ciSKI, forbidden),
		tlv(tCtx0c, testutil.Concat(
			tlv([]byte{0x80}, []byte(matchingID)),
			tlv(tCtx1c, testutil.Concat(tlv([]byte{0x80}, make([]byte, 8)), tlv(tCtx1c, nil))),
		)),
	))
	key, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	euiccPriv, err := key.ECDSAKey(testRoot + "/eUICC/SK_EUICC_NIST.pem")
	require.NoError(t, err)
	euiccSig1, err := crypto.SignRaw(euiccPriv, euiccSigned1)
	require.NoError(t, err)

	asr := tlv(tBF38, tlv(tCtx0c, testutil.Concat(
		euiccSigned1,
		tlv(tSig, euiccSig1),
		readFile(t, testRoot+"/eUICC/CERT_EUICC_NIST.der"),
		readFile(t, testRoot+"/EUM/CERT_EUM_NIST.der"),
	)))
	_, err = cmae.AuthenticateClient(context.Background(), init.TransactionID, asr)
	return err
}

// TestAuthenticateBindsAnonymousProfileToEID covers G4: an anonymously claimed
// profile (no EID on the order) is bound to the eUICC that actually downloads
// it, and a subsequent download from another EID is refused.
func TestAuthenticateBindsAnonymousProfileToEID(t *testing.T) {
	cmae, st := setupCMAE(t)

	profile, err := NewInventory(st.Profiles, "8900012", "00101").
		Allocate(AllocateRequest{ProfileType: "operational"})
	require.NoError(t, err)
	require.Empty(t, profile.EID)
	profile.MatchingID = "MATCH-ANON"
	require.NoError(t, st.Profiles.Update(profile))
	_, err = NewOrderService(st.Profiles).Confirm(profile.ICCID, true)
	require.NoError(t, err)

	require.NoError(t, authenticateForTest(t, cmae, "MATCH-ANON"))

	got, err := st.Profiles.GetByICCID(profile.ICCID)
	require.NoError(t, err)
	require.Equal(t, testEID, got.EID, "the download must bind the profile to the authenticating eUICC")
	require.Equal(t, store.StateReleased, got.State)

	// The profile is now device-bound: a different EID is refused.
	got.EID = "89049032123451234512345678909999"
	require.NoError(t, st.Profiles.Update(got))
	err = authenticateForTest(t, cmae, "MATCH-ANON")
	require.Error(t, err)
}

// TestLoadUPPUsesTenantTemplate covers G3: the order/profile tenant selects the
// template, and there is no "any template" fallback.
func TestLoadUPPUsesTenantTemplate(t *testing.T) {
	cmae, st := setupCMAE(t)

	// Register a tenant-local template whose bytes are not a valid UPP, so the
	// resolution path is observable.
	require.NoError(t, st.UPP.Upsert(&store.UPPTemplate{
		Name: "tenant-tpl", TenantID: "carrier-a", SAIPMajor: 2, SAIPMinor: 1,
		SHA256: "t", Bytes: []byte{0xff, 0x00}, Active: true,
	}))

	profile := &store.Profile{ICCID: "89000123456789012341", TenantID: "carrier-a", UPPTemplate: "tenant-tpl"}
	_, err := cmae.loadUPP(profile, nil)
	require.Error(t, err, "a corrupt tenant template must surface as an error, not fall back")

	// An unknown template for the tenant is an error too (no Any() fallback).
	profile.UPPTemplate = "missing"
	_, err = cmae.loadUPP(profile, nil)
	require.Error(t, err)

	// With no template pinned anywhere and no tenant default, resolution fails
	// rather than silently picking an arbitrary template.
	cmae.Deps.DefaultUPP = ""
	profile.UPPTemplate = ""
	_, err = cmae.loadUPP(profile, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no UPP template configured")
}

// TestAllocateRejectsBlockedPoolICCID covers the interaction between an
// operator-supplied ICCID and the pool: a blocked entry is never issued, and an
// available entry is claimed (allocated, owned) rather than left claimable.
func TestAllocateRejectsBlockedPoolICCID(t *testing.T) {
	st := openServiceStore(t)
	inv := NewInventory(st.Profiles, "8900012", "00101")
	inv.Pool = st.Pool

	_, _, _, err := st.Pool.ImportRange("carrier-a", "8900012000000000000", "8900012000000000099", "")
	require.NoError(t, err)
	entries, _, err := st.Pool.ListPage("available", "", nil, 2, 0)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	blocked, free := entries[0].ICCID, entries[1].ICCID
	require.NoError(t, st.Pool.SetState(blocked, "blocked", "ops"))

	_, err = inv.Allocate(AllocateRequest{ICCID: blocked, Tenant: "carrier-a"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "blocked")

	p, err := inv.Allocate(AllocateRequest{ICCID: free, Tenant: "carrier-a"})
	require.NoError(t, err)
	state, err := st.Pool.State(p.ICCID)
	require.NoError(t, err)
	require.Equal(t, "allocated", state)
}

// openServiceStore opens a store for service-level tests.
func openServiceStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "svc.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestInitiateAcceptsSNMPAddressWithPort pins SGP.22 §4.1: the SM-DP+ address
// an Activation Code carries is "FQDN [:Port]", and LPAs do send the port (lpac
// passes `-s host:port` through verbatim). Only a wrong host or a port this
// server does not serve may be refused.
func TestInitiateAcceptsSNMPAddressWithPort(t *testing.T) {
	cmae, _ := setupCMAE(t)
	challenge := make([]byte, 16)
	_, _ = rand.Read(challenge)
	ciSKI := cmae.Deps.Certs.CI().SubjectKeyId //nolint:staticcheck // test helper

	for _, addr := range []string{
		testFQDN,
		testFQDN + ":8443",
		strings.ToUpper(testFQDN) + ":8443",
	} {
		_, err := cmae.Initiate(challenge, buildEUICCInfo1(ciSKI), addr)
		require.NoError(t, err, "address %q must be accepted", addr)
	}

	for _, addr := range []string{
		"other.example.com",
		"other.example.com:8443",
		testFQDN + ":9999",
		testFQDN + ":abc",
		"",
	} {
		_, err := cmae.Initiate(challenge, buildEUICCInfo1(ciSKI), addr)
		require.Error(t, err, "address %q must be refused", addr)
	}
}

// TestAuthenticateRefusesPPRForbiddenByEuicc pins SGP.22 §5.7.5: the SM-DP+
// SHALL not deliver a Profile carrying a PPR the eUICC lists in
// forbiddenProfilePolicyRules. The refusal is 8.2.5/4.3 "No eligible Profile for
// this eUICC/Device", it must not consume a download attempt, and it must not
// move the order out of Released.
func TestAuthenticateRefusesPPRForbiddenByEuicc(t *testing.T) {
	cmae, st := setupCMAE(t)
	cmae.Cfg.PPRIds = rsp.PPRIDBits([]int{1}) // the Profile would carry PPR1

	p := releasedProfile(t, st, "MATCH-PPR-FORBIDDEN")

	// Forbidding PPR2 only must not block a PPR1 profile.
	require.NoError(t, authenticateWithForbiddenPPRForTest(t, cmae, "MATCH-PPR-FORBIDDEN",
		rsp.PPRIDBits([]int{2})))
	before, err := st.Profiles.GetByICCID(p.ICCID)
	require.NoError(t, err)

	// Forbidding PPR1 intersects: refuse with 8.2.5/4.3.
	err = authenticateWithForbiddenPPRForTest(t, cmae, "MATCH-PPR-FORBIDDEN",
		rsp.PPRIDBits([]int{1, 2}))
	require.Error(t, err)
	var sc *rsp.StatusCode
	require.ErrorAs(t, err, &sc)
	require.Equal(t, "8.2.5", sc.SubjectCode)
	require.Equal(t, "4.3", sc.ReasonCode)

	got, err := st.Profiles.GetByICCID(p.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateReleased, got.State)
	require.Equal(t, before.DownloadAttempts, got.DownloadAttempts,
		"an eligibility failure must not consume an attempt")
}

// TestForbiddenPPRHit covers the bitmap intersection, including the
// pprUpdateControl(0) bit that is not a Profile Policy Rule.
func TestForbiddenPPRHit(t *testing.T) {
	info := func(bits []byte) *rsp.EUICCInfo2 {
		return &rsp.EUICCInfo2{ForbiddenProfilePolicyRules: bits}
	}
	cases := []struct {
		name      string
		ppr       []byte
		forbidden []byte
		wantID    int
		wantHit   bool
	}{
		{"no forbidden list", rsp.PPRIDBits([]int{1}), nil, 0, false},
		{"disjoint", rsp.PPRIDBits([]int{1}), rsp.PPRIDBits([]int{2}), 0, false},
		{"intersect ppr1", rsp.PPRIDBits([]int{1}), rsp.PPRIDBits([]int{1, 2}), 1, true},
		{"intersect ppr2", rsp.PPRIDBits([]int{1, 2}), rsp.PPRIDBits([]int{2}), 2, true},
		{"no ppr on the profile", nil, rsp.PPRIDBits([]int{1, 2}), 0, false},
		{"lowest hit wins", rsp.PPRIDBits([]int{1, 2}), rsp.PPRIDBits([]int{1, 2}), 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, hit := forbiddenPPRHit(tc.ppr, info(tc.forbidden))
			require.Equal(t, tc.wantHit, hit)
			if tc.wantHit {
				require.Equal(t, tc.wantID, id)
			}
		})
	}
	// A nil euiccInfo2 (an eUICC that sent none) forbids nothing.
	_, hit := forbiddenPPRHit(rsp.PPRIDBits([]int{1}), nil)
	require.False(t, hit)
}
