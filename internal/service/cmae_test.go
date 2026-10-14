package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
	"rsp42/internal/cert"
	"rsp42/internal/crypto"
	"rsp42/internal/kms"
	"rsp42/internal/rsp"
	"rsp42/internal/saip"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/store"
)

const (
	testEID  = "89049032123451234512345678901235"
	testFQDN = "testsmdpplus1.example.com"
	testOID  = "2.999.10"
	testRoot = "../../testdata/sgp26"
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
		concat(
			tlv([]byte{0x82}, []byte{0x02, 0x02, 0x00}),
			tlv([]byte{0xa9}, tlv([]byte{0x04}, ski)),
			tlv([]byte{0xaa}, tlv([]byte{0x04}, ski)),
		))
}

func buildEUICCInfo2(ski []byte) []byte {
	return tlv(tBF22, concat(
		tlv([]byte{0x81}, []byte{0x02, 0x02, 0x00}),
		tlv([]byte{0x82}, []byte{0x02, 0x02, 0x00}),
		tlv([]byte{0x83}, []byte{0x02, 0x02, 0x00}),
		tlv([]byte{0x84}, nil),
		tlv([]byte{0x85}, []byte{0x00}),
		tlv([]byte{0x88}, []byte{0x00}),
		tlv([]byte{0xa9}, tlv([]byte{0x04}, ski)),
		tlv([]byte{0xaa}, tlv([]byte{0x04}, ski)),
		tlv([]byte{0x04}, []byte{0x02, 0x00, 0x00}),
		tlv([]byte{0x0c}, []byte("x")),
	))
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
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
	_, err = ImportUPPTemplates("../../testdata/upp", st.UPP)
	require.NoError(t, err)

	perso := NewPersonalizationService(st.Perso, provider)
	cmae, err := NewCMAE(CMAEConfig{
		FQDN: testFQDN, OID: testOID, HostID: make([]byte, 8),
		TransactionIDLen: 16, MaxDownloadAttempts: 5, MaxCCAttempts: 3,
		SessionTTL: 30 * time.Minute, DownloadTTL: 24 * time.Hour,
	}, certs, NewSessionService(st.Sessions, provider, 30*time.Minute), st.Profiles,
		perso, st.UPP, "TS48v1_A.der", &personalization.Engine{Algorithm: "milenage"}, slog.Default())
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
	ciSKI := cmae.Certs.CI().SubjectKeyId
	init, err := cmae.Initiate(euiccChallenge, buildEUICCInfo1(ciSKI), testFQDN)
	require.NoError(t, err)

	// Verify serverSignature1 over serverSigned1 with CERT.DPauth.
	dpAuthPub := cmae.Certs.DPAuth().PublicKey.(*ecdsa.PublicKey)
	require.True(t, crypto.VerifyRaw(dpAuthPub, init.ServerSigned1, rsp.SignatureValue(init.ServerSignature1)))

	serverSigned1, _, err := asn1.ReadTLV(init.ServerSigned1)
	require.NoError(t, err)
	ss1, err := rsp.DecodeServerSigned1(serverSigned1)
	require.NoError(t, err)
	require.Equal(t, euiccChallenge, ss1.EuiccChallenge)

	// --- eUICC builds AuthenticateServerResponse ---
	txn := mustHexLower(init.TransactionID)
	euiccSigned1 := tlv(tSeq, concat(
		tlv(tCtx0p, txn),
		tlv(tCtx3p, []byte(testFQDN)),
		tlv(tCtx4p, ss1.ServerChallenge),
		buildEUICCInfo2(ciSKI),
		tlv(tCtx0c, concat(
			tlv([]byte{0x80}, []byte("MATCH-1")),
			tlv(tCtx1c, concat(tlv([]byte{0x80}, make([]byte, 8)), tlv(tCtx1c, nil))),
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
	asr := tlv(tBF38, tlv(tCtx0c, concat(
		euiccSigned1,
		tlv(tSig, euiccSig1),
		euiccCertDER,
		eumCertDER,
	)))

	auth, err := cmae.AuthenticateClient(context.Background(), init.TransactionID, asr)
	require.NoError(t, err)

	// Verify smdpSignature2 over smdpSigned2 || euiccSignature1.
	dpPbPub := cmae.Certs.DPPb().PublicKey.(*ecdsa.PublicKey)
	require.True(t, crypto.VerifyRaw(dpPbPub, concat(auth.SmdpSigned2, tlv(tSig, euiccSig1)), rsp.SignatureValue(auth.SmdpSignature2)))

	// --- eUICC builds PrepareDownloadResponse ---
	euiccOtSK := make([]byte, 32)
	_, _ = rand.Read(euiccOtSK)
	euiccOtpk, err := crypto.ECPointFromPrivate(euiccOtSK)
	require.NoError(t, err)
	euiccSigned2 := tlv(tSeq, concat(tlv(tCtx0p, txn), tlv(tOtpk, euiccOtpk)))
	euiccSig2, err := crypto.SignRaw(euiccPriv, concat(euiccSigned2, auth.SmdpSignature2))
	require.NoError(t, err)
	pdr := tlv(tBF21, tlv(tCtx0c, concat(euiccSigned2, tlv(tSig, euiccSig2))))

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
	notifs := NewNotificationService(slog.Default(), st.Notifs, st.Profiles, orders)

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

	txn := mustHexLower("00112233445566778899AABBCCDDEEFF")
	ss := NewSessionService(st.Sessions, provider, time.Hour)
	require.NoError(t, ss.Put(&store.Session{
		TransactionID: strings.ToUpper(hex.EncodeToString(txn)),
		State:         "downloaded", ProfileID: profile.ID, EuiccCert: euiccCertDER,
	}))
	notifs.Sessions = ss
	gotPoint := 0
	notifs.Callback = func(_ context.Context, info ProgressInfo) error {
		gotPoint = info.PointID
		return nil
	}

	meta := tlv([]byte{0xbf, 0x2f}, concat(
		tlv([]byte{0x80}, []byte{0x01}),
		tlv([]byte{0x81}, []byte{0x00, 0x80}),
		tlv([]byte{0x0c}, []byte("x")),
	))
	success := tlv([]byte{0xa2}, tlv([]byte{0xa0}, concat(
		tlv([]byte{0x4f}, mustHex(t, "a0000005591010ffffffff8900001000")),
		tlv([]byte{0x04}, nil),
	)))
	pird := tlv([]byte{0xbf, 0x27}, concat(tlv(tCtx0p, txn), meta, success))
	sig, err := crypto.SignRaw(euiccKey, pird)
	require.NoError(t, err)
	pir := tlv([]byte{0xbf, 0x37}, concat(pird, tlv(tSig, sig)))

	require.NoError(t, notifs.HandlePendingNotification(context.Background(), pir))

	p, err := st.Profiles.GetByICCID(profile.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateInstalled, p.State)
	require.Equal(t, 4, gotPoint)
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
	notifs := NewNotificationService(slog.Default(), st.Notifs, st.Profiles, orders)

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
	txn := mustHexLower("00112233445566778899AABBCCDDEEFF")
	ss := NewSessionService(st.Sessions, provider, time.Hour)
	require.NoError(t, ss.Put(&store.Session{
		TransactionID: strings.ToUpper(hex.EncodeToString(txn)),
		State:         "downloaded", ProfileID: profile.ID,
		EuiccCert: readFile(t, testRoot+"/eUICC/CERT_EUICC_NIST.der"),
	}))
	notifs.Sessions = ss

	meta := tlv([]byte{0xbf, 0x2f}, concat(
		tlv([]byte{0x80}, []byte{0x01}),
		tlv([]byte{0x81}, []byte{0x00, 0x80}),
		tlv([]byte{0x0c}, []byte("x")),
	))
	success := tlv([]byte{0xa2}, tlv([]byte{0xa0}, concat(
		tlv([]byte{0x4f}, mustHex(t, "a0000005591010ffffffff8900001000")),
		tlv([]byte{0x04}, nil),
	)))
	pird := tlv([]byte{0xbf, 0x27}, concat(tlv(tCtx0p, txn), meta, success))
	pir := tlv([]byte{0xbf, 0x37}, concat(pird, tlv(tSig, make([]byte, 64))))

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
	notifs := NewNotificationService(slog.Default(), st.Notifs, st.Profiles, orders)
	notifs.Certs = testCertificateManager(t)

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
	meta := tlv([]byte{0xbf, 0x2f}, concat(
		tlv([]byte{0x80}, []byte{0x01}),
		tlv([]byte{0x81}, []byte{0x00, 0x10}), // delete
		tlv([]byte{0x0c}, []byte("x")),
		tlv([]byte{0x5a}, iccidBCD),
	))
	sig, err := crypto.SignRaw(euiccKey, meta)
	require.NoError(t, err)

	// Valid notification (PendingNotification wraps the CHOICE in [0]).
	osn := tlv([]byte{0xa0}, tlv([]byte{0x30}, concat(meta, tlv(tSig, sig), euiccCert, eumCert)))
	require.NoError(t, notifs.HandlePendingNotification(context.Background(), osn))

	got, err := st.Notifs.ListByEID(testEID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, got[0].SignatureOK)
	require.Equal(t, "delete", got[0].Operation)
	require.Equal(t, profile.ICCID, got[0].ICCID)

	// Tampered signature is recorded but not processed.
	bad := tlv([]byte{0xa0}, tlv([]byte{0x30}, concat(meta, tlv(tSig, make([]byte, 64)), euiccCert, eumCert)))
	require.NoError(t, notifs.HandlePendingNotification(context.Background(), bad))
	got, err = st.Notifs.ListByEID(testEID)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.False(t, got[1].SignatureOK)
}

func TestPickUPPSelectsCompatibleVersion(t *testing.T) {
	cmae, _ := setupCMAE(t)
	require.Equal(t, "", cmae.pickUPP("", nil))

	// The TS.48 v1 templates declare SAIP 2.1 and sort first, so an eUICC
	// advertising 2.2 gets the highest compatible template (2.1).
	require.Equal(t, "TS48v1_A.der", cmae.pickUPP("", []byte{2, 2, 0}))
	require.Equal(t, "TS48v2_SAIP2.3_BERTLV.der", cmae.pickUPP("", []byte{2, 3, 0}))
	// Nothing qualifies below SAIP 2.1.
	require.Empty(t, cmae.pickUPP("", []byte{1, 0, 0}))
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
	sess := &store.Session{UPPTemplate: "TS48v1_A.der"}

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

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
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

	// Type 0: redownload activation code.
	res, err = cmae.handleACR(context.Background(), "TXN2", &clientAuth{Session: &store.Session{TransactionID: "TXN2"}, EID: testEID, MatchingID: "ACR-0-" + profile.ICCID})
	require.NoError(t, err)
	require.True(t, res.ACROnly)
	require.Contains(t, hex.EncodeToString(res.ProfileMetadata), "81") // UTF8String alternative

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
	require.True(t, strings.HasPrefix(rotated.MatchingID, "ACR-"))
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
	euiccChallenge := make([]byte, 16)
	_, _ = rand.Read(euiccChallenge)
	ciSKI := cmae.Certs.CI().SubjectKeyId
	init, err := cmae.Initiate(euiccChallenge, buildEUICCInfo1(ciSKI), testFQDN)
	require.NoError(t, err)

	serverSigned1, _, err := asn1.ReadTLV(init.ServerSigned1)
	require.NoError(t, err)
	ss1, err := rsp.DecodeServerSigned1(serverSigned1)
	require.NoError(t, err)

	txn := mustHexLower(init.TransactionID)
	euiccSigned1 := tlv(tSeq, concat(
		tlv(tCtx0p, txn),
		tlv(tCtx3p, []byte(testFQDN)),
		tlv(tCtx4p, ss1.ServerChallenge),
		buildEUICCInfo2(ciSKI),
		tlv(tCtx0c, concat(
			tlv([]byte{0x80}, []byte(matchingID)),
			tlv(tCtx1c, concat(tlv([]byte{0x80}, make([]byte, 8)), tlv(tCtx1c, nil))),
		)),
	))
	key, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	euiccPriv, err := key.ECDSAKey(testRoot + "/eUICC/SK_EUICC_NIST.pem")
	require.NoError(t, err)
	euiccSig1, err := crypto.SignRaw(euiccPriv, euiccSigned1)
	require.NoError(t, err)

	asr := tlv(tBF38, tlv(tCtx0c, concat(
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
	cmae.DefaultUPP = ""
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
