package rsp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
	"rsp42/internal/testutil"
)

func golden(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "rsp_golden.json"))
	require.NoError(t, err)
	m := map[string]string{}
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func seqBytes(n int, start byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func hexEq(t *testing.T, want string, got []byte) {
	t.Helper()
	require.Equal(t, want, hex.EncodeToString(got))
}

func TestEncodeServerSigned1(t *testing.T) {
	g := golden(t)
	s := &ServerSigned1{
		TransactionID:   seqBytes(16, 0),
		EuiccChallenge:  seqBytes(16, 16),
		ServerAddress:   "testsmdpplus1.example.com",
		ServerChallenge: seqBytes(16, 32),
	}
	hexEq(t, g["ServerSigned1"], s.Encode())
}

func TestEncodeSmdpSigned2(t *testing.T) {
	s := &SmdpSigned2{TransactionID: seqBytes(16, 0), CCRequiredFlag: false}
	// Golden for the ccRequiredFlag=false case is embedded in AuthenticateClientResponseEs9.
	g := golden(t)
	require.Contains(t, g["AuthenticateClientResponseEs9_Ok"], hex.EncodeToString(s.Encode()))
}

func TestEncodeInitialiseSecureChannelRequest(t *testing.T) {
	r := &InitialiseSecureChannelRequest{
		RemoteOpID:    1,
		TransactionID: seqBytes(16, 0),
		ControlRefTemplate: ControlRefTemplate{
			KeyType: []byte{0x88}, KeyLen: []byte{0x10}, HostID: []byte("00000000"),
		},
		SmdpOtpk: seqBytes(65, 0),
		SmdpSign: repeat(0, 64),
	}
	g := golden(t)
	require.Contains(t, g["BoundProfilePackage"], hex.EncodeToString(r.Encode()))
}

// TestEncodeDoesNotMutateRemoteOpID pins that Encode is a pure function: it used
// to default a zero RemoteOpID to 1 in the receiver, which made encoding
// order-dependent and could desynchronise the signed bytes from the encoded
// element.
func TestEncodeDoesNotMutateRemoteOpID(t *testing.T) {
	r := &InitialiseSecureChannelRequest{
		TransactionID: seqBytes(16, 0),
		ControlRefTemplate: ControlRefTemplate{
			KeyType: []byte{0x88}, KeyLen: []byte{0x10}, HostID: []byte("00000000"),
		},
		SmdpOtpk: seqBytes(65, 0),
	}
	first := r.Encode()
	require.Zero(t, r.RemoteOpID, "Encode must not modify the receiver")
	require.Equal(t, first, r.Encode(), "Encode must be idempotent")

	// The zero RemoteOpID still defaults to 1 on the wire, and SignedBytes must
	// cover exactly that value.
	require.Contains(t, hex.EncodeToString(first), hex.EncodeToString([]byte{0x82, 0x01, 0x01}))
	require.Contains(t, hex.EncodeToString(r.SignedBytes(nil)), hex.EncodeToString([]byte{0x82, 0x01, 0x01}))
}

func TestEncodeConfigureISDPRequest(t *testing.T) {
	r := &ConfigureISDPRequest{DpOID: "2.999.10"}
	// Value captured from asn1tools.
	got, err := r.Encode()
	require.NoError(t, err)
	hexEq(t, "bf2407b805800388370a", got)
	empty, err := (&ConfigureISDPRequest{}).Encode()
	require.NoError(t, err)
	hexEq(t, "bf2400", empty)
}

// TestEncodeConfigureISDPRequestRejectsBadOID pins the contract that a bad
// configured OID surfaces as an error instead of a panic.
func TestEncodeConfigureISDPRequestRejectsBadOID(t *testing.T) {
	_, err := (&ConfigureISDPRequest{DpOID: "2"}).Encode()
	require.Error(t, err)
}

// TestACROIDLiteral guards the compile-time OID constant used by the ACR
// vendor extension.
func TestACROIDLiteral(t *testing.T) {
	require.NotEmpty(t, acrOID)
	got, err := asn1.DecodeOID(acrOID)
	require.NoError(t, err)
	require.Equal(t, "2.23.146.1.3.1.1", got)
}

func TestEncodeStoreMetadataRequest(t *testing.T) {
	class := int64(2)
	r := &StoreMetadataRequest{
		ICCID:               testutil.MustHex(t, "98001032547698103214"),
		ServiceProviderName: "SPN",
		ProfileName:         "Name",
		ProfileClass:        &class,
		Notifications: []NotificationConfigurationInformation{
			{Operation: 0x40, Address: "a"},
			{Operation: 0x20, Address: "a"},
			{Operation: 0x10, Address: "a"},
		},
	}
	g := golden(t)
	hexEq(t, g["StoreMetadataRequest"], r.Encode())
}

func TestAssembleBoundProfilePackage(t *testing.T) {
	bpp := &BoundProfilePackage{
		InitialiseSecureChannelRequest: &InitialiseSecureChannelRequest{
			RemoteOpID:         1,
			TransactionID:      seqBytes(16, 0),
			ControlRefTemplate: ControlRefTemplate{KeyType: []byte{0x88}, KeyLen: []byte{0x10}, HostID: []byte("00000000")},
			SmdpOtpk:           seqBytes(65, 0),
			SmdpSign:           repeat(0, 64),
		},
		FirstSequenceOf87: [][]byte{testutil.MustHex(t, "8704aabbccdd")},
		SequenceOf88:      [][]byte{testutil.MustHex(t, "8804aabbccdd")},
		SequenceOf86:      [][]byte{testutil.MustHex(t, "8604aabbccdd")},
	}
	g := golden(t)
	hexEq(t, g["BoundProfilePackage"], bpp.Assemble())

	// Decode round-trip.
	dec, err := DecodeBoundProfilePackage(bpp.Assemble())
	require.NoError(t, err)
	require.Equal(t, bpp.FirstSequenceOf87, dec.FirstSequenceOf87)
	require.Equal(t, bpp.SequenceOf88, dec.SequenceOf88)
	require.Equal(t, bpp.SequenceOf86, dec.SequenceOf86)
}

func TestEncodeResponses(t *testing.T) {
	g := golden(t)
	txn := seqBytes(16, 0)

	// AuthenticateClientResponseEs9 OK.
	profileMeta := (&StoreMetadataRequest{ICCID: testutil.MustHex(t, "98001032547698103214"), ServiceProviderName: "SPN", ProfileName: "Name"}).Encode()
	smdpSigned2 := (&SmdpSigned2{TransactionID: txn, CCRequiredFlag: false}).Encode()
	sig2 := asn1.RawTagged(asn1.App(55, false), repeat(0, 64))
	certDER := mustRead(t, "../../testdata/sgp26/EUM/CERT_EUM_NIST.der")
	got := AuthenticateClientResponseEs9Ok(txn, profileMeta, smdpSigned2, sig2, certDER)
	hexEq(t, g["AuthenticateClientResponseEs9_Ok"], got)

	// AuthenticateClientResponseEs9 error branch (implicit INTEGER tag 0x81).
	hexEq(t, g["AuthenticateClientResponseEs9_Err"], AuthenticateClientResponseEs9Error(1))

	// AuthenticateClientResponseEs9 ACR branch (A5).
	hexEq(t, g["AuthenticateClientResponseEs9_OkAcr"], AuthenticateClientResponseEs9OkAcr(txn, profileMeta))

	// GetBoundProfilePackageResponse OK.
	bpp := testutil.MustHex(t, g["BoundProfilePackage"])
	hexEq(t, g["GetBoundProfilePackageResponse_Ok"], GetBoundProfilePackageResponseOk(txn, bpp))

	// CancelSessionResponseEs9 OK.
	hexEq(t, g["CancelSessionResponseEs9"], CancelSessionResponseEs9Ok())

	// AuthenticateClientResponseEs11 OK.
	entries := [][2]string{{"e1", "a"}, {"e2", "b"}}
	hexEq(t, g["AuthenticateClientResponseEs11_Ok"], AuthenticateClientResponseEs11Ok(txn, entries))
}

func TestDecodePrepareDownloadResponse(t *testing.T) {
	g := golden(t)
	ok, errResp, err := DecodePrepareDownloadResponse(testutil.MustHex(t, g["PrepareDownloadResponse_Ok"]))
	require.NoError(t, err)
	require.Nil(t, errResp)
	require.NotNil(t, ok)
	require.Equal(t, seqBytes(16, 0), ok.EuiccSigned2.TransactionID)
	require.Equal(t, seqBytes(65, 0), ok.EuiccSigned2.EuiccOtpk)
	require.Equal(t, repeat(0, 64), ok.EuiccSignature2)

	ok, errResp, err = DecodePrepareDownloadResponse(testutil.MustHex(t, g["PrepareDownloadResponse_Err"]))
	require.NoError(t, err)
	require.Nil(t, ok)
	require.EqualValues(t, 1, errResp.DownloadErrorCode)
}

func TestDecodeAuthenticateServerResponse(t *testing.T) {
	g := golden(t)
	ok, errResp, err := DecodeAuthenticateServerResponse(testutil.MustHex(t, g["AuthenticateServerResponse_Ok"]))
	require.NoError(t, err)
	require.Nil(t, errResp)
	require.Equal(t, seqBytes(16, 0), ok.EuiccSigned1.TransactionID)
	require.Equal(t, "ABC", ok.EuiccSigned1.CtxParams1.MatchingID)
	require.NotNil(t, ok.EuiccSigned1.EuiccInfo2)
	require.Equal(t, mustRead(t, "../../testdata/sgp26/eUICC/CERT_EUICC_NIST.der"), ok.EuiccCertificate)
	require.Equal(t, mustRead(t, "../../testdata/sgp26/EUM/CERT_EUM_NIST.der"), ok.EumCertificate)

	_, errResp, err = DecodeAuthenticateServerResponse(testutil.MustHex(t, g["AuthenticateServerResponse_Err"]))
	require.NoError(t, err)
	require.EqualValues(t, 3, errResp.AuthenticateErrorCode)
}

func TestDecodeCancelSession(t *testing.T) {
	g := golden(t)
	ok, _, err := DecodeCancelSessionResponse(testutil.MustHex(t, g["CancelSessionResponse"]))
	require.NoError(t, err)
	require.Equal(t, seqBytes(16, 0), ok.Signed.TransactionID)
	require.Equal(t, "2.999.10", ok.Signed.SmdpOID)
	require.EqualValues(t, 0, ok.Signed.Reason)

	req, err := DecodeCancelSessionRequestEs9(testutil.MustHex(t, g["CancelSessionRequestEs9"]))
	require.NoError(t, err)
	require.Equal(t, seqBytes(16, 0), req.TransactionID)
	require.EqualValues(t, 5, req.Reason)
}

func TestDecodeHandleNotification(t *testing.T) {
	g := golden(t)
	h, err := DecodeHandleNotification(testutil.MustHex(t, g["HandleNotification"]))
	require.NoError(t, err)
	require.NotNil(t, h.Pending.InstallationResult)
	pir := h.Pending.InstallationResult
	require.Equal(t, seqBytes(16, 0), pir.Data.TransactionID)
	require.NotNil(t, pir.Data.FinalResult)
	require.True(t, pir.Data.FinalResult.Success)
	require.Equal(t, testutil.MustHex(t, "a0000005591010ffffffff8900001000"), pir.Data.FinalResult.AID)

	o, err := DecodePendingNotification(testutil.MustHex(t, g["OtherSignedNotification"]))
	require.NoError(t, err)
	require.NotNil(t, o.OtherSigned)
	require.EqualValues(t, 2, o.OtherSigned.Notification.SeqNumber)
	require.Equal(t, mustRead(t, "../../testdata/sgp26/eUICC/CERT_EUICC_NIST.der"), o.OtherSigned.EuiccCertificate)
}

func TestParseEUICCInfo1(t *testing.T) {
	g := golden(t)
	info, err := ParseEUICCInfo1(testutil.MustHex(t, g["EUICCInfo1"]))
	require.NoError(t, err)
	require.Equal(t, testutil.MustHex(t, "020200"), info.SVN)
	require.Len(t, info.CiPKIDListForVerification, 1)
	require.Len(t, info.CiPKIDListForSigning, 1)
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}
