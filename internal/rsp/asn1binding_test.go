package rsp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
)

func TestASN1BindingInitiateRequest(t *testing.T) {
	challenge := seqBytes(16, 0x11)
	info := tlvBytes([]byte{0xbf, 0x20}, []byte{0x82, 0x02, 0x02, 0x00})
	req := tlvBytes(asn1.Ctx(tagInitiateAuth, true),
		append(append(
			tlvBytes(asn1.Ctx(1, false), challenge),
			tlvBytes(asn1.Ctx(3, false), []byte("smdp.example.com"))...),
			info...))
	envelope := EncodeRemoteProfileProvisioningResponse(req)

	fn, inner, err := DecodeRemoteProfileProvisioningRequest(envelope)
	require.NoError(t, err)
	require.Equal(t, FuncInitiateAuthentication, fn)

	parsed, err := DecodeInitiateAuthenticationRequest(inner)
	require.NoError(t, err)
	require.Equal(t, challenge, parsed.EuiccChallenge)
	require.Equal(t, "smdp.example.com", parsed.SmdpAddress)
	require.Equal(t, info, parsed.EuiccInfo1)
}

func TestASN1BindingInitiateResponse(t *testing.T) {
	txn := seqBytes(16, 0x01)
	serverSigned1 := (&ServerSigned1{TransactionID: txn, ServerAddress: "x"}).Encode()
	sig := tlvBytes(asn1.App(55, false), seqBytes(64, 0x22))
	ski := append([]byte{0x04, 0x14}, seqBytes(20, 0x33)...)
	cert := tlvBytes([]byte{0x30}, nil)

	ok := InitiateAuthenticationResponseOk(txn, serverSigned1, sig, ski, cert)
	fn, inner, err := DecodeRemoteProfileProvisioningRequest(EncodeRemoteProfileProvisioningResponse(ok))
	require.NoError(t, err)
	require.Equal(t, FuncInitiateAuthentication, fn)

	tlv, _, err := asn1.ReadTLV(inner)
	require.NoError(t, err)
	require.Equal(t, "bf39", hexTag(tlv.Tag))

	alt, ok2 := tlv.Find(asn1.Ctx(0, true))
	require.True(t, ok2, "Ok branch must be tagged A0")
	require.Equal(t, txn, childBytes(alt, asn1.Ctx(0, false)))
	_, hasSeq := alt.Find([]byte{0x30}) // serverSigned1 / serverCertificate
	require.True(t, hasSeq)
	_, hasSig := alt.Find(asn1.App(55, false)) // serverSignature1
	require.True(t, hasSig)
	_, hasSKI := alt.Find(asn1.TagOctetStr) // euiccCiPKIdToBeUsed
	require.True(t, hasSKI)

	// Error branch carries an implicit INTEGER (0x81).
	errResp := InitiateAuthenticationResponseError(3)
	_, errInner, err := DecodeRemoteProfileProvisioningRequest(EncodeRemoteProfileProvisioningResponse(errResp))
	require.NoError(t, err)
	errTLV, _, err := asn1.ReadTLV(errInner)
	require.NoError(t, err)
	v, ok3 := errTLV.Find(asn1.Ctx(1, false))
	require.True(t, ok3)
	n, err := v.Int()
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
}

func TestDecodeASN1BindingRequestsUnwrapExplicitFields(t *testing.T) {
	txn := seqBytes(16, 0x09)

	// AuthenticateClientRequest: authenticateServerResponse [56] wraps a CHOICE.
	asr := tlvBytes([]byte{0xbf, 0x38}, tlvBytes(asn1.Ctx(0, true), nil))
	authReq := tlvBytes([]byte{0xbf, 0x3b}, append(
		tlvBytes(asn1.Ctx(0, false), txn),
		tlvBytes([]byte{0xbf, 0x38}, asr)...))
	gotAuth, err := DecodeAuthenticateClientRequest(authReq)
	require.NoError(t, err)
	require.Equal(t, txn, gotAuth.TransactionID)
	require.Equal(t, asr, gotAuth.AuthenticateResponse)

	// GetBoundProfilePackageRequest: prepareDownloadResponse [33] wraps a CHOICE.
	pdr := tlvBytes([]byte{0xbf, 0x21}, tlvBytes(asn1.Ctx(0, true), nil))
	bppReq := tlvBytes([]byte{0xbf, 0x3a}, append(
		tlvBytes(asn1.Ctx(0, false), txn),
		tlvBytes([]byte{0xbf, 0x21}, pdr)...))
	gotBPP, err := DecodeGetBoundProfilePackageRequest(bppReq)
	require.NoError(t, err)
	require.Equal(t, txn, gotBPP.TransactionID)
	require.Equal(t, pdr, gotBPP.PrepareDownloadRaw)
}

func TestUnwrapExplicit(t *testing.T) {
	inner := tlvBytes([]byte{0xbf, 0x38}, []byte{0x01, 0x02})
	double := tlvBytes([]byte{0xbf, 0x38}, inner)
	field, _, err := asn1.ReadTLV(double)
	require.NoError(t, err)
	require.Equal(t, inner, unwrapExplicit(field, []byte{0xbf, 0x38}))

	// Single-tagged form is returned unchanged.
	field2, _, err := asn1.ReadTLV(inner)
	require.NoError(t, err)
	require.Equal(t, inner, unwrapExplicit(field2, []byte{0xbf, 0x38}))
}
