package rsp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
)

// choiceEnvelope wraps CHOICE alternatives in an outer response tag, the way a
// real AuthenticateServerResponse (BF38) does.
func choiceEnvelope(t *testing.T, alts ...*asn1.Builder) asn1.TLV {
	t.Helper()
	tlv, _, err := asn1.ReadTLV(asn1.Marshal(asn1.New(asn1.Ctx(56, true), alts...)))
	require.NoError(t, err)
	return tlv
}

// TestSplitChoice covers the ok/error alternatives of the SGP.22 response
// CHOICE, including the absent cases every decoder has to handle.
func TestSplitChoice(t *testing.T) {
	okAlt := asn1.New(asn1.Ctx(0, true),
		asn1.New(asn1.TagSequence, asn1.Prim(asn1.TagInteger, []byte{0x01})),
		asn1.Prim([]byte{0x5f, 0x37}, []byte{0x02}),
	)
	errAlt := asn1.New(asn1.Ctx(1, true), asn1.Prim(asn1.TagInteger, []byte{0x07}))

	t.Run("ok present", func(t *testing.T) {
		ok, hasOK, _, hasErr := splitChoice(choiceEnvelope(t, okAlt))
		require.True(t, hasOK)
		require.False(t, hasErr)
		require.NotEmpty(t, ok.Raw)
		kids, err := ok.Children()
		require.NoError(t, err)
		require.Len(t, kids, 2)
		require.True(t, isSequence(kids[0]))
		require.True(t, isSignature(kids[1]))
	})

	t.Run("error present", func(t *testing.T) {
		_, hasOK, e, hasErr := splitChoice(choiceEnvelope(t, errAlt))
		require.False(t, hasOK)
		require.True(t, hasErr)
		code, found := choiceErrorCode(e)
		require.True(t, found)
		require.EqualValues(t, 7, code)
	})

	t.Run("neither present", func(t *testing.T) {
		_, hasOK, _, hasErr := splitChoice(choiceEnvelope(t, asn1.New(asn1.Ctx(3, true))))
		require.False(t, hasOK)
		require.False(t, hasErr)
	})
}

// TestChoiceErrorCodeAcceptsBothForms: SGP.22 carries the code as a bare
// INTEGER, but an error alternative may wrap it in a context-tagged [1] element.
func TestChoiceErrorCodeAcceptsBothForms(t *testing.T) {
	bare := asn1.Marshal(asn1.New(asn1.Ctx(1, true), asn1.Prim(asn1.TagInteger, []byte{0x09})))
	wrapped := asn1.Marshal(asn1.New(asn1.Ctx(1, true), asn1.Prim(asn1.Ctx(1, false), []byte{0x0A})))

	for _, tc := range []struct {
		name string
		raw  []byte
		want int64
	}{
		{"bare INTEGER", bare, 9},
		{"context-tagged", wrapped, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlv, _, err := asn1.ReadTLV(tc.raw)
			require.NoError(t, err)
			code, found := choiceErrorCode(tlv)
			require.True(t, found)
			require.Equal(t, tc.want, code)
		})
	}

	// No code at all.
	empty := asn1.Marshal(asn1.New(asn1.Ctx(1, true)))
	tlv, _, err := asn1.ReadTLV(empty)
	require.NoError(t, err)
	_, found := choiceErrorCode(tlv)
	require.False(t, found)
}

// TestTagPredicates pins the tag discrimination used by the ok-branch walks.
func TestTagPredicates(t *testing.T) {
	seq, _, err := asn1.ReadTLV(asn1.Marshal(asn1.New(asn1.TagSequence, asn1.Prim(asn1.TagInteger, []byte{1}))))
	require.NoError(t, err)
	require.True(t, isSequence(seq))
	require.False(t, isSignature(seq))

	sig, _, err := asn1.ReadTLV(asn1.Marshal(asn1.Prim([]byte{0x5f, 0x37}, []byte{0x01})))
	require.NoError(t, err)
	require.True(t, isSignature(sig))
	require.False(t, isSequence(sig))
}
