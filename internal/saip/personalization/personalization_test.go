package personalization

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
	"rsp42/internal/saip"
)

func loadUPP(t *testing.T, name string) (*saip.Sequence, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/upp/" + name)
	require.NoError(t, err)
	seq, err := saip.ParseUPP(raw)
	require.NoError(t, err)
	return seq, raw
}

func TestParseHeaderAndFiles(t *testing.T) {
	seq, _ := loadUPP(t, "TS48v1_A.der")
	hdr, err := saip.ParseHeader(seq.Header())
	require.NoError(t, err)
	require.Equal(t, byte(2), hdr.Major)
	require.Equal(t, "89000123456789012341", hex.EncodeToString(hdr.ICCID))

	iccidFile := seq.FindFile(saip.FIDICCID)
	require.NotNil(t, iccidFile)
	require.Equal(t, "98001032547698103214", hex.EncodeToString(iccidFile.Body()))

	imsiFile := seq.FindFile(saip.FIDIMSI)
	require.NotNil(t, imsiFile)
	// EF.IMSI content for IMSI 001010123456063.
	require.Equal(t, "080910101032540636", hex.EncodeToString(imsiFile.Body()))
}

func TestRoundTripPreservesElements(t *testing.T) {
	seq, raw := loadUPP(t, "TS48v1_A.der")
	out := seq.Encode()
	require.Equal(t, len(raw), len(out))
	require.Equal(t, raw, out)

	seq2, err := saip.ParseUPP(out)
	require.NoError(t, err)
	require.Equal(t, len(seq.Elements), len(seq2.Elements))
}

func TestEncodeIMSI(t *testing.T) {
	require.Equal(t, "080910101032540636", hex.EncodeToString(EncodeIMSI("001010123456063")))
	// Even-length IMSI (14 digits).
	require.Equal(t, "0801101010325406f6", hex.EncodeToString(EncodeIMSI("00101012345606")))
}

func TestApplyPersonalization(t *testing.T) {
	seq, _ := loadUPP(t, "TS48v1_A.der")

	d := &Data{
		ICCID:     "89000123456789012342",
		IMSI:      "001010123456064",
		K:         mustHex(t, "465b5ce8b199b49faa5f0a2ee238a6bc"),
		OPc:       mustHex(t, "cdc202d5123e20f62b6d676ac72cab35"),
		Algorithm: "milenage",
		PIN1:      "4321",
		PUK1:      "87654321",
		SPN:       "RSP42",
	}
	eng := &Engine{Algorithm: "milenage"}
	require.NoError(t, eng.Apply(seq, d))

	// Re-parse the modified profile.
	seq2, err := saip.ParseUPP(seq.Encode())
	require.NoError(t, err)

	hdr, err := saip.ParseHeader(seq2.Header())
	require.NoError(t, err)
	require.Equal(t, "89000123456789012342", hex.EncodeToString(hdr.ICCID))

	require.Equal(t, "98001032547698103224", hex.EncodeToString(seq2.FindFile(saip.FIDICCID).Body()))
	require.Equal(t, hex.EncodeToString(EncodeIMSI("001010123456064")), hex.EncodeToString(seq2.FindFile(saip.FIDIMSI).Body()))
	require.Equal(t, "RSP42", string(seq2.FindFile(saip.FIDSPN).Body()))

	// AKA parameter now says milenage.
	require.Equal(t, 1, saip.AKAAlgorithmID(seq2.Find(saip.TagAKAParameter)))

	// The mandatory services list reflects the algorithm change.
	hdr2, err := saip.ParseHeader(seq2.Header())
	require.NoError(t, err)
	require.True(t, hdr2.HasService(saip.SvcMilenage))
	require.False(t, hdr2.HasService(saip.SvcUSIMTestAlgorithm))
}

func TestApplyExtendedParams(t *testing.T) {
	seq, _ := loadUPP(t, "TS48v1_A.der")
	keccak := int64(2)
	eng := &Engine{Algorithm: "milenage"}
	require.NoError(t, eng.Apply(seq, &Data{
		ICCID:             "89000123456789012343",
		IMSI:              "001010123456065",
		K:                 make([]byte, 16),
		OPc:               make([]byte, 16),
		ADM1:              "11111111",
		ADM2:              "22222222",
		RotationConstants: mustHex(t, "4000204060"),
		XoringConstants:   make([]byte, 80),
		NumberOfKeccak:    &keccak,
	}))

	seq2, err := saip.ParseUPP(seq.Encode())
	require.NoError(t, err)
	aka := seq2.Find(saip.TagAKAParameter)
	require.NotNil(t, aka)
	algo := aka.Find(asn1.Ctx(1, true)).Find(asn1.Ctx(1, true))
	require.Equal(t, mustHex(t, "4000204060"), algo.Find(asn1.Ctx(4, false)).Value)
	require.Equal(t, asn1.IntBytes(2), algo.Find(asn1.Ctx(7, false)).Value)

	// ADM1/ADM2 applied to the PIN PE (key references 0x0a / 0x0b).
	found := 0
	for _, pe := range seq2.FindAll(saip.TagPinCodes) {
		for _, entry := range allEntries(pe) {
			ref := entry.Find(asn1.Ctx(0, false))
			if ref == nil || len(ref.Value) == 0 {
				continue
			}
			if ref.Value[len(ref.Value)-1] == 0x0a || ref.Value[len(ref.Value)-1] == 0x0b {
				found++
			}
		}
	}
	require.GreaterOrEqual(t, found, 2)
}

func allEntries(pe *asn1.Node) []*asn1.Node {
	container := pe.Find(asn1.Ctx(1, true))
	if container == nil {
		return nil
	}
	entries := container.Children
	if len(entries) == 1 && len(entries[0].Tag) == 1 && entries[0].Tag[0] == 0xa0 {
		entries = entries[0].Children
	}
	return entries
}

func TestApplyTwoProfiles(t *testing.T) {
	for _, name := range []string{"TS48v1_A.der", "TS48v3_SAIP2.3_BERTLV.der"} {
		t.Run(name, func(t *testing.T) {
			seq, _ := loadUPP(t, name)
			eng := &Engine{Algorithm: "milenage"}
			require.NoError(t, eng.Apply(seq, &Data{
				ICCID: "89000123456789012345",
				IMSI:  "001010123456099",
				K:     make([]byte, 16),
				OPc:   make([]byte, 16),
				PIN1:  "1234",
				PUK1:  "12345678",
				SPN:   "TEST",
			}))
			seq2, err := saip.ParseUPP(seq.Encode())
			require.NoError(t, err)
			hdr, err := saip.ParseHeader(seq2.Header())
			require.NoError(t, err)
			require.Equal(t, "89000123456789012345", hex.EncodeToString(hdr.ICCID))
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
