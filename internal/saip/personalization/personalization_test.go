package personalization

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
	"rsp42/internal/saip"
	"rsp42/internal/testutil"
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
		K:         testutil.MustHex(t, "465b5ce8b199b49faa5f0a2ee238a6bc"),
		OPc:       testutil.MustHex(t, "cdc202d5123e20f62b6d676ac72cab35"),
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
		RotationConstants: testutil.MustHex(t, "4000204060"),
		XoringConstants:   make([]byte, 80),
		NumberOfKeccak:    &keccak,
	}))

	seq2, err := saip.ParseUPP(seq.Encode())
	require.NoError(t, err)
	aka := seq2.Find(saip.TagAKAParameter)
	require.NotNil(t, aka)
	algo := aka.Find(asn1.Ctx(1, true)).Find(asn1.Ctx(1, true))
	require.Equal(t, testutil.MustHex(t, "4000204060"), algo.Find(asn1.Ctx(4, false)).Value)
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

func TestEncodePLMN(t *testing.T) {
	// TS 24.008 §10.5.1.13 worked examples.
	b, err := EncodePLMN("234", "15")
	require.NoError(t, err)
	require.Equal(t, []byte{0x32, 0xF4, 0x51}, b)

	b, err = EncodePLMN("208", "01")
	require.NoError(t, err)
	require.Equal(t, []byte{0x02, 0xF8, 0x10}, b)

	// Three-digit MNCs keep the third digit in the high nibble of octet 4, and
	// MCC digit 3 in its low nibble.
	b, err = EncodePLMN("310", "260")
	require.NoError(t, err)
	require.Equal(t, []byte{0x13, 0x00, 0x62}, b)

	b, err = EncodePLMN("311", "260")
	require.NoError(t, err)
	require.Equal(t, []byte{0x13, 0x01, 0x62}, b)

	_, err = EncodePLMN("20", "01")
	require.Error(t, err)
	_, err = EncodePLMN("208", "0")
	require.Error(t, err)
	_, err = EncodePLMN("20a", "01")
	require.Error(t, err)
}

// TestApplyOperatorOverrides covers the G7 additions: raw EF patches, the ACC
// value, the MSISDN and the preferred PLMN list. Each is asserted only when the
// template actually carries the file, and an override naming an absent file is
// an error.
func TestApplyOperatorOverrides(t *testing.T) {
	seq, _ := loadUPP(t, "TS48v1_A.der")

	// A raw patch of an existing file (EF.SPN).
	require.NotNil(t, seq.FindFile(saip.FIDSPN))
	eng := &Engine{}
	require.NoError(t, eng.Apply(seq, &Data{
		FilePatches: []FilePatch{{FID: saip.FIDSPN, Hex: "4f70657261746f72"}},
	}))
	require.Equal(t, []byte("Operator"), seq.FindFile(saip.FIDSPN).Body())

	// A patch naming a file the template does not have is refused.
	seq2, _ := loadUPP(t, "TS48v1_A.der")
	err := eng.Apply(seq2, &Data{FilePatches: []FilePatch{{FID: 0x6F99, Hex: "00"}}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "6F99")

	// Non-hex patch content is refused.
	seq3, _ := loadUPP(t, "TS48v1_A.der")
	require.Error(t, eng.Apply(seq3, &Data{FilePatches: []FilePatch{{FID: saip.FIDSPN, Hex: "zz"}}}))

	// ACC, MSISDN and PLMN follow the same "file must exist" rule.
	seq4, _ := loadUPP(t, "TS48v1_A.der")
	acc := uint16(0x0001)
	data := &Data{ACC: &acc, MSISDN: "8613800138000", PLMN: []PLMNRecord{{MCC: "208", MNC: "01", AcT: 0x8000}}}
	err = eng.Apply(seq4, data)
	if seq4.FindFile(saip.FIDACC) == nil || seq4.FindFile(saip.FIDMSISDN) == nil ||
		(seq4.FindFile(saip.FIDPLMNwAcT) == nil && seq4.FindFile(saip.FIDHPLMNwAcT) == nil) {
		require.Error(t, err, "a missing target file must be reported")
	} else {
		require.NoError(t, err)
		require.Equal(t, []byte{0x00, 0x01}, seq4.FindFile(saip.FIDACC).Body())
		require.Equal(t, "8613800138000", decodeMSISDN(seq4.FindFile(saip.FIDMSISDN).Body()))
	}
}

// TestApplyPLMNTargetsHPLMNwAcT pins the FID fix: the PLMN list goes to
// EF.HPLMNwAcT (6F62). The constant previously held 0x6F31 (EF.HPPLMN, a
// 1-octet file), so the PLMN record overwrote EF.HPPLMN and EF.HPLMNwAcT was
// never written.
func TestApplyPLMNTargetsHPLMNwAcT(t *testing.T) {
	require.Equal(t, uint16(0x6F62), uint16(saip.FIDHPLMNwAcT), "EF.HPLMNwAcT is FID 6F62")

	file := func(fid, content []byte) *asn1.Node {
		return asn1.NewConstructed(asn1.Ctx(2, true),
			asn1.NewConstructed([]byte{0xa1}, asn1.NewPrimitive([]byte{0x83}, fid)),
			asn1.NewPrimitive([]byte{0x83}, content),
		)
	}
	tid, err := asn1.EncodeOID("2.23.143.1.2.13")
	require.NoError(t, err)
	hdr := asn1.NewConstructed(saip.TagHeader,
		asn1.NewPrimitive([]byte{0x80}, []byte{2}),
		asn1.NewPrimitive([]byte{0x81}, []byte{3}),
	)
	pe := asn1.NewConstructed(saip.TagOptUSIM,
		asn1.NewConstructed([]byte{0xa0}, asn1.NewPrimitive([]byte{0x80}, nil)),
		asn1.NewPrimitive([]byte{0x81}, tid),
		file([]byte{0x6f, 0x31}, []byte{0x0a}),                   // EF.HPPLMN, 1 octet
		file([]byte{0x6f, 0x62}, []byte{0x00, 0x00, 0x00, 0x00}), // EF.HPLMNwAcT
	)
	seq := &saip.Sequence{Elements: []*asn1.Node{hdr, pe}}

	require.NoError(t, (&Engine{}).Apply(seq, &Data{
		PLMN: []PLMNRecord{{MCC: "208", MNC: "01", AcT: 0x8000}},
	}))

	// 208/01 → 02 F8 10, AcT 8000, written to EF.HPLMNwAcT.
	require.Equal(t, []byte{0x02, 0xf8, 0x10, 0x80, 0x00}, seq.FindFile(saip.FIDHPLMNwAcT).Body())
	// The 1-octet EF.HPPLMN (6F31) is untouched.
	require.Equal(t, []byte{0x0a}, seq.FindFile(0x6f31).Body())
}

// decodeMSISDN reverses the EF.MSISDN encoding (length, TON/NPI, swapped BCD).
func decodeMSISDN(b []byte) string {
	if len(b) < 3 {
		return ""
	}
	out := make([]byte, 0, 2*(len(b)-2))
	for _, by := range b[2:] {
		out = append(out, hexDigit(by&0x0f), hexDigit(by>>4))
	}
	s := string(out)
	for len(s) > 0 && (s[len(s)-1] == 'F' || s[len(s)-1] == 'f') {
		s = s[:len(s)-1]
	}
	return s
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + (n - 10)
}

// TestApplySdKeysAndMncLen pins N17: the GP key set is written to
// PE-SecurityDomain and the MNC length to EF.AD (FID 6FAD).
func TestApplySdKeysAndMncLen(t *testing.T) {
	seq, _ := loadUPP(t, "TS48v2_SAIP2.3_BERTLV.der")

	// EF.AD exists and defaults to 00 00 00 02 (two-digit MNC).
	ad := seq.FindFile(saip.FIDEFAD)
	require.NotNil(t, ad, "the SAIP 2.3 test profile carries EF.AD (6FAD)")
	require.Equal(t, byte(0x02), ad.Body()[3]&0x0F)

	macLen := 8
	eng := &Engine{}
	err := eng.Apply(seq, &Data{
		MncLen: intPtr(3),
		SdKeys: []SdKey{{
			KeyUsageQualifier: "38",
			KeyIdentifier:     "01",
			KeyVersionNumber:  "30",
			Components: []SdKeyComponent{
				{KeyType: "88", KeyData: "11223344556677889900AABBCCDDEEFF", MacLength: &macLen},
			},
		}},
	})
	require.NoError(t, err)

	// EF.AD byte 4 now declares a three-digit MNC and keeps the high nibble.
	body := ad.Body()
	require.Equal(t, byte(0x03), body[3]&0x0F)
	require.Equal(t, byte(0x00), body[3]&0xF0)

	// The re-encoded profile carries the injected key object.
	reparsed, err := saip.ParseUPP(seq.Encode())
	require.NoError(t, err)
	sd := reparsed.Find(saip.TagSecurityDomain)
	require.NotNil(t, sd)
	keyList := findKeyList(sd)
	require.NotNil(t, keyList, "PE-SecurityDomain must carry a keyList")
	require.Len(t, keyList.Children, 1)
	obj := keyList.Children[0]
	require.Equal(t, []byte{0x95}, obj.Children[0].Tag)
	require.Equal(t, []byte{0x38}, obj.Children[0].Value)
	require.Equal(t, []byte{0x30}, obj.Children[lastComponentIndex(obj)].Tag)
}

func findKeyList(sd *asn1.Node) *asn1.Node {
	for _, c := range sd.Children {
		if len(c.Children) > 0 && len(c.Children[0].Tag) == 1 && c.Children[0].Tag[0] == 0x30 {
			return c
		}
	}
	return nil
}

func lastComponentIndex(obj *asn1.Node) int {
	return len(obj.Children) - 1
}

func intPtr(v int) *int { return &v }

func TestApplyMncLenRejectsBadInput(t *testing.T) {
	seq, _ := loadUPP(t, "TS48v2_SAIP2.3_BERTLV.der")
	require.Error(t, (&Engine{}).Apply(seq, &Data{MncLen: intPtr(4)}))
	require.Error(t, (&Engine{}).Apply(seq, &Data{MncLen: intPtr(0)}))
}
