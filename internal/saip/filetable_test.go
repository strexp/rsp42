package saip

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
)

// TestTemplateFileTable pins the Annex A row counts and a sample of the values
// so a transcription error surfaces. The counts equal the number of File
// members of the corresponding PE definition in §8.3.4.
func TestTemplateFileTable(t *testing.T) {
	counts := map[string]int{
		"mf": 6, "cd": 3, "telecom": 38, "phonebook": 18, "gsm-access": 5,
		"df-5gs": 11, "df-saip": 2, "usim": 24, "opt-usim": 74, "isim": 7,
		"opt-isim": 9, "csim": 35, "opt-csim": 67, "eap": 8,
	}
	total := 0
	for pe, want := range counts {
		require.Len(t, TemplateFiles(pe), want, "template %s", pe)
		total += want
	}
	require.Equal(t, 307, total)
	require.Nil(t, TemplateFiles("genericFileManagement"), "GFM is not backed by a template")

	// Spot checks across the columns.
	f, ok := FindTemplateFile("usim", 0x6F07)
	require.True(t, ok)
	require.Equal(t, "EF IMSI", f.Name)
	require.Equal(t, "TR", f.Type)
	require.Equal(t, 9, f.Size)
	require.True(t, f.ContentRequired)

	f, ok = FindTemplateFile("mf", 0x2F00)
	require.True(t, ok)
	require.Equal(t, "EF DIR", f.Name)
	require.Equal(t, -1, f.NBRec, "the Annex A cell is X")
	require.Equal(t, -1, f.Size, "the Annex A cell is X")
	require.Equal(t, 0x1E, f.SFI)

	f, ok = FindTemplateFile("phonebook", 0x4F50)
	require.True(t, ok)
	require.Equal(t, "EF IAP", f.Name)
	require.Equal(t, uint16(0x4F57), f.FIDEnd, "EF IAP is an FID range")
	require.True(t, f.InRange(0x4F55))

	// 4F20 is EF.IMG under DF GRAPHICS and EF.MLPL under DF MMSS: the first
	// FID match wins, so callers must consider the DF scope.
	f, ok = FindTemplateFile("telecom", 0x4F20)
	require.True(t, ok)
	require.Equal(t, "EF IMG", f.Name)

	f, ok = FindTemplateFile("df-5gs", 0x5FC0)
	require.True(t, ok)
	require.Equal(t, "DF", f.Type)
	require.Equal(t, 14, f.ARR)

	f, ok = FindTemplateFile("opt-usim", 0x6FF1)
	require.True(t, ok)
	require.Equal(t, "EF IPS", f.Name)
	require.Equal(t, "CY", f.Type)
	require.Equal(t, 4, f.Size)

	// ADF placeholders carry no default FID.
	_, ok = FindTemplateFile("usim", 0x0000)
	require.False(t, ok, "the ADF temporary FID has no default, so a FID lookup cannot match it")
}

// --- helpers ---------------------------------------------------------------

func mustOID(oid string) *asn1.Node {
	enc, err := asn1.EncodeOID(oid)
	if err != nil {
		panic(err)
	}
	return asn1.NewPrimitive(tagOID, enc)
}

// templatePE builds a file-system PE with a mandated header and a templateID.
func templatePE(tag []byte, memberFiles ...*asn1.Node) *asn1.Node {
	kids := []*asn1.Node{
		asn1.NewConstructed(peHeader, asn1.NewPrimitive(peMandated, nil)),
		mustOID("2.23.143.1.2.1"),
	}
	kids = append(kids, memberFiles...)
	return asn1.NewConstructed(tag, kids...)
}

// fileMember builds the File member that lives at PE member index idx.
func fileMember(idx int, children ...*asn1.Node) *asn1.Node {
	return asn1.NewConstructed(asn1.Ctx(uint64(idx), true), children...)
}

func fcpOf(children ...*asn1.Node) *asn1.Node {
	return asn1.NewConstructed(tagFcp, children...)
}

// fileWithContent builds a File member whose Fcp is followed by a
// fillFileContent sibling (the File CHOICE), which is how content is carried.
func fileWithContent(idx int, body []byte, fcpChildren ...*asn1.Node) *asn1.Node {
	return fileMember(idx, fcpOf(fcpChildren...), asn1.NewPrimitive(tagFileContent, body))
}

// profileWith builds a valid element sequence around the given header and the
// second (MF) element.
func profileWith(hdr, second *asn1.Node, extra ...*asn1.Node) *Sequence {
	elems := []*asn1.Node{hdr, second}
	elems = append(elems, extra...)
	elems = append(elems, asn1.NewConstructed(TagEnd))
	return &Sequence{Elements: elems}
}

// profileAroundMF wraps an MF PE plus optional extra PEs.
func profileAroundMF(mf *asn1.Node, extra ...*asn1.Node) *Sequence {
	return profileWith(headerWithGFSTE(), mf, extra...)
}

// profileAroundMFPlus wraps an empty MF PE plus extra PEs.
func profileAroundMFPlus(extra ...*asn1.Node) *Sequence {
	return profileWith(headerWithGFSTE(), asn1.NewConstructed(TagMF), extra...)
}

// adfMember is the PE-USIM adf-usim File member (index 2) with an AID and
// pinStatusTemplateDO, satisfied by a dummy content.
func adfMember() *asn1.Node {
	return fileWithContent(2, []byte{0x00},
		asn1.NewPrimitive(tagFcpDfName, []byte{0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}),
		asn1.NewPrimitive(tagFcpPinStatus, []byte{0x01, 0x0a}))
}

func imsiMember(idx int) *asn1.Node {
	return fileWithContent(idx, make([]byte, 9),
		asn1.NewPrimitive(tagFcpFileID, []byte{0x6f, 0x07}),
		asn1.NewPrimitive(tagFcpEFSize, []byte{0x09}))
}

// --- validation ------------------------------------------------------------

// TestValidateTemplateFileSizeRequired pins the §8.3.3 rule that a parameter
// with no template default ("X" in Annex A) has to be provided.
func TestValidateTemplateFileSizeRequired(t *testing.T) {
	ok := templatePE(TagUSIM, adfMember(), imsiMember(3),
		fileMember(4, fcpOf(
			asn1.NewPrimitive(tagFcpFileID, []byte{0x6f, 0x06}),
			asn1.NewPrimitive(tagFcpEFSize, []byte{0x01, 0x2c}),
		)),
	)
	require.Empty(t, profileAroundMFPlus(ok).ValidateV231().Errors)

	// Removing efFileSize from EF ARR must fail: it has no default size.
	bad := templatePE(TagUSIM, adfMember(), imsiMember(3),
		fileMember(4, fcpOf(asn1.NewPrimitive(tagFcpFileID, []byte{0x6f, 0x06}))),
	)
	errs := strings.Join(profileAroundMFPlus(bad).ValidateV231().Errors, "\n")
	require.Contains(t, errs, "EF ARR")
	require.Contains(t, errs, "no default file size")
}

// TestValidateTemplateFileKindParams pins the DF/EF-specific FCP parameter
// rules of §8.3.3.
func TestValidateTemplateFileKindParams(t *testing.T) {
	// efFileSize on the ADF, and a missing dfName.
	usim := templatePE(TagUSIM,
		fileMember(2, fcpOf(
			asn1.NewPrimitive(tagFcpFileID, []byte{0x00, 0x01}),
			asn1.NewPrimitive(tagFcpEFSize, []byte{0x10}),
		)),
	)
	errs := strings.Join(profileAroundMFPlus(usim).ValidateV231().Errors, "\n")
	require.Contains(t, errs, "efFileSize is not allowed for a ADF file")
	require.Contains(t, errs, "dfName (AID) is mandatory for an ADF")

	// pinStatusTemplateDO on an EF.
	usim = templatePE(TagUSIM, adfMember(),
		fileWithContent(3, make([]byte, 9),
			asn1.NewPrimitive(tagFcpFileID, []byte{0x6f, 0x07}),
			asn1.NewPrimitive(tagFcpEFSize, []byte{0x09}),
			asn1.NewPrimitive(tagFcpPinStatus, []byte{0x01, 0x0a}),
		),
	)
	errs = strings.Join(profileAroundMFPlus(usim).ValidateV231().Errors, "\n")
	require.Contains(t, errs, "pinStatusTemplateDO is not allowed for an EF")
}

// TestValidateTemplateFileSFI pins the shortEFID value domain.
func TestValidateTemplateFileSFI(t *testing.T) {
	usimWithSFI := func(sfi []byte) *Sequence {
		return profileAroundMFPlus(templatePE(TagUSIM, adfMember(),
			fileWithContent(3, make([]byte, 9),
				asn1.NewPrimitive(tagFcpFileID, []byte{0x6f, 0x07}),
				asn1.NewPrimitive(tagFcpEFSize, []byte{0x09}),
				asn1.NewPrimitive(tagFcpShortEFID, sfi),
			),
		))
	}
	require.Empty(t, usimWithSFI([]byte{0x08}).ValidateV231().Errors)
	require.Contains(t, strings.Join(usimWithSFI([]byte{0x07}).ValidateV231().Errors, "\n"),
		"bits b3..b1 set to 000")
	require.Contains(t, strings.Join(usimWithSFI([]byte{0xf8}).ValidateV231().Errors, "\n"),
		"outside the 1..30 range")
	require.Contains(t, strings.Join(usimWithSFI([]byte{0x08, 0x00}).ValidateV231().Errors, "\n"),
		"at most 1 octet")
}

// TestValidateTemplateFileDuplicates pins fileID uniqueness within a scope.
func TestValidateTemplateFileDuplicates(t *testing.T) {
	usim := templatePE(TagUSIM, adfMember(), imsiMember(3),
		fileWithContent(4, []byte{0x00, 0x00},
			asn1.NewPrimitive(tagFcpFileID, []byte{0x6f, 0x07}),
			asn1.NewPrimitive(tagFcpEFSize, []byte{0x02}),
		),
	)
	require.Contains(t, strings.Join(profileAroundMFPlus(usim).ValidateV231().Errors, "\n"),
		"fileID 6F07 is already used")
}

// TestValidateTemplateFileType pins §8.3.3's "the file type must not change".
func TestValidateTemplateFileType(t *testing.T) {
	usim := templatePE(TagUSIM, adfMember(),
		fileWithContent(3, make([]byte, 9),
			asn1.NewPrimitive(tagFcpFileID, []byte{0x6f, 0x07}),
			asn1.NewPrimitive(tagFcpEFSize, []byte{0x09}),
			asn1.NewPrimitive(tagFcpFileDescriptor, []byte{0x78, 0x21}),
		),
	)
	require.Contains(t, strings.Join(profileAroundMFPlus(usim).ValidateV231().Errors, "\n"),
		"fileDescriptor declares a df but the template defines a ef")
}

// TestValidateTemplateFileUnknownFID pins that an additional file is a warning,
// because §8.3.4.3 requires it to be created with PE-GenericFileManagement.
func TestValidateTemplateFileUnknownFID(t *testing.T) {
	mf := templatePE(TagMF,
		fileWithContent(8, []byte{0x00, 0x00},
			asn1.NewPrimitive(tagFcpFileID, []byte{0x6f, 0xaa}),
			asn1.NewPrimitive(tagFcpEFSize, []byte{0x02}),
		),
	)
	v := profileAroundMF(mf).ValidateV231()
	require.Empty(t, v.Errors)
	require.Contains(t, strings.Join(v.Warnings, "\n"), "not part of the V2.3.1 mf template")
}

// TestPEMemberIndexHighTagForm pins the BER high-tag-number decode of a PE
// member tag: tags 31..127 are 0xBF followed by the number itself, so the
// index is tag[1], not 31+tag[1] (which shifted every member above 30).
func TestPEMemberIndexHighTagForm(t *testing.T) {
	for _, tc := range []struct {
		idx int
		tag []byte
	}{
		{31, []byte{0xbf, 0x1f}},
		{33, []byte{0xbf, 0x21}},
		{39, []byte{0xbf, 0x27}},
	} {
		got, ok := peMemberIndex(tc.tag)
		require.True(t, ok, "peMemberIndex(%x)", tc.tag)
		require.Equal(t, tc.idx, got, "peMemberIndex(%x)", tc.tag)
	}
	// Three-byte high-tag-number forms (>= 128) are not PE members.
	_, ok := peMemberIndex([]byte{0xbf, 0x81, 0x00})
	require.False(t, ok)
}

// TestValidateHighMemberIndexTemplateRow pins that a PE member above index 30
// with no explicit fileID is matched to the correct Annex A row: PE-OPT-USIM
// member 33 is EF VBS (row 31), a transparent EF.
func TestValidateHighMemberIndexTemplateRow(t *testing.T) {
	member := fileWithContent(33, []byte{0x00},
		asn1.NewPrimitive(tagFcpPinStatus, []byte{0x01, 0x0a}),
	)
	errs := strings.Join(profileAroundMFPlus(templatePE(TagOptUSIM, member)).ValidateV231().Errors, "\n")
	require.Contains(t, errs, "EF VBS")
	require.Contains(t, errs, "pinStatusTemplateDO is not allowed for an EF")
}

// TestFDKindFileTypeBits pins the ETSI TS 102 221 §11.1.1.4.3 file-descriptor
// decode: the file type is (b>>3)&7, so the ordinary EF descriptors 0x41
// (transparent), 0x42 (linear fixed) and 0x46 (cyclic) are EF-like, while 0x78
// is a DF. The BER-TLV EF code points 0x39/0x79 keep their file-type bits 111
// but are EFs, not DFs.
func TestFDKindFileTypeBits(t *testing.T) {
	for _, b := range []byte{0x41, 0x42, 0x46, 0x39, 0x79, 0x00} {
		require.Equal(t, "ef", fdKind(b), "fdKind(%02X)", b)
	}
	require.Equal(t, "df", fdKind(0x78), "fdKind(78)")
	require.Empty(t, fdKind(0x82), "fdKind(82) has b8 set")
}

// TestValidateTemplateFileTypeEFDescriptor pins the corrected classification in
// the §8.3.3 "file type must not change" check.
func TestValidateTemplateFileTypeEFDescriptor(t *testing.T) {
	// The MF template row is a DF, so a transparent-EF descriptor (0x41) is a
	// mismatch (it was silently unclassified before the mask fix).
	mf := templatePE(TagMF,
		fileWithContent(2, []byte{0x00},
			asn1.NewPrimitive(tagFcpFileID, []byte{0x3f, 0x00}),
			asn1.NewPrimitive(tagFcpFileDescriptor, []byte{0x41, 0x21}),
			asn1.NewPrimitive(tagFcpPinStatus, []byte{0x01, 0x0a}),
		),
	)
	require.Contains(t, strings.Join(profileAroundMF(mf).ValidateV231().Errors, "\n"),
		"fileDescriptor declares a ef but the template defines a df")

	// A BER-TLV EF descriptor (0x79) on an EF row is accepted.
	usim := templatePE(TagUSIM, adfMember(),
		fileWithContent(3, make([]byte, 9),
			asn1.NewPrimitive(tagFcpFileID, []byte{0x6f, 0x07}),
			asn1.NewPrimitive(tagFcpEFSize, []byte{0x09}),
			asn1.NewPrimitive(tagFcpFileDescriptor, []byte{0x79, 0x21}),
		),
	)
	require.Empty(t, profileAroundMFPlus(usim).ValidateV231().Errors)
}

// TestValidatePINCodesSharedFilePath pins that the pinCodes filePath CHOICE
// alternative (a1 { 81 <path> }) is not mistaken for a short pinValue, while a
// short pinValue inside the pinconfig alternative is still rejected.
func TestValidatePINCodesSharedFilePath(t *testing.T) {
	filePath := asn1.NewConstructed(TagPinCodes,
		asn1.NewConstructed(peHeader, asn1.NewPrimitive(peMandated, nil)),
		asn1.NewConstructed([]byte{0xa1}, asn1.NewPrimitive([]byte{0x81}, []byte{0x01, 0x02})),
	)
	errs := strings.Join(profileAroundMFPlus(filePath).ValidateV231().Errors, "\n")
	require.NotContains(t, errs, "pinValue")

	pinconfig := asn1.NewConstructed(TagPinCodes,
		asn1.NewConstructed(peHeader, asn1.NewPrimitive(peMandated, nil)),
		asn1.NewConstructed([]byte{0xa1}, asn1.NewConstructed([]byte{0xa0},
			asn1.NewConstructed([]byte{0x30},
				asn1.NewPrimitive([]byte{0x80}, []byte{0x01}),
				asn1.NewPrimitive([]byte{0x81}, make([]byte, 7)),
			),
		)),
	)
	require.Contains(t, strings.Join(profileAroundMFPlus(pinconfig).ValidateV231().Errors, "\n"),
		"PINConfiguration.pinValue: value is 7 octets, minimum is 8")
}

// TestValidateValueRanges pins the ASN.1 SIZE/INTEGER domain checks (R1).
func TestValidateValueRanges(t *testing.T) {
	// ProfileHeader.iccid must be 10 octets.
	badICCID := headerWithGFSTE()
	badICCID.AppendChild(asn1.NewPrimitive(hdrICCID, make([]byte, 9)))
	require.Contains(t, strings.Join(profileWith(badICCID, asn1.NewConstructed(TagMF)).ValidateV231().Errors, "\n"),
		"ProfileHeader.iccid: value is 9 octets, minimum is 10")

	// ProfileHeader.profileType is SIZE(1..100).
	long := make([]byte, 101)
	for i := range long {
		long[i] = 'x'
	}
	hdr := headerWithGFSTE()
	hdr.AppendChild(asn1.NewPrimitive(hdrProfileType, long))
	require.Contains(t, strings.Join(profileWith(hdr, asn1.NewConstructed(TagMF)).ValidateV231().Errors, "\n"),
		"ProfileHeader.profileType: value is 101 octets, maximum is 100")

	// Fcp.fileID is SIZE(2), even when it is too short to parse.
	mf := templatePE(TagMF,
		fileWithContent(2, []byte{0x00}, asn1.NewPrimitive(tagFcpFileID, []byte{0x3f})),
	)
	require.Contains(t, strings.Join(profileAroundMF(mf).ValidateV231().Errors, "\n"),
		"fileID: value is 1 octets, minimum is 2")

	// PUKConfiguration.pukValue is SIZE(8).
	puk := asn1.NewConstructed(TagPukCodes,
		asn1.NewConstructed(peHeader, asn1.NewPrimitive(peMandated, nil)),
		asn1.NewConstructed([]byte{0xa1},
			asn1.NewConstructed([]byte{0x30}, // PUKConfiguration
				asn1.NewPrimitive([]byte{0x80}, []byte{0x01}),
				asn1.NewPrimitive([]byte{0x81}, make([]byte, 7)),
			),
		),
	)
	require.Contains(t, strings.Join(profileAroundMFPlus(puk).ValidateV231().Errors, "\n"),
		"PUKConfiguration.pukValue: value is 7 octets, minimum is 8")
}
