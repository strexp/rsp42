package saip

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
)

// TestV231TemplateTable pins N13's Annex B data: exactly the 14 template OIDs
// assigned by the V2.3.1 specification, plus the specification-version OID.
func TestV231TemplateTable(t *testing.T) {
	require.Equal(t, "2.23.143.1.1.2", SpecificationVersionOID)
	require.Len(t, V231Templates, 14, "V2.3.1 Annex B assigns 14 file-system templates")
	for i, tpl := range V231Templates {
		require.Equal(t, TemplateOIDArc+"."+strconv.Itoa(i+1), tpl.OID, "templates are consecutive from .1")
		require.NotEmpty(t, tpl.PE)
		require.NotEmpty(t, tpl.Name)
		require.True(t, IsTemplateOID(tpl.OID))
	}
	require.False(t, IsTemplateOID("2.23.143.1.2.15"))
	require.True(t, IsTemplateSubarc("2.23.143.1.2.13.2"), "a versioned subarc is under the template arc")
	require.False(t, IsTemplateSubarc("2.23.143.1.2.13"))
	require.False(t, IsTemplateSubarc("2.23.143.1.1.2"))
}

// TestValidateTS48Vectors is the N13 regression gate: every TS.48 test vector
// must remain a valid V2.3.1 profile.
func TestValidateTS48Vectors(t *testing.T) {
	dir := "../../testdata/upp"
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".der") || strings.Contains(name, "UNIQUE") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			require.NoError(t, err)
			seq, err := ParseUPP(raw)
			require.NoError(t, err)
			v := seq.ValidateV231()
			require.Empty(t, v.Errors, "TS.48 vector must satisfy the V2.3.1 constraints")
		})
		checked++
	}
	require.Greater(t, checked, 0)
}

func headerWithGFSTE(oids ...string) *asn1.Node {
	children := []*asn1.Node{
		asn1.NewPrimitive(hdrMajor, []byte{2}),
		asn1.NewPrimitive(hdrMinor, []byte{3}),
	}
	if len(oids) > 0 {
		list := asn1.NewConstructed(hdrGFSTE)
		for _, oid := range oids {
			list.AppendChild(asn1.NewPrimitive(tagOID, asn1.EncodeOID(oid)))
		}
		children = append(children, list)
	}
	return asn1.NewConstructed(TagHeader, children...)
}

// TestValidateStructureErrors covers the structural failures the plan requires
// /upp/validate to report.
func TestValidateStructureErrors(t *testing.T) {
	// Missing end: only two elements.
	seq := &Sequence{Elements: []*asn1.Node{
		headerWithGFSTE("2.23.143.1.2.1"),
		asn1.NewConstructed(TagMF),
	}}
	v := seq.ValidateV231()
	require.NotEmpty(t, v.Errors)
	require.Contains(t, strings.Join(v.Errors, "\n"), "at least header, mf and end")

	// Wrong first element.
	seq = &Sequence{Elements: []*asn1.Node{
		asn1.NewConstructed(TagMF),
		headerWithGFSTE(),
		asn1.NewConstructed(TagEnd),
	}}
	v = seq.ValidateV231()
	require.Contains(t, strings.Join(v.Errors, "\n"), "first profile element")

	// Wrong last element.
	seq = &Sequence{Elements: []*asn1.Node{
		headerWithGFSTE(),
		asn1.NewConstructed(TagMF),
		asn1.NewConstructed(TagUSIM),
	}}
	v = seq.ValidateV231()
	require.Contains(t, strings.Join(v.Errors, "\n"), "last profile element")
}

// TestValidateGFSTEVersionedSubarc pins the rule that a GFSTE entry must be one
// of the 14 V2.3.1 templates; a versioned subarc (from a newer specification)
// is a hard error.
func TestValidateGFSTEVersionedSubarc(t *testing.T) {
	seq := &Sequence{Elements: []*asn1.Node{
		headerWithGFSTE("2.23.143.1.2.13.2"),
		asn1.NewConstructed(TagMF),
		asn1.NewConstructed(TagEnd),
	}}
	v := seq.ValidateV231()
	require.Len(t, v.Errors, 1)
	require.Contains(t, v.Errors[0], "2.23.143.1.2.13.2")
	require.Contains(t, v.Errors[0], "not a V2.3.1 template")

	// The unversioned form is accepted.
	seq.Elements[0] = headerWithGFSTE("2.23.143.1.2.13")
	require.Empty(t, seq.ValidateV231().Errors)
}

// TestValidateNonBaselinePEWarning verifies that a mandated post-V2.3.1 PE is a
// warning, not a hard error (SAIP V3.x is out of scope, but must not be
// silently accepted as baseline either).
func TestValidateNonBaselinePEWarning(t *testing.T) {
	iot := asn1.NewConstructed([]byte{0xbf, 0x20},
		asn1.NewConstructed(peHeader, asn1.NewPrimitive(peMandated, nil)),
	)
	seq := &Sequence{Elements: []*asn1.Node{
		headerWithGFSTE(),
		asn1.NewConstructed(TagMF),
		iot,
		asn1.NewConstructed(TagEnd),
	}}
	v := seq.ValidateV231()
	require.Empty(t, v.Errors)
	require.Len(t, v.Warnings, 1)
	require.Contains(t, v.Warnings[0], "IOT")
}

// TestFileBodyHonoursFillFileOffset pins the C6/N13 fix: fragmented file content
// must be linearized at the fillFileOffset positions.
func TestFileBodyHonoursFillFileOffset(t *testing.T) {
	entry := asn1.NewConstructed(tagFileSequence,
		asn1.NewPrimitive(tagFileContent, []byte("AB")),
		asn1.NewPrimitive(tagFileOffset, []byte{0x00, 0x04}),
		asn1.NewPrimitive(tagFileContent, []byte("CD")),
	)
	f := &FileHandle{Entry: entry}
	require.Equal(t, []byte{'A', 'B', 0x00, 0x00, 'C', 'D'}, f.Body())

	// Overlapping writes overwrite in place; a second offset seeks back.
	entry = asn1.NewConstructed(tagFileSequence,
		asn1.NewPrimitive(tagFileContent, []byte("XYZ")),
		asn1.NewPrimitive(tagFileOffset, []byte{0x00, 0x00}),
		asn1.NewPrimitive(tagFileContent, []byte("Q")),
	)
	f = &FileHandle{Entry: entry}
	require.Equal(t, []byte("QYZ"), f.Body())

	// SetBody linearizes any fragmented encoding.
	f.SetBody([]byte("HELLO"))
	require.Equal(t, []byte("HELLO"), f.Body())
}
