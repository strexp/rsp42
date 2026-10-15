package saip

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// peHex renders a PE tag the way peByTag keys it.
func peHex(tag []byte) string { return hex.EncodeToString(tag) }

// peTagByName returns the tag of the PE with the given canonical name, or nil.
func peTagByName(name string) []byte {
	for _, d := range peDescriptors {
		if d.name == name {
			return d.tag
		}
	}
	return nil
}

// TestPEDescriptorNames pins the PE tag → canonical name registry that PEName
// derives from peDescriptors: the 25 SAIP V2.3.1 PE_Definitions names plus the
// three named V3.x template PEs (df-snpn, iot, opt-iot). These literals are spec
// data (the PE CHOICE alternative names), not a restatement of the descriptor
// table.
func TestPEDescriptorNames(t *testing.T) {
	expected := map[string]string{
		"a0": "header", "a1": "genericFileManagement", "a2": "pinCodes", "a3": "pukCodes",
		"a4": "akaParameter", "a5": "cdmaParameter", "a6": "securityDomain", "a7": "rfm",
		"a8": "application", "a9": "nonStandard", "aa": "end",
		"b0": "mf", "b1": "cd", "b2": "telecom", "b3": "usim", "b4": "opt-usim",
		"b5": "isim", "b6": "opt-isim", "b7": "phonebook", "b8": "gsm-access",
		"b9": "csim", "ba": "opt-csim", "bb": "eap", "bc": "df-5gs", "bd": "df-saip",
		"be": "df-snpn", "bf20": "iot", "bf21": "opt-iot",
	}
	require.Len(t, expected, 28, "25 V2.3.1 PE_Definitions names plus 3 named V3.x template PEs")

	seenTag := map[string]bool{}
	seenName := map[string]bool{}
	for hexTag, name := range expected {
		tag, err := hex.DecodeString(hexTag)
		require.NoError(t, err)
		require.Equal(t, name, PEName(tag), "PEName(%s)", hexTag)
		require.False(t, seenTag[peHex(tag)], "duplicate tag %s", hexTag)
		require.False(t, seenName[name], "duplicate PE name %q", name)
		seenTag[peHex(tag)] = true
		seenName[name] = true
	}
	require.Len(t, peDescriptors, len(expected)+2,
		"the registry holds the named PEs (25 V2.3.1 + 3 V3.x) plus the two unnamed post-baseline PEs")

	// Post-V2.3.1 PEs the baseline must recognise but PEName never named, and
	// any unknown tag, stay unnamed.
	require.Empty(t, PEName([]byte{0xbf, 0x1f}))
	require.Empty(t, PEName([]byte{0xbf, 0x22}))
	require.Empty(t, PEName([]byte{0x00}))
}

// TestPEDescriptorFileAndTemplateFlags pins the file-bearing and template-PE
// sets against the SAIP PE_Definitions literals and checks the derived
// predicates agree for every descriptor.
func TestPEDescriptorFileAndTemplateFlags(t *testing.T) {
	fileBearing := map[string]bool{
		"a1":   true, // PE-GenericFileManagement
		"b0":   true, // mf
		"b1":   true, // cd
		"b2":   true, // telecom
		"b3":   true, // usim
		"b4":   true, // opt-usim
		"b5":   true, // isim
		"b6":   true, // opt-isim
		"b7":   true, // phonebook
		"b8":   true, // gsm-access
		"b9":   true, // csim
		"ba":   true, // opt-csim
		"bb":   true, // eap
		"bc":   true, // df-5gs
		"bd":   true, // df-saip
		"be":   true, // df-snpn
		"bf20": true, // iot
		"bf21": true, // opt-iot
	}
	templatePE := map[string]bool{
		"b0": true, "b1": true, "b2": true, "b3": true, "b4": true, "b5": true,
		"b6": true, "b7": true, "b8": true, "b9": true, "ba": true, "bb": true,
		"bc": true, "bd": true, "be": true, "bf20": true, "bf21": true,
	}
	require.Len(t, fileBearing, 18, "18 PEs create files")
	require.Len(t, templatePE, 17, "17 PEs carry a templateID (genericFileManagement is excluded)")

	for _, d := range peDescriptors {
		key := peHex(d.tag)
		require.Equal(t, fileBearing[key], d.fileBearing, "fileBearing(%s)", key)
		require.Equal(t, templatePE[key], d.templatePE, "templatePE(%s)", key)
		require.Equal(t, d.fileBearing, isFileBearing(d.tag), "isFileBearing(%s)", key)
		require.Equal(t, d.templatePE, isTemplatePE(d.tag), "isTemplatePE(%s)", key)
	}
	require.False(t, isFileBearing([]byte{0x00}))
	require.False(t, isTemplatePE([]byte{0x00}))
	require.True(t, isFileBearing([]byte{0xa1}) && !isTemplatePE([]byte{0xa1}),
		"genericFileManagement is file-bearing but not a template PE")

	// Every Annex B template PE is a template PE; the three post-V2.3.1
	// templates are template PEs without a V2.3.1 OID.
	for _, tpl := range V231Templates {
		tag := peTagByName(tpl.PE)
		require.NotNil(t, tag, "Annex B PE %q is in the registry", tpl.PE)
		require.True(t, isTemplatePE(tag), "%q is a template PE", tpl.PE)
	}
	for _, name := range []string{"df-snpn", "iot", "opt-iot"} {
		tag := peTagByName(name)
		require.NotNil(t, tag)
		require.True(t, isTemplatePE(tag), "%q is a post-V2.3.1 template PE", name)
	}
}

// TestPEDescriptorValidationAttributes pins the singleton and post-V2.3.1 sets
// that ValidateV231 derives from peDescriptors.
func TestPEDescriptorValidationAttributes(t *testing.T) {
	singletons := map[string]bool{
		"header": true, "mf": true, "end": true, "cd": true, "telecom": true,
		"usim": true, "isim": true, "csim": true,
		"opt-usim": true, "opt-isim": true, "opt-csim": true,
		"df-saip": true, "df-5gs": true,
	}
	nonBaseline := map[string]string{
		"be": "df-snpn", "bf20": "iot", "bf21": "opt-iot",
		"bf1f": "df-5gprose", "bf22": "ssim",
	}
	require.Len(t, singletons, 13)
	require.Len(t, nonBaseline, 5)

	for _, d := range peDescriptors {
		require.Equal(t, singletons[d.name], d.singleton, "singleton(%q)", d.name)
		require.Equal(t, nonBaseline[peHex(d.tag)], d.nonBaseline, "nonBaseline(%s)", peHex(d.tag))
	}
}

// TestServiceNamesValues pins the SAIP V2.3.1 ServicesList names. The service
// bits are a separate enumeration (keyed by bit index, not by PE), so they stay
// out of peDescriptors.
func TestServiceNamesValues(t *testing.T) {
	expected := []string{
		"contactless", "usim", "isim", "csim", "milenage", "tuak128", "cave",
		"gba-usim", "gba-isim", "mbms", "eap", "javacard", "multos",
		"multiple-usim", "multiple-isim", "multiple-csim", "tuak256",
		"usim-test-algorithm", "ber-tlv", "dfLink", "cat-tp", "get-identity",
		"profile-a-x25519", "profile-b-p256",
	}
	require.Len(t, expected, 24, "SAIP V2.3.1 ServicesList has 24 entries")
	for i, name := range expected {
		require.Equal(t, name, serviceNames[i], "serviceNames[%d]", i)
	}
}
