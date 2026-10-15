package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
)

type bppVector struct {
	BPPB64         string `json:"bpp_b64"`
	SEnc           string `json:"senc"`
	SMac           string `json:"smac"`
	MCV            string `json:"mcv"`
	PPKSEnc        string `json:"ppk_senc"`
	PPKSMac        string `json:"ppk_smac"`
	PPKMCV         string `json:"ppk_mcv"`
	PlainCfgISDP   string `json:"plain_cfg_isdp"`
	PlainSMD       string `json:"plain_smd"`
	OriginalUPPB64 string `json:"original_upp_b64"`
}

// TestDecodeRealBPP decrypts a BoundProfilePackage captured from a third-party
// SM-DP+, exercising DemacAndDecrypt/DemacOnly.
func TestDecodeRealBPP(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "bpp_decode.json"))
	require.NoError(t, err)
	var v bppVector
	require.NoError(t, json.Unmarshal(raw, &v))

	bpp, err := base64.StdEncoding.DecodeString(v.BPPB64)
	require.NoError(t, err)

	outer, _, err := asn1.ReadTLV(bpp)
	require.NoError(t, err)
	require.Equal(t, "bf36", hex.EncodeToString(outer.Tag))

	kids, err := outer.Children()
	require.NoError(t, err)
	var a0, a1, a3 asn1.TLV
	for _, k := range kids {
		switch hex.EncodeToString(k.Tag) {
		case "a0":
			a0 = k
		case "a1":
			a1 = k
		case "a3":
			a3 = k
		}
	}
	require.NotEmpty(t, a0.Raw)
	require.NotEmpty(t, a1.Raw)
	require.NotEmpty(t, a3.Raw)

	bi, err := NewBSPInstanceRaw(hb(v.SEnc), hb(v.SMac), hb(v.MCV))
	require.NoError(t, err)

	plainCfg, err := bi.DemacAndDecrypt(childSegments(t, a0, 0x87))
	require.NoError(t, err)
	require.Equal(t, hb(v.PlainCfgISDP), plainCfg)

	plainSMD, err := bi.DemacOnly(childSegments(t, a1, 0x88))
	require.NoError(t, err)
	require.Equal(t, hb(v.PlainSMD), plainSMD)

	ppk, err := NewBSPInstanceRaw(hb(v.PPKSEnc), hb(v.PPKSMac), hb(v.PPKMCV))
	require.NoError(t, err)
	plainUPP, err := ppk.DemacAndDecrypt(childSegments(t, a3, 0x86))
	require.NoError(t, err)
	wantUPP, err := base64.StdEncoding.DecodeString(v.OriginalUPPB64)
	require.NoError(t, err)
	require.Equal(t, wantUPP, plainUPP)
}

func childSegments(t *testing.T, parent asn1.TLV, tag byte) [][]byte {
	t.Helper()
	kids, err := parent.Children()
	require.NoError(t, err)
	var segs [][]byte
	for _, k := range kids {
		require.Len(t, k.Tag, 1)
		require.Equal(t, tag, k.Tag[0])
		// The group member *is* the SCP03t data block TLV (SGP.22 Annex H:
		// "SEQUENCE OF [7] OCTET STRING -- sequence of '87' TLVs"), so its raw
		// form is what the BSP layer verifies. Wrapping the segment in a second
		// OCTET STRING (and reading k.Value here) produces a package a real
		// eUICC rejects (docs/real-card-test-report.md, R5); the vector has
		// been normalised to the wire form.
		segs = append(segs, k.Raw)
	}
	require.NotEmpty(t, segs)
	return segs
}

func hb(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
