package personalization

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"rsp42/internal/asn1"
	"rsp42/internal/saip"
)

func applyPLMN(seq *saip.Sequence, list []PLMNRecord) error {
	body := make([]byte, 0, len(list)*5)
	for _, r := range list {
		plmn, err := EncodePLMN(r.MCC, r.MNC)
		if err != nil {
			return err
		}
		body = append(body, plmn...)
		body = append(body, byte(r.AcT>>8), byte(r.AcT))
	}
	applied := false
	for _, fid := range []uint16{saip.FIDHPLMNwAcT, saip.FIDPLMNwAcT, saip.FIDOPLMNwAcT} {
		if f := seq.FindFile(fid); f != nil {
			f.SetBody(body)
			applied = true
		}
	}
	if !applied {
		return fmt.Errorf("personalization: no PLMN list file (EF.PLMNwAcT/EF.HPLMNwAcT) in the template")
	}
	return nil
}

// EncodePLMN encodes an MCC/MNC pair as the 3-byte PLMN of TS 24.008 §10.5.1.13.
func EncodePLMN(mcc, mnc string) ([]byte, error) {
	if len(mcc) != 3 {
		return nil, fmt.Errorf("personalization: MCC %q must be 3 digits", mcc)
	}
	if len(mnc) != 2 && len(mnc) != 3 {
		return nil, fmt.Errorf("personalization: MNC %q must be 2 or 3 digits", mnc)
	}
	for _, s := range []string{mcc, mnc} {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return nil, fmt.Errorf("personalization: non-digit in PLMN %q", s)
			}
		}
	}
	mnc3 := byte(0xF)
	if len(mnc) == 3 {
		mnc3 = mnc[2] - '0'
	}
	return []byte{
		(mcc[1]-'0')<<4 | (mcc[0] - '0'),
		mnc3<<4 | (mcc[2] - '0'),
		(mnc[1]-'0')<<4 | (mnc[0] - '0'),
	}, nil
}

// applyMSISDN writes EF.MSISDN (length-prefixed international BCD number).

func applyMSISDN(seq *saip.Sequence, msisdn string) error {
	f := seq.FindFile(saip.FIDMSISDN)
	if f == nil {
		return fmt.Errorf("personalization: EF.MSISDN not found")
	}
	for i := 0; i < len(msisdn); i++ {
		if msisdn[i] < '0' || msisdn[i] > '9' {
			return fmt.Errorf("personalization: MSISDN %q must be digits only", msisdn)
		}
	}
	digits := msisdn
	if len(digits)%2 != 0 {
		digits += "F"
	}
	body := make([]byte, 1+len(digits)/2)
	body[0] = 0x91 // international
	for i := 0; i < len(digits)/2; i++ {
		body[i+1] = nibble(digits[2*i+1])<<4 | nibble(digits[2*i])
	}
	f.SetBody(append([]byte{byte(len(body))}, body...))
	return nil
}

// applyFilePatches overrides raw EF bodies by FID.

func applyFilePatches(seq *saip.Sequence, patches []FilePatch) error {
	for _, p := range patches {
		f := seq.FindFile(p.FID)
		if f == nil {
			return fmt.Errorf("personalization: file %04X not found for patch", p.FID)
		}
		raw, err := hex.DecodeString(p.Hex)
		if err != nil {
			return fmt.Errorf("personalization: file %04X patch is not hex: %w", p.FID, err)
		}
		f.SetBody(raw)
	}
	return nil
}

// ICCIDHeaderBytes encodes the ProfileHeader.iccid (plain BCD, 10 bytes).

func applyAKA(pe *asn1.Node, algo string, k, opc, rotation, xoring []byte, keccak *int64) error {
	if pe == nil {
		return fmt.Errorf("personalization: AKA parameter PE not found")
	}
	cfg := pe.Find(asn1.Ctx(1, true))
	if cfg == nil {
		return fmt.Errorf("personalization: AKA algoConfiguration not found")
	}
	algoParam := cfg.Find(asn1.Ctx(1, true))
	if algoParam == nil {
		return fmt.Errorf("personalization: AKA algoParameter not found")
	}
	id := int64(1)
	switch strings.ToLower(algo) {
	case "", "milenage":
		id = 1
	case "tuak":
		id = 2
	case "usim-test-algorithm", "test":
		id = 3
	}
	setChild(algoParam, asn1.Ctx(0, false), asn1.IntBytes(id))
	if len(k) > 0 {
		setChild(algoParam, asn1.Ctx(2, false), k)
	}
	if len(opc) > 0 {
		setChild(algoParam, asn1.Ctx(3, false), opc)
	}
	if len(rotation) > 0 {
		setChild(algoParam, asn1.Ctx(4, false), rotation)
	}
	if len(xoring) > 0 {
		setChild(algoParam, asn1.Ctx(5, false), xoring)
	}
	if keccak != nil {
		setChild(algoParam, asn1.Ctx(7, false), asn1.IntBytes(*keccak))
	}
	return nil
}

func applyPinLike(seq *saip.Sequence, peTag []byte, ref byte, value string, valueTag byte) error {
	applied := false
	for _, pe := range seq.FindAll(peTag) {
		// PE-PINCodes: a1 → A0 → SEQUENCE entries (PINConfiguration).
		// PE-PUKCodes: a1 → SEQUENCE entries (PUKConfiguration).
		container := pe.Find(asn1.Ctx(1, true))
		if container == nil {
			continue
		}
		entries := container.Children
		if len(entries) == 1 && bytes.Equal(entries[0].Tag, asn1.Ctx(0, true)) {
			entries = entries[0].Children
		}
		for _, entry := range entries {
			keyRef := entry.Find(asn1.Ctx(0, false))
			if keyRef == nil || len(keyRef.Value) == 0 {
				continue
			}
			if keyRef.Value[len(keyRef.Value)-1] != ref {
				continue
			}
			setChild(entry, []byte{valueTag}, encodePinPuk(value))
			applied = true
		}
	}
	if !applied {
		return fmt.Errorf("personalization: no applicable PIN/PUK/ADM entry (ref 0x%02x) found", ref)
	}
	return nil
}

func encodePinPuk(s string) []byte {
	out := make([]byte, 8)
	for i := range out {
		if i < len(s) {
			out[i] = s[i]
		} else {
			out[i] = 0xff
		}
	}
	return out
}
