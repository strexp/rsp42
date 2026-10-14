package personalization

import (
	"encoding/hex"
	"fmt"
	"strings"

	"rsp42/internal/asn1"
	"rsp42/internal/saip"
)

// PLMNRecord is one entry of the preferred-PLMN lists (EF.PLMNwAcT /
// EF.HPLMNwAcT). AcT is the raw 16-bit access-technology bitmask from
// TS 31.102 and is written through verbatim.
type PLMNRecord struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
	AcT uint16 `json:"act"`
}

// FilePatch overrides the raw body of one elementary file, addressed by FID.
type FilePatch struct {
	FID uint16 `json:"fid"`
	Hex string `json:"hex"`
}

// Data is one set of personalization values supplied by an operator system.
type Data struct {
	ICCID     string
	IMSI      string
	K         []byte
	OPc       []byte
	Algorithm string // "milenage" | "tuak" | "usim-test-algorithm"
	PIN1      string
	PUK1      string
	ADM1      string
	ADM2      string
	SPN       string
	// Milenage/TUAK tuning (applied to the AKA parameter PE).
	RotationConstants []byte // 5 bytes
	XoringConstants   []byte // 80 bytes
	NumberOfKeccak    *int64
	// PLMN is written to EF.PLMNwAcT and/or EF.HPLMNwAcT (whichever the template
	// carries) when non-empty.
	PLMN []PLMNRecord
	// MSISDN is written to EF.MSISDN when non-empty.
	MSISDN string
	// ACC is written to EF.ACC (2 bytes, big-endian) when non-nil.
	ACC *uint16
	// FilePatches overrides raw EF bodies; a patch naming an absent file is an
	// error (it almost always means an operator typo).
	FilePatches []FilePatch
}

// Source provides personalization data. Implementations must not assume any
// subscriber semantics; they merely hand out values.
type Source interface {
	// Next returns the next available data set, or (nil, nil) when exhausted.
	Next() (*Data, error)
}

// StaticSource returns a fixed list of data sets.
type StaticSource struct {
	Items []*Data
	pos   int
}

// Next implements Source.
func (s *StaticSource) Next() (*Data, error) {
	if s.pos >= len(s.Items) {
		return nil, nil
	}
	d := s.Items[s.pos]
	s.pos++
	return d, nil
}

// Engine applies personalization data to a parsed profile.
type Engine struct {
	Algorithm string // default algorithm when Data.Algorithm is empty
}

// Apply injects the personalization values into the profile and recomputes the
// header's mandatory services.
func (e *Engine) Apply(seq *saip.Sequence, d *Data) error {
	if d.ICCID != "" {
		hdr, err := saip.ParseHeader(seq.Header())
		if err != nil {
			return err
		}
		raw, err := ICCIDHeaderBytes(d.ICCID)
		if err != nil {
			return err
		}
		hdr.SetICCID(raw)
		if f := seq.FindFile(saip.FIDICCID); f != nil {
			ef, err := ICCIDEFBytes(d.ICCID)
			if err != nil {
				return err
			}
			f.SetBody(ef)
		}
	}
	if d.IMSI != "" {
		f := seq.FindFile(saip.FIDIMSI)
		if f == nil {
			return fmt.Errorf("personalization: EF.IMSI not found")
		}
		f.SetBody(EncodeIMSI(d.IMSI))
	}
	if len(d.K) > 0 || len(d.OPc) > 0 || len(d.RotationConstants) > 0 || len(d.XoringConstants) > 0 || d.NumberOfKeccak != nil {
		algo := d.Algorithm
		if algo == "" {
			algo = e.Algorithm
		}
		if err := applyAKA(seq.Find(saip.TagAKAParameter), algo, d.K, d.OPc, d.RotationConstants, d.XoringConstants, d.NumberOfKeccak); err != nil {
			return err
		}
	}
	if d.PIN1 != "" {
		if err := applyPinLike(seq, saip.TagPinCodes, 0x01, d.PIN1, 0x81); err != nil {
			return err
		}
	}
	if d.ADM1 != "" {
		if err := applyPinLike(seq, saip.TagPinCodes, 0x0a, d.ADM1, 0x81); err != nil {
			return err
		}
	}
	if d.ADM2 != "" {
		if err := applyPinLike(seq, saip.TagPinCodes, 0x0b, d.ADM2, 0x81); err != nil {
			return err
		}
	}
	if d.PUK1 != "" {
		if err := applyPinLike(seq, saip.TagPukCodes, 0x01, d.PUK1, 0x81); err != nil {
			return err
		}
	}
	if d.SPN != "" {
		if f := seq.FindFile(saip.FIDSPN); f != nil {
			f.SetBody([]byte(d.SPN))
		}
	}
	if len(d.PLMN) > 0 {
		if err := applyPLMN(seq, d.PLMN); err != nil {
			return err
		}
	}
	if d.MSISDN != "" {
		if err := applyMSISDN(seq, d.MSISDN); err != nil {
			return err
		}
	}
	if d.ACC != nil {
		if f := seq.FindFile(saip.FIDACC); f != nil {
			f.SetBody([]byte{byte(*d.ACC >> 8), byte(*d.ACC)})
		}
	}
	if err := applyFilePatches(seq, d.FilePatches); err != nil {
		return err
	}
	if err := seq.RebuildMandatoryServices(); err != nil {
		return err
	}
	return seq.RebuildMandatoryGFSTEList()
}

// applyPLMN writes the preferred PLMN list into EF.PLMNwAcT and EF.HPLMNwAcT
// (whichever the template provides).
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
func ICCIDHeaderBytes(iccid string) ([]byte, error) {
	padded := iccid
	for len(padded) < 20 {
		padded += "F"
	}
	if len(padded) != 20 {
		return nil, fmt.Errorf("personalization: ICCID %q has %d digits", iccid, len(iccid))
	}
	return hex.DecodeString(padded)
}

// ICCIDEFBytes encodes EF.ICCID (3GPP nibble-swapped BCD).
func ICCIDEFBytes(iccid string) ([]byte, error) {
	digits := []byte(iccid)
	if len(digits)%2 != 0 {
		digits = append(digits, 'F')
	}
	out := make([]byte, len(digits)/2)
	for i := 0; i < len(out); i++ {
		hi, lo := digits[2*i], digits[2*i+1]
		if err := checkHex(hi); err != nil {
			return nil, err
		}
		if err := checkHex(lo); err != nil {
			return nil, err
		}
		out[i] = nibble(hi) | nibble(lo)<<4
	}
	// Pad to 10 bytes.
	for len(out) < 10 {
		out = append(out, 0xff)
	}
	return out, nil
}

// EncodeIMSI encodes an IMSI as EF.IMSI content (3GPP TS 31.102).
func EncodeIMSI(imsi string) []byte {
	oe := byte(len(imsi) & 1)
	digits := imsi
	for len(digits) < 15 {
		digits += "F"
	}
	s := fmt.Sprintf("%01x", (oe<<3)|1) + digits
	b := make([]byte, len(s)/2)
	for i := range b {
		b[i] = nibble(s[2*i])<<4 | nibble(s[2*i+1])
	}
	// swap nibbles
	for i := range b {
		b[i] = b[i]>>4 | b[i]<<4
	}
	return append([]byte{byte((len(imsi) + 1 + 1) / 2)}, b...)
}

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
		if len(entries) == 1 && bytesEq(entries[0].Tag, asn1.Ctx(0, true)) {
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

func setChild(parent *asn1.Node, tag, value []byte) {
	if c := parent.Find(tag); c != nil {
		c.Value = append([]byte(nil), value...)
		return
	}
	parent.AppendChild(asn1.NewPrimitive(tag, value))
}

func nibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func checkHex(c byte) error {
	if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
		return nil
	}
	return fmt.Errorf("personalization: non-hex ICCID digit %q", c)
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
