package personalization

import (
	"fmt"

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
	// SdKeys replaces the PE-SecurityDomain keyList (N17). The key material is
	// supplied by the operator; rsp42 never generates or derives it
	// (docs/esim42-integration-gaps.md §8.1 decision 4).
	SdKeys []SdKey
	// MncLen sets the MNC length (2 or 3 digits) in EF.AD (FID 6FAD, the low
	// nibble of byte 4 of TS 31.102 §4.2.23). N17.
	MncLen *int
}

// SdKeyComponent is one key-material entry of a PE-SecurityDomain key object
// (SAIP V2.3.1 KeyObject.keyCompontents).
type SdKeyComponent struct {
	// KeyType is the GP key type byte (e.g. 0x80 DES, 0x88 AES), hex encoded.
	KeyType string `json:"keyType"`
	// KeyData is the key material, hex encoded.
	KeyData string `json:"keyData"`
	// MacLength overrides the specification default of 8 bytes.
	MacLength *int `json:"macLength,omitempty"`
}

// SdKey is one GP key object (SAIP V2.3.1 KeyObject) injected into
// PE-SecurityDomain. All byte values are hex encoded.
type SdKey struct {
	KeyUsageQualifier string           `json:"keyUsageQualifier"` // 1-2 bytes, e.g. "38"
	KeyAccess         string           `json:"keyAccess,omitempty"`
	KeyIdentifier     string           `json:"keyIdentifier"`
	KeyVersionNumber  string           `json:"keyVersionNumber"`
	KeyCounterValue   string           `json:"keyCounterValue,omitempty"`
	Components        []SdKeyComponent `json:"components"`
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
	if len(d.SdKeys) > 0 {
		if err := applySdKeys(seq, d.SdKeys); err != nil {
			return err
		}
	}
	if d.MncLen != nil {
		if err := applyMncLen(seq, *d.MncLen); err != nil {
			return err
		}
	}
	if err := seq.RebuildMandatoryServices(); err != nil {
		return err
	}
	return seq.RebuildMandatoryGFSTEList()
}

// KeyObject / PE-SecurityDomain tags. AUTOMATIC TAGS gives each member of
// PE-SecurityDomain a context tag: [0] sd-Header, [1] instance, [2] keyList,
// [3] sdPersoData. The KeyObject members are likewise context tagged.
