package personalization

import (
	"bytes"
	"fmt"

	"rsp42/internal/asn1"
	"rsp42/internal/saip"
)

var (
	tagSequence          = []byte{0x30}
	tagAppAID            = []byte{0x4f} // APPLICATION 15, primitive
	tagKeyList           = []byte{0xa2} // PE-SecurityDomain keyList [2]
	tagKeyUsageQualifier = []byte{0x95} // KeyObject keyUsageQualifier [21]
	tagKeyAccess         = []byte{0x96} // KeyObject keyAccess [22]
	tagKeyIdentifier     = []byte{0x82} // KeyObject keyIdentifier [2]
	tagKeyVersionNumber  = []byte{0x83} // KeyObject keyVersionNumber [3]
	tagKeyCounterValue   = []byte{0x85} // KeyObject keyCounterValue [5]
	tagKeyType           = []byte{0x80} // keyCompontents.keyType [0]
	tagKeyData           = []byte{0x86} // keyCompontents.keyData [6]
	tagMacLength         = []byte{0x87} // keyCompontents.macLength [7]
)

// applySdKeys replaces the keyList of PE-SecurityDomain with the supplied key
// set. It errors when the template has no PE-SecurityDomain or a key object is
// malformed.

func applySdKeys(seq *saip.Sequence, keys []SdKey) error {
	pe := seq.Find(saip.TagSecurityDomain)
	if pe == nil {
		return fmt.Errorf("personalization: PE-SecurityDomain not found")
	}
	keyObjects := make([]*asn1.Node, 0, len(keys))
	for i, k := range keys {
		obj, err := buildKeyObject(k)
		if err != nil {
			return fmt.Errorf("personalization: sdKeys[%d]: %w", i, err)
		}
		keyObjects = append(keyObjects, obj)
	}

	// An existing keyList ([2]) is the child whose first entry is a KeyObject
	// (an untagged SEQUENCE). ApplicationInstance ([1]) starts with an
	// APPLICATION 15 AID instead.
	for _, c := range pe.Children {
		if len(c.Children) > 0 && bytes.Equal(c.Children[0].Tag, tagSequence) {
			c.Children = keyObjects
			return nil
		}
	}
	// No keyList yet: insert it right after the ApplicationInstance ([1]).
	list := asn1.NewConstructed(tagKeyList, keyObjects...)
	idx := len(pe.Children)
	for i, c := range pe.Children {
		if len(c.Children) > 0 && bytes.Equal(c.Children[0].Tag, tagAppAID) {
			idx = i + 1
			break
		}
	}
	pe.Children = append(pe.Children, nil)
	copy(pe.Children[idx+1:], pe.Children[idx:])
	pe.Children[idx] = list
	return nil
}

// buildKeyObject encodes one KeyObject.
func buildKeyObject(k SdKey) (*asn1.Node, error) {
	kuq, err := hexBytes(k.KeyUsageQualifier, "keyUsageQualifier")
	if err != nil {
		return nil, err
	}
	if len(kuq) < 1 || len(kuq) > 2 {
		return nil, fmt.Errorf("keyUsageQualifier must be 1-2 bytes")
	}
	kid, err := hexByte(k.KeyIdentifier, "keyIdentifier")
	if err != nil {
		return nil, err
	}
	kvn, err := hexByte(k.KeyVersionNumber, "keyVersionNumber")
	if err != nil {
		return nil, err
	}
	obj := asn1.NewConstructed(tagSequence)
	obj.AppendChild(asn1.NewPrimitive(tagKeyUsageQualifier, kuq))
	if k.KeyAccess != "" {
		ka, err := hexByte(k.KeyAccess, "keyAccess")
		if err != nil {
			return nil, err
		}
		obj.AppendChild(asn1.NewPrimitive(tagKeyAccess, ka))
	}
	obj.AppendChild(asn1.NewPrimitive(tagKeyIdentifier, kid))
	obj.AppendChild(asn1.NewPrimitive(tagKeyVersionNumber, kvn))
	if k.KeyCounterValue != "" {
		kcv, err := hexBytes(k.KeyCounterValue, "keyCounterValue")
		if err != nil {
			return nil, err
		}
		obj.AppendChild(asn1.NewPrimitive(tagKeyCounterValue, kcv))
	}
	if len(k.Components) == 0 {
		return nil, fmt.Errorf("components must have at least one entry")
	}
	comps := asn1.NewConstructed(tagSequence)
	for i, c := range k.Components {
		kt, err := hexBytes(c.KeyType, "keyType")
		if err != nil {
			return nil, err
		}
		kd, err := hexBytes(c.KeyData, "keyData")
		if err != nil {
			return nil, err
		}
		comp := asn1.NewConstructed(tagSequence)
		comp.AppendChild(asn1.NewPrimitive(tagKeyType, kt))
		comp.AppendChild(asn1.NewPrimitive(tagKeyData, kd))
		if c.MacLength != nil {
			if *c.MacLength < 0 || *c.MacLength > 255 {
				return nil, fmt.Errorf("components[%d].macLength out of range [0,255]", i)
			}
			comp.AppendChild(asn1.NewPrimitive(tagMacLength, []byte{byte(*c.MacLength)}))
		}
		comps.AppendChild(comp)
	}
	obj.AppendChild(comps)
	return obj, nil
}

// applyMncLen writes the MNC length into EF.AD (FID 6FAD). Per TS 31.102
// §4.2.23 the value is the low nibble of byte 4 (2 = two-digit MNC, 3 =
// three-digit MNC); the default EF.AD is 00 00 00 02.

func applyMncLen(seq *saip.Sequence, mncLen int) error {
	if mncLen != 2 && mncLen != 3 {
		return fmt.Errorf("personalization: mncLen must be 2 or 3, got %d", mncLen)
	}
	f := seq.FindFile(saip.FIDEFAD)
	if f == nil {
		return fmt.Errorf("personalization: EF.AD (6FAD) not found")
	}
	body := f.Body()
	if len(body) < 4 {
		return fmt.Errorf("personalization: EF.AD is %d bytes, expected at least 4", len(body))
	}
	body[3] = (body[3] & 0xF0) | byte(mncLen)
	f.SetBody(body)
	return nil
}

// hexBytes decodes a hex field.
