package cert

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"strings"

	"rsp42/internal/asn1"
)

// EUMConstraints captures the EUM's permitted subject identifiers extracted
// from the nameConstraints extension and, when present, the newer permittedEIN
// extension (SGP.29).
type EUMConstraints struct {
	OrganizationName string
	IIN              string      // issuer identification number (prefix of the EID)
	PermittedEIN     [][2][]byte // inclusive [min,max] EIN ranges, when present
}

// OrganizationNameOID / SerialNumberOID are the RDN attribute types used by the
// EUM name constraints.
const (
	oidOrganizationName = "2.5.4.10"
	oidSerialNumber     = "2.5.4.5"
)

// ParseEUMConstraints extracts the constraints asserted by an EUM certificate.
func ParseEUMConstraints(cert *x509.Certificate) (*EUMConstraints, error) {
	c := &EUMConstraints{}
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidExtensionNameConstr):
			if err := c.parseNameConstraints(ext.Value); err != nil {
				return nil, err
			}
		case ext.Id.Equal(oidPermittedEIN):
			c.PermittedEIN = parsePermittedEIN(ext.Value)
		}
	}
	return c, nil
}

func (c *EUMConstraints) parseNameConstraints(value []byte) error {
	seq, _, err := asn1.ReadTLV(value)
	if err != nil {
		return fmt.Errorf("cert: parse nameConstraints: %w", err)
	}
	kids, err := seq.Children()
	if err != nil {
		return err
	}
	for _, k := range kids {
		if len(k.Tag) != 1 || k.Tag[0] != 0xa0 { // permittedSubtrees only
			continue
		}
		subtrees, err := k.Children()
		if err != nil {
			return err
		}
		for _, st := range subtrees {
			attrs, err := parseGeneralSubtreeDirName(st)
			if err != nil {
				return err
			}
			if v, ok := attrs[oidOrganizationName]; ok {
				c.OrganizationName = v
			}
			if v, ok := attrs[oidSerialNumber]; ok {
				c.IIN = v
			}
		}
	}
	return nil
}

// parseGeneralSubtreeDirName returns the RDN attributes of a GeneralSubtree's
// directoryName base.
func parseGeneralSubtreeDirName(subtree asn1.TLV) (map[string]string, error) {
	kids, err := subtree.Children()
	if err != nil {
		return nil, err
	}
	for _, k := range kids {
		if len(k.Tag) != 1 || k.Tag[0] != 0xa4 { // directoryName [4]
			continue
		}
		// directoryName is EXPLICIT: the value is an RDNSequence SEQUENCE.
		seq, _, err := asn1.ReadTLV(k.Value)
		if err != nil {
			return nil, err
		}
		return parseRDNSequence(seq)
	}
	return nil, nil
}

// parseRDNSequence flattens an RDNSequence into an OID->value map. Values are
// taken as their raw content bytes (sufficient for organizationName and
// serialNumber, which use PrintableString/UTF8String).
func parseRDNSequence(seq asn1.TLV) (map[string]string, error) {
	out := map[string]string{}
	rdns, err := seq.Children()
	if err != nil {
		return nil, err
	}
	for _, rdn := range rdns {
		atvs, err := rdn.Children() // RDN ::= SET OF AttributeTypeAndValue
		if err != nil {
			return nil, err
		}
		for _, atv := range atvs {
			parts, err := atv.Children()
			if err != nil || len(parts) != 2 {
				continue
			}
			oid, err := asn1.DecodeOID(parts[0].Value)
			if err != nil {
				continue
			}
			out[oid] = string(parts[1].Value)
		}
	}
	return out, nil
}

// parsePermittedEIN is a best-effort parser for the SGP.29 permittedEIN
// extension. It returns the octet-string pairs it can find, and an empty slice
// when the encoding is not recognized.
func parsePermittedEIN(value []byte) [][2][]byte {
	seq, _, err := asn1.ReadTLV(value)
	if err != nil {
		return nil
	}
	kids, err := seq.Children()
	if err != nil {
		return nil
	}
	var out [][2][]byte
	for _, k := range kids {
		fields, err := k.Children()
		if err != nil || len(fields) < 2 {
			continue
		}
		out = append(out, [2][]byte{fields[0].Value, fields[1].Value})
	}
	return out
}

// ValidateEID checks that eid satisfies the EUM constraints. A missing IIN is
// treated as "no restriction" and reported as a warning by the caller.
func (c *EUMConstraints) ValidateEID(eid string) error {
	if c.IIN != "" && !strings.HasPrefix(eid, c.IIN) {
		return fmt.Errorf("cert: EID %s does not start with EUM IIN %s", eid, c.IIN)
	}
	if len(c.PermittedEIN) > 0 {
		b, err := asn1DecodeEID(eid)
		if err != nil {
			return err
		}
		for _, r := range c.PermittedEIN {
			if bytes.Compare(b, r[0]) >= 0 && bytes.Compare(b, r[1]) <= 0 {
				return nil
			}
		}
		return fmt.Errorf("cert: EID %s outside permitted EIN ranges", eid)
	}
	return nil
}

func asn1DecodeEID(eid string) ([]byte, error) {
	if len(eid) != 32 {
		return nil, fmt.Errorf("cert: EID %q is not 32 digits", eid)
	}
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi, lo := eid[2*i], eid[2*i+1]
		if hi < '0' || hi > '9' || lo < '0' || lo > '9' {
			return nil, fmt.Errorf("cert: EID %q contains non-digits", eid)
		}
		b[i] = (hi-'0')<<4 | (lo - '0')
	}
	return b, nil
}
