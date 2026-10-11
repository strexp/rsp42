// Package cert loads and validates SGP.26 (or private CA) certificate chains
// and exposes role-based certificates and keys to the rest of the project.
package cert

import (
	"bytes"
	"crypto/x509"
	stdasn1 "encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"rsp42/internal/asn1"
)

// SGP.22 role/policy OIDs (id-rsp = 2.23.146.1, id-rspRole = 2.23.146.1.2.1).
const (
	OIDRoleCI     = "2.23.146.1.2.1.0"
	OIDRoleEUICC  = "2.23.146.1.2.1.1"
	OIDRoleEUM    = "2.23.146.1.2.1.2"
	OIDRoleDPTLS  = "2.23.146.1.2.1.3"
	OIDRoleDPAuth = "2.23.146.1.2.1.4"
	OIDRoleDPPb   = "2.23.146.1.2.1.5"
	OIDRoleDSTLS  = "2.23.146.1.2.1.6"
	OIDRoleDSAuth = "2.23.146.1.2.1.7"
)

var (
	oidExtensionSAN        = stdasn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionNameConstr = stdasn1.ObjectIdentifier{2, 5, 29, 30}
	oidPermittedEIN        = stdasn1.ObjectIdentifier{2, 23, 146, 1, 2, 2, 0}
)

// ValidationError describes a certificate validation failure.
type ValidationError struct {
	Cert   string
	Reason string
}

func (e *ValidationError) Error() string { return fmt.Sprintf("cert %s: %s", e.Cert, e.Reason) }

// ParsePEMorDER parses a single certificate from PEM or DER bytes.
func ParsePEMorDER(b []byte) (*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(b); err == nil {
		return cert, nil
	}
	if block, _ := pem.Decode(b); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, fmt.Errorf("cert: cannot parse certificate (neither DER nor PEM)")
}

// LoadCertificate reads and parses a certificate file (DER or PEM).
func LoadCertificate(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cert: read %s: %w", path, err)
	}
	cert, err := ParsePEMorDER(b)
	if err != nil {
		return nil, fmt.Errorf("cert: %s: %w", path, err)
	}
	return cert, nil
}

// RoleOID returns the SGP.22 role/policy OID asserted by the certificate, if
// any of the known role OIDs is present.
func RoleOID(cert *x509.Certificate) (string, bool) {
	known := map[string]bool{
		OIDRoleCI: true, OIDRoleEUICC: true, OIDRoleEUM: true, OIDRoleDPTLS: true,
		OIDRoleDPAuth: true, OIDRoleDPPb: true, OIDRoleDSTLS: true, OIDRoleDSAuth: true,
	}
	for _, oid := range cert.PolicyIdentifiers {
		if known[oid.String()] {
			return oid.String(), true
		}
	}
	return "", false
}

// RequireRole verifies that the certificate asserts the expected role OID.
func RequireRole(cert *x509.Certificate, want string) error {
	oid, ok := RoleOID(cert)
	if !ok {
		return &ValidationError{Cert: cert.Subject.String(), Reason: "no SGP.22 role policy OID"}
	}
	if oid != want {
		return &ValidationError{Cert: cert.Subject.String(), Reason: fmt.Sprintf("role %s, want %s", oid, want)}
	}
	return nil
}

// RegisteredIDs returns the registered IDs (RIDs) present in the certificate's
// subjectAltName extension.
func RegisteredIDs(cert *x509.Certificate) ([]string, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidExtensionSAN) {
			continue
		}
		return parseRegisteredIDs(ext.Value)
	}
	return nil, nil
}

// HasRegisteredID reports whether the certificate asserts the given RID.
func HasRegisteredID(cert *x509.Certificate, rid string) (bool, error) {
	rids, err := RegisteredIDs(cert)
	if err != nil {
		return false, err
	}
	for _, r := range rids {
		if r == rid {
			return true, nil
		}
	}
	return false, nil
}

func parseRegisteredIDs(extValue []byte) ([]string, error) {
	seq, _, err := asn1.ReadTLV(extValue)
	if err != nil {
		return nil, fmt.Errorf("cert: parse SAN: %w", err)
	}
	kids, err := seq.Children()
	if err != nil {
		return nil, err
	}
	var rids []string
	for _, k := range kids {
		// registeredID is [8] IMPLICIT OBJECT IDENTIFIER, primitive tag 0x88.
		if len(k.Tag) == 1 && k.Tag[0] == 0x88 {
			oid, err := asn1.DecodeOID(k.Value)
			if err != nil {
				return nil, err
			}
			rids = append(rids, oid)
		}
	}
	return rids, nil
}

// CheckValidity verifies that now is within the certificate validity window.
// When allowExpired is true an expired certificate is reported as a warning
// instead of an error (used only for the SGP.26 test material).
func CheckValidity(cert *x509.Certificate, now time.Time, allowExpired bool) error {
	if now.Before(cert.NotBefore) {
		return &ValidationError{Cert: cert.Subject.String(), Reason: fmt.Sprintf("not yet valid until %s", cert.NotBefore)}
	}
	if now.After(cert.NotAfter) {
		if allowExpired {
			return nil
		}
		return &ValidationError{Cert: cert.Subject.String(), Reason: fmt.Sprintf("expired at %s", cert.NotAfter)}
	}
	return nil
}

// VerifySignatureChain verifies leaf against an ordered issuer chain (from the
// direct issuer up to the self-signed root) using AKI/SKI linkage and the
// signature. It does not check validity; use CheckValidity for that.
func VerifySignatureChain(leaf *x509.Certificate, chain []*x509.Certificate) error {
	cur := leaf
	for _, parent := range chain {
		if len(cur.AuthorityKeyId) > 0 && len(parent.SubjectKeyId) > 0 && !bytes.Equal(cur.AuthorityKeyId, parent.SubjectKeyId) {
			return &ValidationError{Cert: cur.Subject.String(), Reason: "AKI does not match issuer SKI"}
		}
		if err := cur.CheckSignatureFrom(parent); err != nil {
			return &ValidationError{Cert: cur.Subject.String(), Reason: fmt.Sprintf("signature by %s: %v", parent.Subject, err)}
		}
		cur = parent
	}
	if !cur.IsCA {
		return &ValidationError{Cert: cur.Subject.String(), Reason: "chain root is not a CA"}
	}
	return nil
}
