package service

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"rsp42/internal/cert"
)

// ecdsaKey asserts that a crypto.Signer is an ECDSA private key.
func ecdsaKey(s crypto.Signer) (*ecdsa.PrivateKey, error) {
	k, ok := s.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("service: key is not ECDSA")
	}
	return k, nil
}

func equalBytes(a, b []byte) bool { return bytes.Equal(a, b) }

func mustHexLower(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// confirmationHash computes hashCc = SHA256(SHA256(CC) || transactionId)
// (SGP.22 §2.2), where ccHash is the stored SHA256(CC).
func confirmationHash(ccHash, transactionID []byte) []byte {
	h := sha256.New()
	h.Write(ccHash)
	h.Write(transactionID)
	return h.Sum(nil)
}

// eidFromCert extracts the EID from the eUICC certificate's subject
// serialNumber attribute.
func eidFromCert(c *x509.Certificate) string {
	for _, n := range c.Subject.Names {
		if n.Type.String() == "2.5.4.5" { // serialNumber
			if s, ok := n.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

// validateEUICCChain verifies CERT.EUICC against CERT.EUM and the selected CI,
// and that the EUM chains to the session's CI key id.
func validateEUICCChain(euicc, eum, ci *x509.Certificate, ciCertID []byte) error {
	if ci == nil {
		return fmt.Errorf("no CI loaded")
	}
	if len(ciCertID) > 0 && !bytes.Equal(eum.AuthorityKeyId, ciCertID) {
		return fmt.Errorf("EUM AKI does not match selected CI key id")
	}
	if err := cert.VerifySignatureChain(euicc, []*x509.Certificate{eum, ci}); err != nil {
		return err
	}
	return nil
}
