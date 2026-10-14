// Package crypto implements the cryptographic primitives used by SGP.22:
// ECDSA raw-signature handling, the X9.63 KDF and the SCP03t (BSP) protection
// protocol.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"rsp42/internal/asn1"
)

// ErrBadSignature is returned when a raw signature cannot be parsed.
var ErrBadSignature = errors.New("crypto: invalid raw signature")

// fieldBytes returns the byte length of a coordinate for the curve.
func fieldBytes(c elliptic.Curve) int {
	return (c.Params().BitSize + 7) / 8
}

// SignRaw hashes data with SHA-256, signs it and returns the raw r||s form
// (each coordinate padded to the curve's field size), as used on the SGP.22
// wire.
func SignRaw(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}
	n := fieldBytes(priv.Curve)
	out := make([]byte, 2*n)
	r.FillBytes(out[:n])
	s.FillBytes(out[n:])
	return out, nil
}

// VerifyRaw verifies a raw r||s signature over data using SHA-256.
func VerifyRaw(pub *ecdsa.PublicKey, data, sig []byte) bool {
	n := fieldBytes(pub.Curve)
	if len(sig) != 2*n {
		return false
	}
	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])
	h := sha256.Sum256(data)
	return ecdsa.Verify(pub, h[:], r, s)
}

// ECPointUncompressed returns the uncompressed encoding (0x04 || X || Y) of a
// public key, matching the SGP.22 EC point representation.
func ECPointUncompressed(pub *ecdsa.PublicKey) ([]byte, error) {
	return pub.Bytes()
}

// ParseECPoint parses an uncompressed EC point (0x04 || X || Y).
func ParseECPoint(curve elliptic.Curve, b []byte) (*ecdsa.PublicKey, error) {
	if len(b) == 0 || b[0] != 0x04 {
		return nil, fmt.Errorf("crypto: EC point must be uncompressed, got %d bytes", len(b))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, b)
	if err != nil {
		return nil, fmt.Errorf("crypto: cannot unmarshal EC point: %w", err)
	}
	return pub, nil
}

// DerToRaw converts a DER-encoded ECDSA signature to raw r||s.
func DerToRaw(curve elliptic.Curve, der []byte) ([]byte, error) {
	t, _, err := asn1.ReadTLV(der)
	if err != nil {
		return nil, err
	}
	if len(t.Tag) != 1 || t.Tag[0] != 0x30 {
		return nil, fmt.Errorf("%w: expected SEQUENCE", ErrBadSignature)
	}
	kids, err := t.Children()
	if err != nil || len(kids) != 2 {
		return nil, fmt.Errorf("%w: expected two INTEGERs", ErrBadSignature)
	}
	r := new(big.Int).SetBytes(kids[0].Value)
	s := new(big.Int).SetBytes(kids[1].Value)
	if r.Sign() < 0 || s.Sign() < 0 {
		return nil, fmt.Errorf("%w: negative coefficients", ErrBadSignature)
	}
	n := fieldBytes(curve)
	out := make([]byte, 2*n)
	r.FillBytes(out[:n])
	s.FillBytes(out[n:])
	return out, nil
}

// RawToDer converts a raw r||s ECDSA signature to DER.
func RawToDer(curve elliptic.Curve, raw []byte) ([]byte, error) {
	n := fieldBytes(curve)
	if len(raw) != 2*n {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrBadSignature, 2*n, len(raw))
	}
	r := new(big.Int).SetBytes(raw[:n])
	s := new(big.Int).SetBytes(raw[n:])
	rt := asn1.Prim(asn1.TagInteger, trimInt(r))
	st := asn1.Prim(asn1.TagInteger, trimInt(s))
	return asn1.Marshal(asn1.New(asn1.TagSequence, rt, st)), nil
}

func trimInt(v *big.Int) []byte {
	if v.Sign() == 0 {
		return []byte{0}
	}
	b := v.Bytes()
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}
