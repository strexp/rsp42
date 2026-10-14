package kms

import "crypto"

// SignerLoader loads signing keys. It is the half of the provider a certificate
// manager needs, so an HSM or vault implementation can satisfy it without also
// having to implement at-rest encryption.
type SignerLoader interface {
	// LoadSigner parses a PEM-encoded private key (ECDSA/P-256).
	LoadSigner(path string) (crypto.Signer, error)
}

// Sealer protects sensitive values at rest with the key-encryption key. It is
// the half the session and personalization stores need.
type Sealer interface {
	// Encrypt seals plaintext with the key-encryption key.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt opens ciphertext produced by Encrypt.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// Provider is a full software key provider: it both loads signing keys and
// seals values. Consumers should depend on SignerLoader or Sealer, whichever
// they actually use; Provider is for the places that need both (e.g. the rekey
// tooling, which decrypts with the old key and re-encrypts with the new).
type Provider interface {
	SignerLoader
	Sealer
}
