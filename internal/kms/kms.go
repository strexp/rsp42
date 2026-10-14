package kms

import "crypto"

// Provider loads signing keys and protects sensitive values at rest.
type Provider interface {
	// LoadSigner parses a PEM-encoded private key (ECDSA/P-256).
	LoadSigner(path string) (crypto.Signer, error)
	// Encrypt seals plaintext with the key-encryption key.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt opens ciphertext produced by Encrypt.
	Decrypt(ciphertext []byte) ([]byte, error)
}
