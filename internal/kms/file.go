package kms

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// FileProvider is a software KMS backed by a 32-byte key-encryption key (from a
// hex string or a file) and PEM files for signing keys.
type FileProvider struct {
	kek []byte
}

// NewFileProvider loads the key-encryption key from kekFile.
func NewFileProvider(kekFile string) (*FileProvider, error) {
	kek, err := os.ReadFile(kekFile)
	if err != nil {
		return nil, fmt.Errorf("kms: read kek %s: %w", kekFile, err)
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("kms: kek %s must be 32 bytes, got %d", kekFile, len(kek))
	}
	return &FileProvider{kek: append([]byte(nil), kek...)}, nil
}

// NewFileProviderFromHex builds a provider from a 64-character hex KEK.
func NewFileProviderFromHex(s string) (*FileProvider, error) {
	kek, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("kms: kek_hex: %w", err)
	}
	return NewFileProviderFromKEK(kek)
}

// NewFileProviderFromKEK builds a provider from raw key bytes (tests).
func NewFileProviderFromKEK(kek []byte) (*FileProvider, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("kms: kek must be 32 bytes, got %d", len(kek))
	}
	return &FileProvider{kek: append([]byte(nil), kek...)}, nil
}

// LoadSigner parses a PEM EC private key. The SGP.26 test keys include a
// leading "EC PARAMETERS" block, so all PEM blocks are scanned.
func (f *FileProvider) LoadSigner(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kms: read key %s: %w", path, err)
	}
	for rest := b; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		case "PRIVATE KEY":
			if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if signer, ok := key.(crypto.Signer); ok {
					return signer, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("kms: no usable private key found in %s", path)
}

// ECDSAKey loads a PEM key and asserts it is an ECDSA key.
func (f *FileProvider) ECDSAKey(path string) (*ecdsa.PrivateKey, error) {
	s, err := f.LoadSigner(path)
	if err != nil {
		return nil, err
	}
	k, ok := s.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("kms: %s is not an ECDSA key", path)
	}
	return k, nil
}

// Encrypt seals plaintext using AES-256-GCM; the output is nonce||ciphertext.
func (f *FileProvider) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(f.kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt opens a value produced by Encrypt.
func (f *FileProvider) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(f.kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("kms: ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
