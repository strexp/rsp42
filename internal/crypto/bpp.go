package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// BSPResult holds the protected BPP segment groups and the key material used.
type BSPResult struct {
	InitialKeys        BSPKeyMaterial
	PPK                BSPKeyMaterial
	SharedSecret       []byte
	FirstSequenceOf87  [][]byte // ConfigureISDP (BF24)
	SequenceOf88       [][]byte // StoreMetadata (BF25)
	SecondSequenceOf87 [][]byte // ReplaceSessionKeys (BF26)
	SequenceOf86       [][]byte // UPP
}

// ECDHSharedSecret computes the P-256 ECDH shared secret (X coordinate) between
// a private key and an uncompressed peer public point.
func ECDHSharedSecret(priv []byte, peerUncompressed []byte) ([]byte, error) {
	curve := ecdh.P256()
	k, err := curve.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("crypto: ecdh private key: %w", err)
	}
	pub, err := curve.NewPublicKey(peerUncompressed)
	if err != nil {
		return nil, fmt.Errorf("crypto: ecdh public key: %w", err)
	}
	return k.ECDH(pub)
}

// GenerateECDHKeyPair returns a fresh P-256 private key and its uncompressed
// public point.
func GenerateECDHKeyPair() (priv, pub []byte, err error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// ECPointFromPrivate returns the uncompressed public point for a P-256 private
// key given as raw bytes.
func ECPointFromPrivate(priv []byte) ([]byte, error) {
	k, err := ecdh.P256().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("crypto: ecdh private key: %w", err)
	}
	return k.PublicKey().Bytes(), nil
}

// RandomKeyMaterial returns random 16-byte SEnc/SMac/MCV material.
func RandomKeyMaterial() (BSPKeyMaterial, error) {
	var m BSPKeyMaterial
	var err error
	if m.SEnc, err = randomBytes(16); err != nil {
		return m, err
	}
	if m.SMac, err = randomBytes(16); err != nil {
		return m, err
	}
	if m.InitialMCV, err = randomBytes(16); err != nil {
		return m, err
	}
	return m, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ProtectBPP applies SCP03t (BSP) protection to the four BPP element groups:
//
//	firstSequenceOf87  <- encrypt+MAC(ConfigureISDP)
//	sequenceOf88       <- MAC only(StoreMetadata)
//	secondSequenceOf87 <- encrypt+MAC(ReplaceSessionKeys)  (optional)
//	sequenceOf86       <- encrypt+MAC(UPP), protected with the PPK keys
//
// When ppk is nil a random PPK is generated. The returned PPK is the material
// the eUICC will adopt for sequenceOf86.
func ProtectBPP(sharedSecret, hostID, eid []byte, configureISDP, storeMetadata, replaceSessionKeys, upp []byte, ppk *BSPKeyMaterial) (*BSPResult, error) {
	if len(configureISDP) == 0 || len(storeMetadata) == 0 || len(upp) == 0 {
		return nil, fmt.Errorf("crypto: configureISDP, storeMetadata and upp are required")
	}
	res := &BSPResult{SharedSecret: append([]byte(nil), sharedSecret...)}

	res.InitialKeys = BSPDerive(sharedSecret, 0x88, 16, hostID, eid, 16)
	initial, err := NewBSPInstance(res.InitialKeys)
	if err != nil {
		return nil, err
	}

	if res.FirstSequenceOf87, err = initial.EncryptAndMAC(0x87, configureISDP); err != nil {
		return nil, err
	}
	if res.SequenceOf88, err = initial.MACOnly(0x88, storeMetadata); err != nil {
		return nil, err
	}
	if len(replaceSessionKeys) > 0 {
		if res.SecondSequenceOf87, err = initial.EncryptAndMAC(0x87, replaceSessionKeys); err != nil {
			return nil, err
		}
	}

	if ppk == nil {
		m, err := RandomKeyMaterial()
		if err != nil {
			return nil, err
		}
		ppk = &m
	}
	res.PPK = *ppk
	ppkInstance, err := NewBSPInstance(res.PPK)
	if err != nil {
		return nil, err
	}
	if res.SequenceOf86, err = ppkInstance.EncryptAndMAC(0x86, upp); err != nil {
		return nil, err
	}
	return res, nil
}

// UnprotectBPP reverses ProtectBPP, returning the plaintext elements. It is the
// inverse half of the BPP protection pair: ProtectBPP generates the package the
// eUICC consumes, and this verifies the generation path (segmenting, padding,
// MAC chaining) round-trips. It is exercised by TestProtectBPPRoundTrip and is
// also useful for interoperability checks against a captured package.
func UnprotectBPP(sharedSecret, hostID, eid []byte, r *BSPResult, ppk *BSPKeyMaterial) (configureISDP, storeMetadata, replaceSessionKeys, upp []byte, err error) {
	initial, err := NewBSPInstance(BSPDerive(sharedSecret, 0x88, 16, hostID, eid, 16))
	if err != nil {
		return
	}
	if configureISDP, err = initial.DemacAndDecrypt(r.FirstSequenceOf87); err != nil {
		return
	}
	if storeMetadata, err = initial.DemacOnly(r.SequenceOf88); err != nil {
		return
	}
	if len(r.SecondSequenceOf87) > 0 {
		if replaceSessionKeys, err = initial.DemacAndDecrypt(r.SecondSequenceOf87); err != nil {
			return
		}
	}
	usePPK := ppk
	if usePPK == nil {
		usePPK = &r.PPK
	}
	ppkInstance, err := NewBSPInstance(*usePPK)
	if err != nil {
		return
	}
	upp, err = ppkInstance.DemacAndDecrypt(r.SequenceOf86)
	return
}
