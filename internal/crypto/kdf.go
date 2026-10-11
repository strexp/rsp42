package crypto

import (
	"crypto/sha256"
	"encoding/binary"

	"rsp42/internal/asn1"
)

// X963KDF implements the ANSI X9.63 key derivation function with SHA-256.
func X963KDF(secret []byte, length int, sharedInfo []byte) []byte {
	var out []byte
	var counter [4]byte
	for i := uint32(1); len(out) < length; i++ {
		binary.BigEndian.PutUint32(counter[:], i)
		h := sha256.New()
		h.Write(secret)
		h.Write(counter[:])
		h.Write(sharedInfo)
		out = h.Sum(out)
	}
	return out[:length]
}

// BSPKeyMaterial holds the three key blocks derived for the BSP protocol.
type BSPKeyMaterial struct {
	InitialMCV []byte // initial MAC chaining value
	SEnc       []byte // session encryption key
	SMac       []byte // session MAC key
}

// BSPDerive derives the SCP03t (BSP) session keys per SGP.22 §2.6.4.2.
//
// sharedInfo = keyType(1) || keyLength(1) || LV(hostId) || LV(eid)
// The X9.63-KDF(SHA-256) output of 3L bytes is split into
// initialMCV | sEnc | sMac. L is the key length (16 for AES-128).
func BSPDerive(sharedSecret []byte, keyType, keyLength int, hostID, eid []byte, l int) BSPKeyMaterial {
	sharedInfo := make([]byte, 0, 2+len(hostID)+len(eid)+8)
	sharedInfo = append(sharedInfo, byte(keyType), byte(keyLength))
	sharedInfo = append(sharedInfo, asn1.EncodeLength(len(hostID))...)
	sharedInfo = append(sharedInfo, hostID...)
	sharedInfo = append(sharedInfo, asn1.EncodeLength(len(eid))...)
	sharedInfo = append(sharedInfo, eid...)

	out := X963KDF(sharedSecret, l*3, sharedInfo)
	return BSPKeyMaterial{
		InitialMCV: out[0:l],
		SEnc:       out[l : 2*l],
		SMac:       out[2*l : 3*l],
	}
}
