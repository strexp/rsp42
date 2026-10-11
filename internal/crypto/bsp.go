package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/aead/cmac"

	"rsp42/internal/asn1"
)

// MaxSegmentSize is the maximum size of one protected BSP segment, including
// tag, length and MAC (SGP.22 §2.5.3).
const MaxSegmentSize = 1020

// lMac is the truncated AES-CMAC length used on the wire.
const lMac = 8

// BSPInstance protects and unprotects BSP (SCP03t) segments.
type BSPInstance struct {
	SEnc       []byte
	SMac       []byte
	macChain   []byte
	blockNr    uint32
	maxPayload int
}

// NewBSPInstance creates an instance from explicit key material. blockNr starts
// at 1 per SGP.22.
func NewBSPInstance(m BSPKeyMaterial) (*BSPInstance, error) {
	if len(m.SEnc) != 16 || len(m.SMac) != 16 || len(m.InitialMCV) != 16 {
		return nil, fmt.Errorf("bsp: SEnc/SMac/InitialMCV must each be 16 bytes")
	}
	lengthLen := len(asn1.EncodeLength(MaxSegmentSize))
	return &BSPInstance{
		SEnc:       append([]byte(nil), m.SEnc...),
		SMac:       append([]byte(nil), m.SMac...),
		macChain:   append([]byte(nil), m.InitialMCV...),
		blockNr:    1,
		maxPayload: MaxSegmentSize - 1 - lengthLen - lMac,
	}, nil
}

// NewBSPInstanceRaw is a convenience constructor from explicit key bytes.
func NewBSPInstanceRaw(sEnc, sMac, initialMCV []byte) (*BSPInstance, error) {
	return NewBSPInstance(BSPKeyMaterial{SEnc: sEnc, SMac: sMac, InitialMCV: initialMCV})
}

// MaxPayloadSize returns the largest plaintext a single segment can carry.
func (b *BSPInstance) MaxPayloadSize() int { return b.maxPayload }

// EncryptAndMAC returns the list of protected segments for tag, encrypting and
// MACing each (SGP.22 §2.6.4.4).
func (b *BSPInstance) EncryptAndMAC(tag byte, plaintext []byte) ([][]byte, error) {
	return b.segments(tag, plaintext, true)
}

// MACOnly returns the list of protected segments for tag, MACing each without
// encryption (SGP.22 §2.6.4.4).
func (b *BSPInstance) MACOnly(tag byte, plaintext []byte) ([][]byte, error) {
	return b.segments(tag, plaintext, false)
}

func (b *BSPInstance) segments(tag byte, plaintext []byte, encrypt bool) ([][]byte, error) {
	var out [][]byte
	for len(plaintext) > 0 {
		n := len(plaintext)
		if n > b.maxPayload {
			n = b.maxPayload
		}
		seg := plaintext[:n]
		plaintext = plaintext[n:]
		var enc []byte
		var err error
		if encrypt {
			enc, err = b.EncryptAndMACOne(tag, seg)
		} else {
			enc, err = b.MACOnlyOne(tag, seg)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, enc)
	}
	return out, nil
}

// EncryptAndMACOne protects a single segment, encrypting then MACing.
func (b *BSPInstance) EncryptAndMACOne(tag byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) > b.maxPayload {
		return nil, fmt.Errorf("bsp: segment of %d bytes exceeds max payload %d", len(plaintext), b.maxPayload)
	}
	ciphered, err := b.encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return b.auth(tag, ciphered)
}

// MACOnlyOne protects a single segment with a MAC but no encryption.
func (b *BSPInstance) MACOnlyOne(tag byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) > b.maxPayload {
		return nil, fmt.Errorf("bsp: segment of %d bytes exceeds max payload %d", len(plaintext), b.maxPayload)
	}
	out, err := b.auth(tag, plaintext)
	if err != nil {
		return nil, err
	}
	// The ICV counter advances for MAC-only segments as well.
	b.blockNr++
	return out, nil
}

// DemacAndDecrypt verifies and decrypts a list of encrypted segments.
func (b *BSPInstance) DemacAndDecrypt(segments [][]byte) ([]byte, error) {
	var out []byte
	for _, seg := range segments {
		p, err := b.DemacAndDecryptOne(seg)
		if err != nil {
			return nil, err
		}
		out = append(out, p...)
	}
	return out, nil
}

// DemacOnly verifies a list of MAC-only segments.
func (b *BSPInstance) DemacOnly(segments [][]byte) ([]byte, error) {
	var out []byte
	for _, seg := range segments {
		p, err := b.DemacOnlyOne(seg)
		if err != nil {
			return nil, err
		}
		out = append(out, p...)
	}
	return out, nil
}

// DemacAndDecryptOne verifies the MAC of a segment and decrypts its payload.
func (b *BSPInstance) DemacAndDecryptOne(segment []byte) ([]byte, error) {
	payload, err := b.verify(segment)
	if err != nil {
		return nil, err
	}
	value, err := segmentValue(payload)
	if err != nil {
		return nil, err
	}
	return b.decrypt(value)
}

// DemacOnlyOne verifies the MAC of a segment and returns its payload.
func (b *BSPInstance) DemacOnlyOne(segment []byte) ([]byte, error) {
	payload, err := b.verify(segment)
	if err != nil {
		return nil, err
	}
	value, err := segmentValue(payload)
	if err != nil {
		return nil, err
	}
	b.blockNr++
	return value, nil
}

// segmentValue extracts the value from a MAC-stripped BSP segment. The declared
// length still counts the removed MAC, so the remaining bytes are returned
// directly rather than trusting the length field.
func segmentValue(payload []byte) ([]byte, error) {
	_, headerLen, err := asn1.ReadHeader(payload)
	if err != nil {
		return nil, err
	}
	if headerLen > len(payload) {
		return nil, fmt.Errorf("bsp: truncated segment header")
	}
	return payload[headerLen:], nil
}

// auth computes the MAC over tag||length||data and returns the protected
// segment tag||length||data||mac.
func (b *BSPInstance) auth(tag byte, data []byte) ([]byte, error) {
	lcc := len(data) + lMac
	tagAndLength := append([]byte{tag}, asn1.EncodeLength(lcc)...)
	temp := make([]byte, 0, len(b.macChain)+len(tagAndLength)+len(data))
	temp = append(temp, b.macChain...)
	temp = append(temp, tagAndLength...)
	temp = append(temp, data...)
	cMac, err := b.cmac(temp)
	if err != nil {
		return nil, err
	}
	b.macChain = cMac
	out := make([]byte, 0, len(tagAndLength)+len(data)+lMac)
	out = append(out, tagAndLength...)
	out = append(out, data...)
	out = append(out, cMac[:lMac]...)
	return out, nil
}

// verify checks the trailing MAC and returns the protected segment with the MAC
// stripped (tag||length||data).
func (b *BSPInstance) verify(segment []byte) ([]byte, error) {
	if len(segment) < lMac {
		return nil, errors.New("bsp: segment shorter than MAC")
	}
	stripped := segment[:len(segment)-lMac]
	received := segment[len(segment)-lMac:]
	temp := make([]byte, 0, len(b.macChain)+len(stripped))
	temp = append(temp, b.macChain...)
	temp = append(temp, stripped...)
	cMac, err := b.cmac(temp)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(received, cMac[:lMac]) {
		return nil, fmt.Errorf("bsp: MAC mismatch: received %X computed %X", received, cMac[:lMac])
	}
	b.macChain = cMac
	return stripped, nil
}

func (b *BSPInstance) cmac(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.SMac)
	if err != nil {
		return nil, err
	}
	h, err := cmac.New(block)
	if err != nil {
		return nil, err
	}
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// encrypt performs AES-CBC with the derived ICV and the 0x80 padding scheme.
func (b *BSPInstance) encrypt(data []byte) ([]byte, error) {
	padded := pad(data)
	iv, err := b.icv()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(b.SEnc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

func (b *BSPInstance) decrypt(data []byte) ([]byte, error) {
	iv, err := b.icv()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(b.SEnc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return unpad(out)
}

// icv derives the CBC IV for the current block number and advances the counter.
func (b *BSPInstance) icv() ([]byte, error) {
	data := make([]byte, 16)
	data[12] = byte(b.blockNr >> 24)
	data[13] = byte(b.blockNr >> 16)
	data[14] = byte(b.blockNr >> 8)
	data[15] = byte(b.blockNr)
	block, err := aes.NewCipher(b.SEnc)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	block.Encrypt(iv, data)
	b.blockNr++
	return iv, nil
}

func pad(data []byte) []byte {
	out := make([]byte, 0, len(data)+16)
	out = append(out, data...)
	out = append(out, 0x80)
	for len(out)%16 != 0 {
		out = append(out, 0x00)
	}
	return out
}

func unpad(padded []byte) ([]byte, error) {
	i := len(padded)
	for i > 0 && padded[i-1] == 0x00 {
		i--
	}
	if i == 0 || padded[i-1] != 0x80 {
		return nil, errors.New("bsp: invalid 0x80 padding")
	}
	return padded[:i-1], nil
}
