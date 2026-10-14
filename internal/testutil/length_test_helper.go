package testutil

// EncodeLength is the minimal BER definite-length encoding (short form below
// 128 bytes, long form above). It mirrors the production encoder so tests can
// build expectations without importing internal/asn1.
func EncodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var body []byte
	for v := n; v > 0; v >>= 8 {
		body = append([]byte{byte(v)}, body...)
	}
	return append([]byte{0x80 | byte(len(body))}, body...)
}
