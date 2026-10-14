package service

import "strings"

func iccidDecimal(b []byte) string {
	var sb strings.Builder
	for _, by := range b {
		sb.WriteByte(hexDigit(by & 0x0f))
		sb.WriteByte(hexDigit(by >> 4))
	}
	return strings.TrimRight(sb.String(), "Ff")
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + (n - 10)
}

// verifyOtherSigned validates the eUICC certificate chain carried in an
// OtherSignedNotification and its euiccNotificationSignature. When no cert
// provider is configured only the signature is checked.
