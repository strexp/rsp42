package activationcode

import (
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// Code is a parsed SGP.22 activation code:
//
//	1$<SM-DP+ FQDN>$<MatchingID>[$<OID>[$<CC required, "1">]]
type Code struct {
	FQDN       string
	MatchingID string
	OID        string
	CCRequired bool
}

// Parse parses an activation code string.
func Parse(s string) (*Code, error) {
	parts := strings.Split(s, "$")
	if len(parts) < 3 || len(parts) > 5 {
		return nil, fmt.Errorf("activationcode: expected 3..5 fields, got %d", len(parts))
	}
	if parts[0] != "1" {
		return nil, fmt.Errorf("activationcode: unsupported format %q (want \"1\")", parts[0])
	}
	c := &Code{FQDN: parts[1], MatchingID: parts[2]}
	if len(parts) >= 4 {
		c.OID = parts[3]
	}
	if len(parts) == 5 {
		c.CCRequired = parts[4] == "1"
	}
	if c.FQDN == "" || c.MatchingID == "" {
		return nil, fmt.Errorf("activationcode: FQDN and MatchingID are required")
	}
	return c, nil
}

// String renders the activation code.
func (c *Code) String() string {
	s := "1$" + c.FQDN + "$" + c.MatchingID
	if c.OID != "" || c.CCRequired {
		s += "$" + c.OID
	}
	if c.CCRequired {
		s += "$1"
	}
	return s
}

// QRContent returns the QR payload (an LPA-prefixed activation code).
func (c *Code) QRContent() string { return "LPA:" + c.String() }

// PNG renders the activation code as a PNG QR image.
func (c *Code) PNG() ([]byte, error) {
	return qrcode.Encode(c.QRContent(), qrcode.Medium, 256)
}

// ACR is a parsed Activation Code Retrieval matching id: ACR-<0|1>-<ICCID>.
type ACR struct {
	// Check is 0 for "retrieve the Activation Code" and 1 for "check
	// availability" (SGP.22 §4.9.1 Table 18a).
	Check int
	ICCID string
}

// ParseACR parses an ACR matching id.
func ParseACR(s string) (*ACR, error) {
	if !strings.HasPrefix(s, "ACR-") {
		return nil, fmt.Errorf("activationcode: %q is not an ACR matching id", s)
	}
	rest := s[len("ACR-"):]
	i := strings.IndexByte(rest, '-')
	if i != 1 {
		return nil, fmt.Errorf("activationcode: invalid ACR type in %q", s)
	}
	switch rest[0] {
	case '0', '1':
	default:
		return nil, fmt.Errorf("activationcode: invalid ACR type %q", rest[0])
	}
	iccid := rest[i+1:]
	if iccid == "" {
		return nil, fmt.Errorf("activationcode: missing ICCID in %q", s)
	}
	for _, r := range iccid {
		if r < '0' || r > '9' {
			return nil, fmt.Errorf("activationcode: ICCID %q contains non-digits", iccid)
		}
	}
	return &ACR{Check: int(rest[0] - '0'), ICCID: iccid}, nil
}

// IsACR reports whether s is an ACR matching id. SGP.22 §4.9.1 fixes the shape
// as "ACR" "-" <0|1> "-" <ICCID>, so only those two prefixes trigger the
// Activation Code Retrieval branch. A plain MatchingID that merely starts with
// "ACR-" (e.g. a redownload token generated elsewhere) must not be swallowed by
// it — the ACR branch would then reject a perfectly usable Activation Code.
func IsACR(s string) bool {
	return strings.HasPrefix(s, "ACR-0-") || strings.HasPrefix(s, "ACR-1-")
}
