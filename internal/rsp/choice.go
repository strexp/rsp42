package rsp

import (
	"bytes"

	"rsp42/internal/asn1"
)

// SGP.22 response CHOICE helpers.
//
// Several responses (AuthenticateServerResponse, PrepareDownloadResponse,
// CancelSessionResponse) are a CHOICE between an ok alternative [0] and an
// error alternative [1]. The ok alternative is a SEQUENCE OF whose members are
// identified by their tag: a universal SEQUENCE for the signed data object and
// the 5F37 element for the eUICC signature. These helpers keep that tag
// discrimination in one place instead of repeating it in every decoder.

// choice holds the alternatives of a response CHOICE. Either may be absent.
type choice struct {
	ok, errAlt    asn1.TLV
	hasOK, hasErr bool
}

// splitChoice extracts the ok ([0]) and error ([1]) alternatives of a response
// CHOICE. A malformed outer value is reported as an error instead of being
// silently treated as "no alternative" (asn1.TLV.Find cannot distinguish the
// two; this helper uses Children so it can).
func splitChoice(t asn1.TLV) (choice, error) {
	var c choice
	kids, err := t.Children()
	if err != nil {
		return c, err
	}
	for _, k := range kids {
		switch {
		case !c.hasOK && bytes.Equal(k.Tag, asn1.Ctx(0, true)):
			c.ok, c.hasOK = k, true
		case !c.hasErr && bytes.Equal(k.Tag, asn1.Ctx(1, true)):
			c.errAlt, c.hasErr = k, true
		}
	}
	return c, nil
}

// isSequence reports whether t is a universal SEQUENCE, i.e. a signed data
// object inside an ok alternative.
func isSequence(t asn1.TLV) bool { return len(t.Tag) == 1 && t.Tag[0] == 0x30 }

// isSignature reports whether t is the 5F37 eUICC signature element.
func isSignature(t asn1.TLV) bool {
	return len(t.Tag) == 2 && t.Tag[0] == 0x5f && t.Tag[1] == 0x37
}

// choiceErrorCode reads the error code of a CHOICE error alternative. SGP.22
// encodes it as an INTEGER; some messages wrap it in a context-tagged [1]
// element as well, so both forms are accepted.
func choiceErrorCode(errAlt asn1.TLV) (int64, bool) {
	if v, ok := errAlt.Find(asn1.TagInteger); ok {
		if n, err := v.Int(); err == nil {
			return n, true
		}
	}
	if v, ok := errAlt.Find(asn1.Ctx(1, false)); ok {
		if n, err := v.Int(); err == nil {
			return n, true
		}
	}
	return 0, false
}
