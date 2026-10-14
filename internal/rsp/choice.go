package rsp

import "rsp42/internal/asn1"

// SGP.22 response CHOICE helpers.
//
// Several responses (AuthenticateServerResponse, PrepareDownloadResponse,
// CancelSessionResponse) are a CHOICE between an ok alternative [0] and an
// error alternative [1]. The ok alternative is a SEQUENCE OF whose members are
// identified by their tag: a universal SEQUENCE for the signed data object and
// the 5F37 element for the eUICC signature. These helpers keep that tag
// discrimination in one place instead of repeating it in every decoder.

// splitChoice returns the ok ([0]) and error ([1]) alternatives of a response
// CHOICE. Either may be absent; callers must check the booleans.
func splitChoice(t asn1.TLV) (ok asn1.TLV, hasOK bool, errAlt asn1.TLV, hasErr bool) {
	ok, hasOK = t.Find(asn1.Ctx(0, true))
	errAlt, hasErr = t.Find(asn1.Ctx(1, true))
	return ok, hasOK, errAlt, hasErr
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
