package saip

import (
	"bytes"
	"fmt"
	"strings"

	"rsp42/internal/asn1"
)

// ASN.1 value-domain checks (R1) for the SAIP V2.3.1 Profile Package.
//
// The constraints are the SIZE(...) and INTEGER ranges of the V2.3.1 ASN.1
// definitions (refs/Profile interoperability technical specification
// _V2.3.1.asn). They complement the structural checks of ValidateV231: the
// parser accepts any well-formed TLV, while these rules reject values that are
// outside the range the specification assigns to a field.
//
// Only the constraints reachable from the PEs rsp42 models are enforced; a
// field that is absent (and has a DEFAULT) is not an error.

// PE-AKAParameter member tags (AUTOMATIC TAGS).
var (
	akaAlgoConfig    = []byte{0xa1} // algoConfiguration CHOICE
	akaAlgoParameter = []byte{0xa1} // algoConfiguration.algoParameter [1]
	akaRotation      = []byte{0x84} // AlgoParameter.rotationConstants
	akaXoring        = []byte{0x85} // AlgoParameter.xoringConstants
	akaCounterMax    = []byte{0x86} // AlgoParameter.authCounterMax
	akaSqnOptions    = []byte{0x82} // PE-AKAParameter.sqnOptions
	akaSqnDelta      = []byte{0x83} // PE-AKAParameter.sqnDelta
	akaSqnAgeLimit   = []byte{0x84} // PE-AKAParameter.sqnAgeLimit
	akaSqnInit       = []byte{0xa5} // PE-AKAParameter.sqnInit
)

// ProprietaryInfo member tags (PRIVATE class).
var (
	propSpecialInfo   = []byte{0xc0} // specialFileInformation
	propFillPattern   = []byte{0xc1} // fillPattern
	propRepeatPattern = []byte{0xc2} // repeatPattern
)

// validateValueRanges enforces the ASN.1 SIZE / INTEGER value domains of the
// profile header, the FCPs, the PIN/PUK codes, the AKA parameters and the CDMA
// parameters.
func (s *Sequence) validateValueRanges(v *Validation) {
	errf := func(format string, args ...any) { v.Errors = append(v.Errors, fmt.Sprintf(format, args...)) }

	// --- ProfileHeader -----------------------------------------------------
	if hd := s.Header(); hd != nil {
		checkSize(errf, hd.Find(hdrProfileType), 1, 100, "ProfileHeader.profileType")
		checkSize(errf, hd.Find(hdrICCID), 10, 10, "ProfileHeader.iccid")
	}

	// --- Fcp of every file -------------------------------------------------
	// Walk the File members directly rather than via Files(): a malformed
	// fileID must still be reported, and Files() skips entries it cannot parse.
	for _, pe := range s.Elements {
		if !isFileBearing(pe.Tag) {
			continue
		}
		for _, entry := range pe.Children {
			if fcp := entry.Find(tagFcp); fcp != nil {
				checkFcp(errf, PEName(pe.Tag), fcp)
			}
		}
	}

	// --- PE-specific constraints -------------------------------------------
	for _, pe := range s.Elements {
		switch {
		case bytes.Equal(pe.Tag, TagPinCodes):
			checkPINCodes(errf, pe)
		case bytes.Equal(pe.Tag, TagPukCodes):
			checkPUKCodes(errf, pe)
		case bytes.Equal(pe.Tag, TagAKAParameter):
			checkAKAParameter(errf, pe)
		case bytes.Equal(pe.Tag, TagCDMAParameter):
			checkCDMAParameter(errf, pe)
		}
	}
}

// checkFcp enforces the SIZE domains of the Fcp members and of the
// ProprietaryInfo sub-structure.
func checkFcp(errf func(string, ...any), pe string, fcp *asn1.Node) {
	where := "PE-" + strings.ToUpper(pe)
	if id := fcp.Find(tagFcpFileID); id != nil {
		where += fmt.Sprintf(" file %X", id.Value)
	}
	checkSize(errf, fcp.Find(tagFcpFileDescriptor), 2, 4, where+" fileDescriptor")
	checkSize(errf, fcp.Find(tagFcpFileID), 2, 2, where+" fileID")
	checkSize(errf, fcp.Find(tagFcpDfName), 5, 16, where+" dfName")
	checkSize(errf, fcp.Find([]byte{0x8a}), 1, 1, where+" lcsi")
	checkSize(errf, fcp.Find([]byte{0x8b}), 1, 3, where+" securityAttributesReferenced")
	checkSize(errf, fcp.Find(tagFcpShortEFID), 0, 1, where+" shortEFID")
	if prop := fcp.Find(tagFcpPropEFInfo); prop != nil {
		checkSize(errf, prop.Find(propSpecialInfo), 1, 1, where+" specialFileInformation")
		checkSize(errf, prop.Find(propFillPattern), 1, 200, where+" fillPattern")
		checkSize(errf, prop.Find(propRepeatPattern), 1, 200, where+" repeatPattern")
	}
}

// checkPINCodes validates pinValue OCTET STRING (SIZE(8)) inside the
// PE-PINCodes pinconfiguration.
func checkPINCodes(errf func(string, ...any), pe *asn1.Node) {
	container := pe.Find([]byte{0xa1})
	if container == nil {
		return
	}
	// pinCodes is a CHOICE: the pinconfig alternative [0] (0xa0) carries the
	// PINConfiguration list, while filePath [1] is a shared-PIN temporary FID
	// whose OCTET STRING is itself tagged 0x81. Only tags inside pinconfig are
	// pinValue, so descend into it before walking.
	cfg := container.Find([]byte{0xa0})
	if cfg == nil {
		return
	}
	walk(cfg, func(n *asn1.Node) {
		if bytes.Equal(n.Tag, []byte{0x81}) {
			checkSize(errf, n, 8, 8, "PINConfiguration.pinValue")
		}
	})
}

// checkPUKCodes validates pukValue OCTET STRING (SIZE(8)).
func checkPUKCodes(errf func(string, ...any), pe *asn1.Node) {
	codes := pe.Find([]byte{0xa1})
	if codes == nil {
		return
	}
	walk(codes, func(n *asn1.Node) {
		if bytes.Equal(n.Tag, []byte{0x81}) {
			checkSize(errf, n, 8, 8, "PUKConfiguration.pukValue")
		}
	})
}

// checkAKAParameter validates the AlgoParameter and SqnParameter size domains
// of PE-AKAParameter.
func checkAKAParameter(errf func(string, ...any), pe *asn1.Node) {
	if cfg := pe.Find(akaAlgoConfig); cfg != nil {
		if algo := cfg.Find(akaAlgoParameter); algo != nil {
			checkSize(errf, algo.Find(akaRotation), 5, 5, "AlgoParameter.rotationConstants")
			checkSize(errf, algo.Find(akaXoring), 80, 80, "AlgoParameter.xoringConstants")
			checkSize(errf, algo.Find(akaCounterMax), 3, 3, "AlgoParameter.authCounterMax")
		}
	}
	checkSize(errf, pe.Find(akaSqnOptions), 1, 1, "PE-AKAParameter.sqnOptions")
	checkSize(errf, pe.Find(akaSqnDelta), 6, 6, "PE-AKAParameter.sqnDelta")
	checkSize(errf, pe.Find(akaSqnAgeLimit), 6, 6, "PE-AKAParameter.sqnAgeLimit")
	if init := pe.Find(akaSqnInit); init != nil {
		if len(init.Children) != 32 {
			errf("PE-AKAParameter.sqnInit must carry 32 entries, got %d", len(init.Children))
		}
		for i, child := range init.Children {
			if len(child.Value) != 6 {
				errf("PE-AKAParameter.sqnInit[%d] must be 6 octets, got %d", i, len(child.Value))
			}
		}
	}
}

// checkCDMAParameter validates the PE-CDMAParameter size domains.
func checkCDMAParameter(errf func(string, ...any), pe *asn1.Node) {
	for _, c := range []struct {
		tag      []byte
		min, max int
		name     string
	}{
		{[]byte{0x81}, 8, 8, "authenticationKey"},
		{[]byte{0x82}, 16, 16, "ssd"},
		{[]byte{0x83}, 2, 32, "hrpdAccessAuthenticationData"},
		{[]byte{0x84}, 3, 483, "simpleIPAuthenticationData"},
		{[]byte{0x85}, 5, 957, "mobileIPAuthenticationData"},
	} {
		checkSize(errf, pe.Find(c.tag), c.min, c.max, "PE-CDMAParameter."+c.name)
	}
}

// checkSize reports a violation when a present node's primitive value is
// shorter than min or longer than max octets.
func checkSize(errf func(string, ...any), n *asn1.Node, min, max int, label string) {
	if n == nil {
		return
	}
	switch {
	case len(n.Value) < min:
		errf("%s: value is %d octets, minimum is %d", label, len(n.Value), min)
	case len(n.Value) > max:
		errf("%s: value is %d octets, maximum is %d", label, len(n.Value), max)
	}
}

// walk calls fn for n and every descendant, depth first.
func walk(n *asn1.Node, fn func(*asn1.Node)) {
	fn(n)
	for _, c := range n.Children {
		walk(c, fn)
	}
}
