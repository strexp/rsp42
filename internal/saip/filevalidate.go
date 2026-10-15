package saip

import (
	"bytes"
	"fmt"
	"strings"

	"rsp42/internal/asn1"
)

// Fcp member tags (SAIP V2.3.1 Fcp, AUTOMATIC TAGS; PRIVATE for the last two).
var (
	tagFcpFileDescriptor = []byte{0x82} // [2] fileDescriptor OCTET STRING (SIZE(2..4))
	tagFcpDfName         = []byte{0x84} // [4] dfName ApplicationIdentifier
	tagFcpEFSize         = []byte{0x80} // [0] efFileSize OCTET STRING
	tagFcpPinStatus      = []byte{0xc6} // [PRIVATE 6] pinStatusTemplateDO
	tagFcpShortEFID      = []byte{0x88} // [8] shortEFID OCTET STRING (SIZE(0..1))
	tagFcpPropEFInfo     = []byte{0xa5} // [5] proprietaryEFInfo ProprietaryInfo
	tagFcpLinkPath       = []byte{0xc7} // [PRIVATE 7] linkPath OCTET STRING
)

// validateTemplateFiles applies the SAIP V2.3.1 Annex A per-file defaults (R1)
// and the FCP parameter rules of §8.3.3 to every file-system-template PE:
//
//   - a file whose template cell is "X" (no default) must provide the value it
//     needs (efFileSize or content);
//   - the DF/EF-specific FCP parameters may not be used on the wrong kind of
//     file (efFileSize/shortEFID on a DF, pinStatusTemplateDO on an EF, ...);
//   - the declared file type may not differ from the template's (§8.3.3);
//   - efFileSize and shortEFID are inside their value domains, and shortEFID
//     and fileID are unique within their file-system scope.
//
// A file whose template cell is "Content Required" or whose fileID differs from
// the template default is only a warning: §9.1 allows both, so neither may
// block registration. A genuinely additional file is also a warning, because
// §8.3.4.3 requires such files to be created with PE-GenericFileManagement.
func (s *Sequence) validateTemplateFiles(v *Validation) {
	errf := func(format string, args ...any) { v.Errors = append(v.Errors, fmt.Sprintf(format, args...)) }
	warnf := func(format string, args ...any) {
		v.Warnings = append(v.Warnings, fmt.Sprintf(format, args...))
	}

	for _, pe := range s.Elements {
		name := PEName(pe.Tag)
		files := TemplateFiles(name)
		if len(files) == 0 {
			continue // not a file-system-template PE
		}
		validatePETemplateFiles(v, pe, name, files, errf, warnf)
	}
}

// isDFType classifies the Annex A "File Type" column into DF-like (MF, DF, ADF)
// and EF-like (TR, LF, CY, BT).
func isDFType(t string) bool {
	switch t {
	case "MF", "DF", "ADF":
		return true
	}
	return false
}

func validatePETemplateFiles(
	v *Validation,
	pe *asn1.Node,
	name string,
	files []TemplateFile,
	errf, warnf func(string, ...any),
) {
	// seenFID/seenSFI are reset when a DF or ADF opens a new file-system scope.
	seenFID := map[uint16]string{}
	seenSFI := map[int]string{}
	for _, entry := range pe.Children {
		if bytes.Equal(entry.Tag, peHeader) {
			continue
		}
		idx, ok := peMemberIndex(entry.Tag)
		if !ok || idx < 2 {
			continue
		}
		fcp := entry.Find(tagFcp)
		if fcp == nil {
			continue // doNotCreate, or not a File member
		}

		// Resolve the template file. The PE member index maps onto the Annex A
		// row order (the tables follow the PE definitions), which is the only
		// reliable association for an ADF whose temporary fileID is chosen by
		// the Profile Creator and for FIDs that are reused under sibling DFs
		// (e.g. 4F20 is EF.IMG under DF GRAPHICS and EF.MLPL under DF MMSS).
		fid, haveFID := fcpFID(fcp)
		var posRow *TemplateFile
		if idx-2 < len(files) {
			posRow = &files[idx-2]
		}
		var tf TemplateFile
		found := false
		if posRow != nil && (!haveFID || posRow.FID == 0 || posRow.InRange(fid)) {
			tf, found = *posRow, true
		}
		if !found && haveFID {
			if t, ok := FindTemplateFile(name, fid); ok {
				tf, found = t, true
			}
		}
		if !found && posRow != nil {
			// §9.1 allows the Profile Creator to change a fileID without
			// limitation, so this is a warning, not an error.
			warnf("PE-%s %s: fileID %04X differs from the template default %04X",
				strings.ToUpper(name), posRow.Name, fid, posRow.FID)
			tf, found = *posRow, true
		}
		if !found {
			if haveFID {
				warnf("PE-%s file %04X is not part of the V2.3.1 %s template; additional files shall be created with PE-GenericFileManagement",
					strings.ToUpper(name), fid, name)
			}
			continue
		}

		label := fmt.Sprintf("PE-%s %s", strings.ToUpper(name), tf.Name)
		contentPresent := entry.Find(tagFileContent) != nil || entry.Find(tagFileOffset) != nil
		link := fcp.Find(tagFcpLinkPath) != nil
		sizeNode := fcp.Find(tagFcpEFSize)
		sfiNode := fcp.Find(tagFcpShortEFID)

		// --- content / size that the template does not default ---------------
		// "Content Required = Y" means there is no standard default content,
		// not that the package must carry it: §9.1 explicitly allows a partial
		// or absent content, which the eUICC then fills with the create-command
		// default. It is still a useful signal for the operator, so it is a
		// warning rather than an error.
		if tf.ContentRequired && !contentPresent && !link {
			warnf("%s: template cell is \"Content Required\" but no content is provided", label)
		}
		if tf.Size == -1 && !contentPresent && sizeNode == nil && !link {
			errf("%s: the template defines no default file size; efFileSize or content must be provided", label)
		}

		// --- FCP parameters allowed per file kind (§8.3.3) --------------------
		if isDFType(tf.Type) {
			if sizeNode != nil && !link {
				errf("%s: efFileSize is not allowed for a %s file", label, tf.Type)
			}
			if sfiNode != nil {
				errf("%s: shortEFID is not allowed for a %s file", label, tf.Type)
			}
			if tf.requiredParam("pinStatusTemplateDO") && fcp.Find(tagFcpPinStatus) == nil {
				errf("%s: pinStatusTemplateDO is mandatory for a %s file", label, tf.Type)
			}
		} else {
			if fcp.Find(tagFcpPinStatus) != nil {
				errf("%s: pinStatusTemplateDO is not allowed for an EF", label)
			}
			if fcp.Find(tagFcpDfName) != nil {
				errf("%s: dfName is only allowed for an ADF", label)
			}
		}
		if tf.Type == "ADF" && fcp.Find(tagFcpDfName) == nil {
			errf("%s: dfName (AID) is mandatory for an ADF", label)
		}

		// --- file type must not change (§8.3.3) ------------------------------
		if desc := fcp.Find(tagFcpFileDescriptor); desc != nil && len(desc.Value) > 0 {
			if kind := fdKind(desc.Value[0]); kind != "" {
				want := "ef"
				if isDFType(tf.Type) {
					want = "df"
				}
				if kind != want {
					errf("%s: fileDescriptor declares a %s but the template defines a %s (%s)", label, kind, want, tf.Type)
				}
			}
		}

		// --- value domains ----------------------------------------------------
		if sizeNode != nil {
			if msg := checkEFSize(sizeNode); msg != "" {
				errf("%s: %s", label, msg)
			}
		}
		if sfiNode != nil {
			sfi, msg := checkShortEFID(sfiNode)
			if msg != "" {
				errf("%s: %s", label, msg)
			} else if sfi != 0 {
				if prev, dup := seenSFI[sfi]; dup {
					errf("%s: shortEFID %02X is already used by %s in the same file-system scope", label, sfi<<3, prev)
				} else {
					seenSFI[sfi] = label
				}
			}
		}
		if haveFID {
			if prev, dup := seenFID[fid]; dup {
				errf("%s: fileID %04X is already used by %s in the same file-system scope", label, fid, prev)
			} else {
				seenFID[fid] = label
			}
		}

		// An ADF/DF opens the scope the following EFs belong to.
		if isDFType(tf.Type) {
			seenFID = map[uint16]string{}
			seenSFI = map[int]string{}
		}
	}
}

// fcpFID returns the fileID [3] of an Fcp, when present and well formed.
func fcpFID(fcp *asn1.Node) (uint16, bool) {
	id := fcp.Find(tagFcpFileID)
	if id == nil || len(id.Value) != 2 {
		return 0, false
	}
	return uint16(id.Value[0])<<8 | uint16(id.Value[1]), true
}

// peMemberIndex recovers the PE SEQUENCE member index from the AUTOMATIC TAGS
// tag of a member (e.g. the third member of PE-MF is [2] -> 0xA2). The index is
// stable across omitted OPTIONAL members, which is what lets an entry without
// an explicit fileID be matched to its Annex A row.
func peMemberIndex(tag []byte) (int, bool) {
	switch {
	case len(tag) == 1 && tag[0] >= 0xa0 && tag[0] <= 0xbe:
		return int(tag[0] - 0xa0), true
	case len(tag) == 2 && tag[0] == 0xbf && tag[1]&0x80 == 0:
		// Long-form tag number: 0xBF is the high-tag-number marker and the
		// following base-128 byte IS the number (31..127), not 31 plus it.
		return int(tag[1]), true
	}
	return 0, false
}

// fdKind classifies the file-descriptor byte (ETSI TS 102 221 §11.1.1.4.3) as
// "df" or "ef": b8 is 0, b7 is the shareable bit, b6..b4 the file type (7 = DF)
// and b3..b1 the structure. The file type is therefore (b>>3)&7.
func fdKind(b byte) string {
	if b&0x80 != 0 {
		return ""
	}
	// BER-TLV EF (TS 102 221 Table 11.5): the non-shareable code point is 0x39
	// and the shareable one 0x79. Its file-type bits are 111, which would
	// otherwise be read as a DF.
	if b&0xbf == 0x39 {
		return "ef"
	}
	switch (b >> 3) & 0x7 {
	case 7:
		return "df"
	case 0, 1:
		return "ef"
	}
	return ""
}

// checkEFSize validates the efFileSize value domain: it is coded on the minimum
// number of octets (Fcp comment) and, being the total file size, fits in the
// two octets the field is limited to.
func checkEFSize(n *asn1.Node) string {
	b := n.Value
	if len(b) == 0 || len(b) > 2 {
		return fmt.Sprintf("efFileSize must be coded on 1 or 2 octets, got %d", len(b))
	}
	if len(b) == 2 && b[0] == 0x00 {
		return "efFileSize must use the minimum number of octets (no leading 00)"
	}
	if uintFromBytes(b) == 0 {
		return "efFileSize must not be zero"
	}
	return ""
}

// checkShortEFID validates shortEFID: SIZE(0..1) and, when present, the Short
// File Identifier coded in bits b8..b4 with bits b3..b1 set to 000.
func checkShortEFID(n *asn1.Node) (int, string) {
	switch len(n.Value) {
	case 0:
		return 0, "" // "no SFI is supported for this EF"
	case 1:
		b := n.Value[0]
		if b&0x07 != 0 {
			return 0, fmt.Sprintf("shortEFID %02X must have bits b3..b1 set to 000", b)
		}
		if b == 0 || b > 0xf0 {
			return 0, fmt.Sprintf("shortEFID %02X is outside the 1..30 range", b)
		}
		return int(b >> 3), ""
	}
	return 0, fmt.Sprintf("shortEFID must be at most 1 octet, got %d", len(n.Value))
}
