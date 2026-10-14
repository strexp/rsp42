package saip

import (
	"fmt"

	"rsp42/internal/asn1"
)

// File entry / Fcp tags.
var (
	tagFileContent = []byte{0x83} // fillFileContent (File CHOICE alternative [3])
	tagFileOffset  = []byte{0x82} // fillFileOffset (alternative [2])
	tagFcp         = []byte{0xa1} // fileDescriptor (alternative [1])
	tagFcpFileID   = []byte{0x83} // Fcp.fileID [3]
)

// FileHandle references a file entry inside a file-bearing PE.
type FileHandle struct {
	PE    *asn1.Node
	Entry *asn1.Node
	Fcp   *asn1.Node
	FID   uint16
}

// Files returns every template-defined file in the profile.
func (s *Sequence) Files() []*FileHandle {
	var out []*FileHandle
	for _, pe := range s.Elements {
		if !isFileBearing(pe.Tag) {
			continue
		}
		for _, entry := range pe.Children {
			fcp := entry.Find(tagFcp)
			if fcp == nil {
				continue
			}
			id := fcp.Find(tagFcpFileID)
			if id == nil || len(id.Value) != 2 {
				continue
			}
			out = append(out, &FileHandle{PE: pe, Entry: entry, Fcp: fcp, FID: uint16(id.Value[0])<<8 | uint16(id.Value[1])})
		}
	}
	return out
}

// FindFile returns the file with the given 16-bit FID, if present.
func (s *Sequence) FindFile(fid uint16) *FileHandle {
	for _, f := range s.Files() {
		if f.FID == fid {
			return f
		}
	}
	return nil
}

// Body returns the linearized file content (concatenation of fillFileContent
// elements, ignoring offsets).
func (f *FileHandle) Body() []byte {
	var out []byte
	for _, c := range f.Entry.Children {
		if bytesEq(c.Tag, tagFileContent) {
			out = append(out, c.Value...)
		}
	}
	return out
}

// SetBody replaces the file content with body. Any existing fillFileOffset /
// fillFileContent children are removed and a single fillFileContent is written.
func (f *FileHandle) SetBody(body []byte) {
	kept := f.Entry.Children[:0]
	for _, c := range f.Entry.Children {
		if bytesEq(c.Tag, tagFileContent) || bytesEq(c.Tag, tagFileOffset) {
			continue
		}
		kept = append(kept, c)
	}
	f.Entry.Children = kept
	f.Entry.AppendChild(asn1.NewPrimitive(tagFileContent, body))
}

// Common file identifiers.
const (
	FIDICCID     = 0x2FE2
	FIDIMSI      = 0x6F07
	FIDSPN       = 0x6F46
	FIDKeys      = 0x6F08
	FIDHPLMNwAcT = 0x6F31
	FIDPLMNwAcT  = 0x6F60
	FIDOPLMNwAcT = 0x6F61
	FIDACC       = 0x6F78
	FIDMSISDN    = 0x6F40
)

// ErrFileNotFound is returned when a required file is absent.
type ErrFileNotFound struct{ FID uint16 }

func (e *ErrFileNotFound) Error() string { return fmt.Sprintf("saip: file %04X not found", e.FID) }
