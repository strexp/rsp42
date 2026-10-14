package saip

import (
	"bytes"
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

// Body returns the linearized file content. The File CHOICE is a sequence of
// fillFileOffset / fillFileContent elements: fillFileOffset moves the write
// position (UInt16, big-endian, absolute) and fillFileContent writes at that
// position, zero-extending the body when it skips ahead. Ignoring the offsets
// silently corrupted templates that use fragmented file content (C6/N13).
func (f *FileHandle) Body() []byte {
	var out []byte
	pos := 0
	for _, c := range f.Entry.Children {
		switch {
		case bytes.Equal(c.Tag, tagFileOffset):
			pos = uintFromBytes(c.Value)
		case bytes.Equal(c.Tag, tagFileContent):
			if pos > len(out) {
				out = append(out, make([]byte, pos-len(out))...)
			}
			end := pos + len(c.Value)
			if end > len(out) {
				out = append(out, make([]byte, end-len(out))...)
			}
			copy(out[pos:], c.Value)
			pos = end
		}
	}
	return out
}

// uintFromBytes decodes a big-endian unsigned integer of up to 8 bytes.
func uintFromBytes(b []byte) int {
	n := 0
	for _, x := range b {
		n = n<<8 | int(x)
	}
	return n
}

// SetBody replaces the file content with body. Any existing fillFileOffset /
// fillFileContent children are removed and a single fillFileContent is written.
func (f *FileHandle) SetBody(body []byte) {
	kept := f.Entry.Children[:0]
	for _, c := range f.Entry.Children {
		if bytes.Equal(c.Tag, tagFileContent) || bytes.Equal(c.Tag, tagFileOffset) {
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
	// FIDEFAD is EF.AD (Administrative Data, TS 31.102 §4.2.23), whose byte-4
	// low nibble carries the MNC length (N17). Note: 6F3A is EF.LI, not EF.AD.
	FIDEFAD = 0x6FAD
)

// ErrFileNotFound is returned when a required file is absent.
type ErrFileNotFound struct{ FID uint16 }

func (e *ErrFileNotFound) Error() string { return fmt.Sprintf("saip: file %04X not found", e.FID) }
