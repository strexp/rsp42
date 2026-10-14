// Package asn1 is rsp42's own BER-TLV layer: a mutable node tree (Node) plus
// encoding/decoding helpers for multi-byte tags, explicit/implicit tag
// wrapping, and the precise raw-byte extraction SGP.22 signature fragments
// need.
//
// It is not a thin wrapper around github.com/euicc-go/bertlv: this package
// builds its own node model, and only construct.go uses bertlv for the
// low-level tag/TLV primitive. internal/rsp and internal/crypto still import
// bertlv directly for a few builders; collapsing those onto this package is
// tracked in TODO.md §3.1.
package asn1
