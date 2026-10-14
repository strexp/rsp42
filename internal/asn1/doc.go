// Package asn1 is rsp42's own BER-TLV layer: an editable node tree (Node) and
// a builder (Builder) plus encoding/decoding helpers for multi-byte tags,
// explicit/implicit tag wrapping, and the precise raw-byte extraction SGP.22
// signature fragments need.
//
// It is not a thin wrapper around github.com/euicc-go/bertlv: this package
// builds its own read model (TLV) and editable tree (Node), and uses bertlv only
// as the low-level primitive behind the opaque Builder type. Tag is a plain byte
// slice, Builder exposes no third-party type, and bertlv is imported by exactly
// one file (construct.go), so replacing the library is a change confined to this
// package. Callers outside this package never need to import bertlv.
package asn1
