// Package hexutil holds the single uppercase-hex rendering helper used across
// the tree.
//
// It is a leaf package: it imports nothing from rsp42, so the API projections,
// the management API, the services and the codecs can all share one spelling
// instead of repeating strings.ToUpper(hex.EncodeToString(...)).
package hexutil

import (
	"encoding/hex"
	"strings"
)

// Upper renders b as an uppercase hex string. An empty or nil b renders as "".
func Upper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
