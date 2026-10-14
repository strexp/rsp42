// Package testutil holds helpers shared by the test suites of several packages.
//
// It must stay dependency-free (no rsp42 imports) so any package can use it, and
// it must never be imported by non-test code: it is not linked into the binary
// as long as only _test.go files reference it.
package testutil

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// MustHex decodes a hex string, failing the test on a malformed literal.
func MustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("testutil: %q is not hex: %v", s, err)
	}
	return b
}

// Concat returns the concatenation of the given byte slices.
func Concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TLV builds a tag + definite-length + content element, matching the BER
// encoding used on the wire. It lets a test assert on individual TLVs without
// pulling the production encoders into the expectation.
func TLV(tag, content []byte) []byte {
	return Concat(tag, EncodeLength(len(content)), content)
}

// HexTag renders a tag as lowercase hex.
func HexTag(tag []byte) string { return hex.EncodeToString(tag) }

// DoJSON performs an HTTP request with an optional JSON body and returns the
// status code and the raw response body.
func DoJSON(t testing.TB, method, url string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("testutil: marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("testutil: new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("testutil: do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testutil: read body: %v", err)
	}
	return resp.StatusCode, raw
}
