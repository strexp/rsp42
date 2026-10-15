// Package mockoperator implements the ES2+ server side
// (handleDownloadProgressInfo, handleAcrRequest) as a mock operator. It backs
// the dev-only `rsp42 admin mock-operator` command and the end-to-end self
// tests.
//
// It deliberately does not live under internal/testutil: that tree is test-only
// and must not be linked into the binary, while this package is reachable from a
// shipped (development-facing) command.
package mockoperator
