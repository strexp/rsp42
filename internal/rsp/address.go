package rsp

import (
	"net"
	"strconv"
	"strings"
)

// AddressMatches reports whether the RSP Server address an LPA carried in its
// request identifies the server at fqdn (listening on port).
//
// It lives with the codecs because the address syntax is the protocol's:
// SGP.22 §4.1 writes the SM-DP+/SM-DS address of an Activation Code as
// "FQDN [:Port]", and LPAs do send it with the port (lpac passes its `-s` value
// through verbatim), so the port must not make an otherwise correct address
// fail. The host comparison is case-insensitive; the port is optional in the
// request and, when present, has to be the one this server listens on — or the
// one baked into the configured FQDN, which wins when set.
func AddressMatches(address, fqdn string, port int) bool {
	wantHost, wantPort := splitHostPort(fqdn)
	if wantPort == 0 {
		wantPort = port
	}
	gotHost, gotPort := splitHostPort(address)
	if gotHost == "" || !strings.EqualFold(gotHost, wantHost) {
		return false
	}
	if gotPort == 0 {
		return true
	}
	// gotPort is -1 for a present but unparseable port, which never matches.
	return wantPort != 0 && gotPort == wantPort
}

// splitHostPort splits an "FQDN[:port]" value. A missing port is 0; a port that
// is present but not a valid number is -1, so it can never compare equal to a
// real listening port.
func splitHostPort(s string) (host string, port int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return strings.Trim(strings.TrimSpace(s), "[]"), 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(p))
	if err != nil || n < 0 || n > 65535 {
		return h, -1
	}
	return h, n
}
