package service

import "testing"

func TestAddressMatches(t *testing.T) {
	// The configured FQDN is usually a bare host with the port in the listener
	// config, but a deployment may also bake the port into the FQDN.
	cases := []struct {
		name    string
		address string
		fqdn    string
		port    int
		want    bool
	}{
		{"exact host", "testsmdpplus1.example.com", "testsmdpplus1.example.com", 8443, true},
		{"host with the listening port", "testsmdpplus1.example.com:8443", "testsmdpplus1.example.com", 8443, true},
		{"case insensitive", "TestSMDPPlus1.Example.COM:8443", "testsmdpplus1.example.com", 8443, true},
		{"surrounding spaces", " testsmdpplus1.example.com:8443 ", "testsmdpplus1.example.com", 8443, true},
		{"fqdn carries the port", "testsmdpplus1.example.com:8443", "testsmdpplus1.example.com:8443", 0, true},
		{"fqdn port wins over listener", "testsmdpplus1.example.com:8443", "testsmdpplus1.example.com:8443", 9999, true},
		{"wrong port", "testsmdpplus1.example.com:9999", "testsmdpplus1.example.com", 8443, false},
		{"non numeric port", "testsmdpplus1.example.com:abc", "testsmdpplus1.example.com", 8443, false},
		{"out of range port", "testsmdpplus1.example.com:70000", "testsmdpplus1.example.com", 8443, false},
		{"wrong host", "other.example.com:8443", "testsmdpplus1.example.com", 8443, false},
		{"empty address", "", "testsmdpplus1.example.com", 8443, false},
		{"unknown listener port", "testsmdpplus1.example.com:8443", "testsmdpplus1.example.com", 0, false},
		{"ipv6 literal", "[::1]:8443", "[::1]", 8443, true},
		{"ipv6 bare", "::1", "[::1]", 8443, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := addressMatches(tc.address, tc.fqdn, tc.port); got != tc.want {
				t.Fatalf("addressMatches(%q, %q, %d) = %v, want %v",
					tc.address, tc.fqdn, tc.port, got, tc.want)
			}
		})
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"host", "host", 0},
		{"host:1", "host", 1},
		{"host:", "host", -1},
		{"host:abc", "host", -1},
		{"[::1]", "::1", 0},
		{"[::1]:443", "::1", 443},
		{"", "", 0},
	}
	for _, tc := range cases {
		host, port := splitHostPort(tc.in)
		if host != tc.wantHost || port != tc.wantPort {
			t.Fatalf("splitHostPort(%q) = (%q, %d), want (%q, %d)",
				tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}
