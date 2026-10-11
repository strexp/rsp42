// Package es15 implements the ES15 cascade client used by an Alternative
// SM-DS to forward event registration/deletion to the Root SM-DS.
//
// ES15 is structurally identical to ES12 and targets the Root SM-DS ES12
// routes; the caller authenticates with CERT.DS.TLS instead of CERT.DP.TLS.
// On the Root side these requests are handled by the ES12 handler, which
// distinguishes the caller role from the mTLS client certificate.
package es15
