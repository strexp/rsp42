package rsp

import "rsp42/internal/saipver"

// Version is an eUICC Profile Package (SAIP) version. The type lives in the
// leaf package internal/saipver so that the persistence layer, the configuration
// validator and the services can compare versions without importing this codec
// package; the alias keeps the historical rsp API working for the codec itself.
type Version = saipver.Version

// ParseVersion parses a "<major>.<minor>" string (a trailing document revision
// is accepted and ignored).
func ParseVersion(s string) (Version, error) { return saipver.Parse(s) }

// VersionFromBytes decodes a SAIP VersionType (SGP.22 §5.7.6); the revision is
// ignored.
func VersionFromBytes(b []byte) (Version, bool) { return saipver.FromBytes(b) }
