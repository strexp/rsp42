package rsp

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is an eUICC Profile Package (SAIP) version. Every comparison uses the
// (major, minor) pair only: the revision component of a document version such
// as V2.3.1 is not encoded in the package, which carries V2.3 verbatim
// (docs/esim42-integration-gaps.md §0.3 N16).
type Version struct {
	Major int
	Minor int
}

// ParseVersion parses a "<major>.<minor>" configuration string. A trailing
// "<major>.<minor>.<revision>" is accepted and the revision is ignored.
func ParseVersion(s string) (Version, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 || len(parts) > 3 {
		return Version{}, fmt.Errorf("invalid SAIP version %q (want <major>.<minor>)", s)
	}
	major, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || major < 0 {
		return Version{}, fmt.Errorf("invalid SAIP version %q (want <major>.<minor>)", s)
	}
	minor, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || minor < 0 {
		return Version{}, fmt.Errorf("invalid SAIP version %q (want <major>.<minor>)", s)
	}
	return Version{Major: major, Minor: minor}, nil
}

// String renders the canonical "<major>.<minor>" form.
func (v Version) String() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// Compare returns -1, 0 or +1 comparing v to o by (major, minor).
func (v Version) Compare(o Version) int {
	switch {
	case v.Major != o.Major:
		if v.Major < o.Major {
			return -1
		}
		return 1
	case v.Minor != o.Minor:
		if v.Minor < o.Minor {
			return -1
		}
		return 1
	default:
		return 0
	}
}

// VersionFromBytes decodes a SAIP VersionType (SGP.22 §5.7.6: major, minor and
// revision on bytes 1..3). The revision is ignored.
func VersionFromBytes(b []byte) (Version, bool) {
	if len(b) < 2 {
		return Version{}, false
	}
	return Version{Major: int(b[0]), Minor: int(b[1])}, true
}
