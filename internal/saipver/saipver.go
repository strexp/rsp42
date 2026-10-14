// Package saipver holds the SAIP (eUICC Profile Package) version value type.
//
// It is a leaf package: the persistence layer, the configuration validator and
// the services all need to compare SAIP versions, and none of them should have
// to import a wire-codec package to do it. The codec package (internal/rsp)
// uses the type as well, through an alias.
package saipver

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

// Parse parses a "<major>.<minor>" configuration string. A trailing
// "<major>.<minor>.<revision>" is accepted and the revision is ignored.
func Parse(s string) (Version, error) {
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

// FromBytes decodes a SAIP VersionType (SGP.22 §5.7.6: major, minor and
// revision on bytes 1..3). The revision is ignored.
func FromBytes(b []byte) (Version, bool) {
	if len(b) < 2 {
		return Version{}, false
	}
	return Version{Major: int(b[0]), Minor: int(b[1])}, true
}

// Max returns the greatest version in the list, or false when it is empty.
func Max(versions []Version) (Version, bool) {
	if len(versions) == 0 {
		return Version{}, false
	}
	max := versions[0]
	for _, v := range versions[1:] {
		if v.Compare(max) > 0 {
			max = v
		}
	}
	return max, true
}

// CompatibleWith reports whether v is covered by an advertised version set:
// there is a set member s with v <= s, i.e. v <= max(set). An empty set is
// never compatible — N12 requires that an unknown version set must not silently
// select a template (docs/esim42-integration-gaps.md §1bis).
func CompatibleWith(v Version, versions []Version) bool {
	max, ok := Max(versions)
	if !ok {
		return false
	}
	return v.Compare(max) <= 0
}

// Strings renders a version list as canonical strings.
func Strings(versions []Version) []string {
	out := make([]string, 0, len(versions))
	for _, v := range versions {
		out = append(out, v.String())
	}
	return out
}
