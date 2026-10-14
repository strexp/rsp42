package saipver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAndString(t *testing.T) {
	v, err := Parse("2.3.1")
	require.NoError(t, err)
	require.Equal(t, Version{Major: 2, Minor: 3}, v, "a document revision is ignored")
	require.Equal(t, "2.3", v.String())

	v, err = Parse(" 2.3 ")
	require.NoError(t, err)
	require.Equal(t, "2.3", v.String())

	for _, bad := range []string{"", "2", "x.1", "2.y", "2.3.1.4", "2.-1"} {
		_, err := Parse(bad)
		require.Error(t, err, "input %q", bad)
	}
}

func TestCompare(t *testing.T) {
	require.Equal(t, -1, Version{2, 1}.Compare(Version{2, 3}))
	require.Equal(t, 1, Version{3, 0}.Compare(Version{2, 9}))
	require.Equal(t, 1, Version{2, 4}.Compare(Version{2, 3}))
	require.Equal(t, 0, Version{2, 3}.Compare(Version{2, 3}))
}

func TestFromBytes(t *testing.T) {
	v, ok := FromBytes([]byte{2, 3, 1})
	require.True(t, ok)
	require.Equal(t, Version{2, 3}, v, "revision byte ignored")

	_, ok = FromBytes([]byte{2})
	require.False(t, ok)
	_, ok = FromBytes(nil)
	require.False(t, ok)
}

func TestMax(t *testing.T) {
	_, ok := Max(nil)
	require.False(t, ok)

	m, ok := Max([]Version{{2, 1}, {2, 3}, {3, 2}})
	require.True(t, ok)
	require.Equal(t, Version{3, 2}, m)

	m, ok = Max([]Version{{2, 3}})
	require.True(t, ok)
	require.Equal(t, Version{2, 3}, m)
}

// TestCompatibleWith pins the compatibility rule the services rely on: a
// template version is usable when it does not exceed the greatest advertised
// version. An unknown (empty) version set is never compatible, so no template is
// selected silently (N12, docs/esim42-integration-gaps.md §1bis).
func TestCompatibleWith(t *testing.T) {
	advertised := []Version{{2, 1}, {2, 3}}

	require.True(t, CompatibleWith(Version{2, 1}, advertised))
	require.True(t, CompatibleWith(Version{2, 3}, advertised))
	require.True(t, CompatibleWith(Version{1, 0}, advertised), "a lower version is compatible")
	require.False(t, CompatibleWith(Version{3, 0}, advertised))

	require.False(t, CompatibleWith(Version{2, 1}, nil))
	require.False(t, CompatibleWith(Version{2, 1}, []Version{}))
}

func TestStrings(t *testing.T) {
	require.Equal(t, []string{"2.1", "2.3"}, Strings([]Version{{2, 1}, {2, 3}}))
	require.Empty(t, Strings(nil))
}
