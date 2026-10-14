package service

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/store"
)

func TestSAIPVersionPolicyAllows(t *testing.T) {
	p, err := NewSAIPVersionPolicy([]string{"2.3"})
	require.NoError(t, err)

	// N16 acceptance matrix: (2,3) passes, anything above is refused.
	require.True(t, p.Allows(2, 3))
	require.True(t, p.Allows(2, 1))
	require.True(t, p.Allows(1, 0))
	require.False(t, p.Allows(2, 4))
	require.False(t, p.Allows(3, 0))
	require.False(t, p.Allows(3, 2))

	// Every version family below the baseline is admitted.
	require.Nil(t, p.CheckSAIPVersion(2, 3))
	rej := p.CheckSAIPVersion(3, 2)
	require.NotNil(t, rej)
	require.Equal(t, "3.2", rej.TemplateVersion)
	require.Equal(t, "2.3", rej.MaxSupported)

	// A nil policy means "no limit" (used by tooling without a config).
	var none *SAIPVersionPolicy
	require.True(t, none.Allows(9, 9))
	require.Nil(t, none.CheckSAIPVersion(9, 9))
}

func TestSAIPVersionPolicyList(t *testing.T) {
	// The list form is the interface reserved for a future dual-major support
	// set: both families must be admitted, anything above the highest refused.
	p, err := NewSAIPVersionPolicy([]string{"3.2", "2.3"})
	require.NoError(t, err)
	require.True(t, p.Allows(2, 3))
	require.True(t, p.Allows(3, 0))
	require.True(t, p.Allows(3, 2))
	require.False(t, p.Allows(3, 3))
	require.False(t, p.Allows(4, 0))
	max, ok := p.Max()
	require.True(t, ok)
	require.Equal(t, "3.2", max.String())
}

func TestSAIPVersionPolicyParseErrors(t *testing.T) {
	for _, raw := range [][]string{{"2"}, {"x.3"}, {"2.y"}, {"2.3.1.4"}, {""}} {
		_, err := NewSAIPVersionPolicy(raw)
		require.Error(t, err, "input %v", raw)
	}
	// A document revision is accepted and ignored: V2.3.1 is encoded as 2.3.
	p, err := NewSAIPVersionPolicy([]string{"2.3.1"})
	require.NoError(t, err)
	require.True(t, p.Allows(2, 3))
	require.False(t, p.Allows(2, 4))
}

// TestImportUPPTemplatesEnforcesVersionLimit pins the CLI import path: the
// importer applies the same policy as the management API, so it cannot be used
// to bypass profiles.allowed_saip_versions. The testdata directory contains
// SAIP 2.3 fixtures, which a 2.1 baseline must refuse.
func TestImportUPPTemplatesEnforcesVersionLimit(t *testing.T) {
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "upp.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	policy, err := NewSAIPVersionPolicy([]string{"2.1"})
	require.NoError(t, err)
	_, err = ImportUPPTemplates(filepath.Join("..", "..", "testdata", "upp"), st.UPP, policy)
	require.Error(t, err)
	require.Contains(t, err.Error(), "2.3")
}
