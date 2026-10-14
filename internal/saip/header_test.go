package saip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRebuildMandatoryGFSTEListMatchesTemplates verifies that recomputing the
// eUICC-Mandatory-GFSTEList from the template PEs reproduces the list already
// present in every TS.48 template.
func TestRebuildMandatoryGFSTEListMatchesTemplates(t *testing.T) {
	dir := "../../testdata/upp"
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".der") || strings.Contains(name, "UNIQUE") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			require.NoError(t, err)
			seq, err := ParseUPP(raw)
			require.NoError(t, err)

			orig := seq.Header().Find(hdrGFSTE)
			require.NotNil(t, orig, "template must carry a GFSTE list")

			require.NoError(t, seq.RebuildMandatoryGFSTEList())
			got := seq.Header().Find(hdrGFSTE)
			require.NotNil(t, got)
			require.Equal(t, orig.Encode(), got.Encode())
		})
		checked++
	}
	require.Greater(t, checked, 0, "expected at least one template")
}
