package service

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/kms"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/store"
)

func TestPersonalizationEncryptedAtRestAndImport(t *testing.T) {
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "perso.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	svc := NewPersonalizationService(st.Perso, provider)

	key, _ := hex.DecodeString("465B5CE8B199B49FAA5F0A2EE238A6BC")
	opc, _ := hex.DecodeString("CDC202D5123E20F62B6D676AC72CAB35")
	require.NoError(t, svc.Put("", &personalization.Data{
		ICCID: "89000123456789012341", IMSI: "001010123456063", K: key, OPc: opc,
		SPN: "TEST", Algorithm: "milenage",
	}))

	// Secrets are encrypted at rest.
	row, err := st.Perso.GetByICCID("", "89000123456789012341")
	require.NoError(t, err)
	require.NotEqual(t, key, row.K)
	require.NotEqual(t, opc, row.OPc)

	// ... and decrypt back through the service.
	got, err := svc.Resolve("", "89000123456789012341", "")
	require.NoError(t, err)
	require.Equal(t, key, got.K)
	require.Equal(t, opc, got.OPc)
	require.Equal(t, "001010123456063", got.IMSI)

	// Unknown ICCID resolves to nil (no personalization), not an error.
	none, err := svc.Resolve("", "89999999999999999999", "")
	require.NoError(t, err)
	require.Nil(t, none)

	// Import from a CSV source.
	csvPath := filepath.Join(t.TempDir(), "perso.csv")
	require.NoError(t, os.WriteFile(csvPath, []byte(
		"iccid,imsi,spn\n"+
			"89000123456789012342,001010123456064,IMPORTED\n"), 0o600))
	n, err := svc.Import("", "csv", csvPath, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	imported, err := svc.Resolve("", "89000123456789012342", "")
	require.NoError(t, err)
	require.Equal(t, "IMPORTED", imported.SPN)

	require.NoError(t, svc.Delete("", "89000123456789012342"))
	deleted, err := svc.Resolve("", "89000123456789012342", "")
	require.NoError(t, err)
	require.Nil(t, deleted)
}
