package activationcode

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseBuildRoundTrip(t *testing.T) {
	c, err := Parse("1$testsmdpplus1.example.com$TOKEN123$2.999.10$1")
	require.NoError(t, err)
	require.Equal(t, "testsmdpplus1.example.com", c.FQDN)
	require.Equal(t, "TOKEN123", c.MatchingID)
	require.Equal(t, "2.999.10", c.OID)
	require.True(t, c.CCRequired)
	require.Equal(t, "1$testsmdpplus1.example.com$TOKEN123$2.999.10$1", c.String())

	c2, err := Parse("1$dp.example.com$TOKEN")
	require.NoError(t, err)
	require.False(t, c2.CCRequired)
	require.Equal(t, "1$dp.example.com$TOKEN", c2.String())

	require.Equal(t, "LPA:1$dp.example.com$TOKEN", c2.QRContent())

	png, err := c2.PNG()
	require.NoError(t, err)
	require.NotEmpty(t, png)
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{"", "2$a$b", "1$", "1$$b", "a$b$c"} {
		_, err := Parse(s)
		require.Error(t, err, "input %q", s)
	}
}

func TestParseACR(t *testing.T) {
	a, err := ParseACR("ACR-0-8947010000123456784")
	require.NoError(t, err)
	require.Equal(t, 0, a.Check)
	require.Equal(t, "8947010000123456784", a.ICCID)

	b, err := ParseACR("ACR-1-8947010000123456784")
	require.NoError(t, err)
	require.Equal(t, 1, b.Check)

	require.True(t, IsACR("ACR-0-1"))
	require.False(t, IsACR("TOKEN"))

	for _, s := range []string{"ACR-2-1", "ACR-0", "ACR-0-abc", "X-0-1"} {
		_, err := ParseACR(s)
		require.Error(t, err, "input %q", s)
	}
}
