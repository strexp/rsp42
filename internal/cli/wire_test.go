package cli

import (
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/config"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// TestWireOperatorES2PIndependence is the regression test for G13: the ACR
// confirmation (ES2+.HandleAcrRequest) must be wired whenever acr_url is
// configured, even when the outbound progress callbacks are disabled — and
// conversely, enabling callbacks must not silently require an ACR URL.
func TestWireOperatorES2PIndependence(t *testing.T) {
	cases := []struct {
		name          string
		cfg           config.CallbackConfig
		wantCallbacks bool
		wantACR       bool
	}{
		{
			name:    "acr only",
			cfg:     config.CallbackConfig{Enabled: false, URL: "", ACRURL: "https://operator.example/acr", ACRTimeout: config.Duration(10 * time.Second)},
			wantACR: true,
		},
		{
			name:          "progress callbacks only",
			cfg:           config.CallbackConfig{Enabled: true, URL: "https://operator.example/cb", MaxAttempts: 3, RetryInterval: config.Duration(time.Minute)},
			wantCallbacks: true,
		},
		{
			name:          "both",
			cfg:           config.CallbackConfig{Enabled: true, URL: "https://operator.example/cb", ACRURL: "https://operator.example/acr", MaxAttempts: 3, RetryInterval: config.Duration(time.Minute)},
			wantCallbacks: true,
			wantACR:       true,
		},
		{
			name: "neither",
			cfg:  config.CallbackConfig{Enabled: false},
		},
		{
			// Enabled but without a URL is the pre-existing "not configured"
			// state; it must not build a queue, and must not enable ACR.
			name: "enabled without url",
			cfg:  config.CallbackConfig{Enabled: true, ACRURL: ""},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.Open("file:" + filepath.Join(t.TempDir(), "wire.db"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = st.Close() })

			cmae := &service.CMAE{}
			notifs := &service.NotificationService{}
			reg := newMetricsRegistry()

			queue, err := wireOperatorES2P(tc.cfg, "2.999.10", cmae, notifs, st, reg, slog.Default())
			require.NoError(t, err)

			if tc.wantCallbacks {
				require.NotNil(t, queue, "progress callbacks must be wired")
				require.NotNil(t, cmae.Notify)
				require.NotNil(t, notifs.Callback)
			} else {
				require.Nil(t, queue, "no callback queue expected")
				require.Nil(t, cmae.Notify)
				require.Nil(t, notifs.Callback)
			}

			if tc.wantACR {
				require.NotNil(t, cmae.ACRCheck, "ACR must be wired from acr_url alone")
			} else {
				require.Nil(t, cmae.ACRCheck)
			}
		})
	}
}
