package config

import (
	"github.com/go-viper/mapstructure/v2"
)

// durationHook decodes strings/time.Duration into our Duration type.
func durationHook() mapstructure.DecodeHookFunc {
	return mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.TextUnmarshallerHookFunc(),
	)
}
