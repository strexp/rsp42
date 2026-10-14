package config

import (
	"reflect"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// bindEnvs registers every configuration key with viper's environment lookup.
//
// AutomaticEnv alone is not sufficient: viper.Unmarshal only iterates the keys
// viper already knows about, so a key that appears neither in the YAML file nor
// in setDefaults would silently ignore its RSP42_* override. That affected e.g.
// RSP42_KMS_KEK_FILE and RSP42_SMDPP_SERVER_ES9P_TLS_CERT_FILE, while the README
// and the container deployment path both promise that every value can be set
// through the environment.
//
// The key list is derived from the Config struct's mapstructure tags, so it
// cannot drift away from the schema.
func bindEnvs(v *viper.Viper) {
	for _, key := range configKeys(reflect.TypeOf(Config{}), "") {
		// BindEnv only fails on an empty key, which configKeys never produces.
		_ = v.BindEnv(key)
	}
}

// configKeys returns the dotted configuration keys of t, skipping fields
// without a mapstructure tag. Struct-valued fields recurse; slice/map-valued
// fields contribute only their container key because element indices cannot be
// expressed as a scalar environment variable.
func configKeys(t reflect.Type, prefix string) []string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := strings.Split(f.Tag.Get("mapstructure"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft != reflect.TypeOf(time.Time{}) {
			keys = append(keys, configKeys(ft, key)...)
			continue
		}
		keys = append(keys, key)
	}
	return keys
}
