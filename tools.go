//go:build tools

// This file pins the project's planned dependencies so that `go mod tidy` keeps
// their versions resolved before the packages that use them are written. It is
// never compiled into any binary.
package tools

import (
	_ "github.com/aead/cmac"
	_ "github.com/euicc-go/bertlv"
	_ "github.com/pressly/goose/v3"
	_ "github.com/santhosh-tekuri/jsonschema/v6"
	_ "github.com/skip2/go-qrcode"
	_ "gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)
