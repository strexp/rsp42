// Package admin implements the `rsp42 admin` command set: database migration and
// rekey, profile/session inspection, garbage collection, UPP template and ICCID
// pool management, per-ICCID personalization, activation-code generation, the
// SM-DS event inspector, the ES2+ client driver and the mock operator.
//
// The dispatch table stays in internal/cli (it is part of the top-level command
// surface); every entry here is a plain func(prog string, args []string) int.
package admin

// DefaultConfigPath is the configuration location the admin commands default to.
// It matches internal/cli's default for the role commands.
const DefaultConfigPath = "config/config.yaml"
