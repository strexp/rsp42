// Package version exposes build metadata for the rsp42 binaries.
package version

import "runtime/debug"

// These values may be overridden at build time with -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info is the structured build information returned by the version command.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"goVersion"`
}

// Get returns the build information, filling in module data when available.
func Get() Info {
	goVersion := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		goVersion = bi.GoVersion
	}
	return Info{Version: Version, Commit: Commit, Date: Date, GoVersion: goVersion}
}
