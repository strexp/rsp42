// Command rsp42 provides both the SM-DP+ and SM-DS roles as subcommands
// (`rsp42 smdpp` and `rsp42 smds`), plus administrative tooling.
package main

import (
	"os"

	"rsp42/internal/cli"
)

func main() {
	os.Exit(cli.Main("rsp42", os.Args[1:]))
}
