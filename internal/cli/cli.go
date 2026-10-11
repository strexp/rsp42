// Package cli implements the rsp42 command line interface shared by the
// rsp42 and smds binaries.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// Main dispatches the rsp42 command line. It returns a process exit code.
func Main(prog string, args []string) int {
	if len(args) == 0 {
		usage(os.Stderr, prog)
		return 2
	}
	cmd := args[0]
	rest := args[1:]
	switch cmd {
	case "smdpp":
		return cmdSMDpp(prog, rest)
	case "smds":
		return cmdSMDS(prog, rest)
	case "admin":
		return cmdAdmin(prog, rest)
	case "version", "--version", "-version":
		return cmdVersion(os.Stdout)
	case "help", "--help", "-h":
		usage(os.Stdout, prog)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n", prog, cmd)
		usage(os.Stderr, prog)
		return 2
	}
}

func usage(w io.Writer, prog string) {
	_, _ = fmt.Fprintf(w, `%s - SM-DP+ and SM-DS for SGP.22

Usage:
  %s smdpp   [--config FILE]   run the SM-DP+ role
  %s smds    [--config FILE]   run the SM-DS role
  %s admin   <command>         administrative commands
  %s version                   print build information

The SM-DP+ and SM-DS roles have equal standing; neither is the default.

Run "%s admin help" for the list of admin commands.
`, prog, prog, prog, prog, prog, prog)
}

// globalFlags registers the flags common to the serve/smds commands.
func globalFlags(prog string, args []string) (cfgPath *string, fs *flag.FlagSet) {
	fs = flag.NewFlagSet(prog, flag.ContinueOnError)
	cfgPath = fs.String("config", "config/config.yaml", "path to the YAML configuration file")
	return cfgPath, fs
}
