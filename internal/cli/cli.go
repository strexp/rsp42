// Package cli implements the rsp42 command line interface. The single rsp42
// binary provides both roles as peers: `rsp42 smdpp` and `rsp42 smds`.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// defaultConfigPath is the configuration location every command defaults to.
const defaultConfigPath = "config/config.yaml"

// command is one CLI subcommand. The table drives both dispatch and the usage
// text, so a command cannot be added or renamed without the help output
// following, and the shared flags come from one place.
type command struct {
	name    string
	usage   string
	summary string
	run     func(prog string, args []string) int
}

// topLevelCommands is the rsp42 command table.
var topLevelCommands = []command{
	{name: "smdpp", usage: "smdpp   [--config FILE]", summary: "run the SM-DP+ role", run: cmdSMDpp},
	{name: "smds", usage: "smds    [--config FILE]", summary: "run the SM-DS role", run: cmdSMDS},
	{name: "admin", usage: "admin   <command>", summary: "administrative commands", run: cmdAdmin},
	{name: "version", usage: "version", summary: "print build information",
		run: func(string, []string) int { return cmdVersion(os.Stdout) }},
}

// Main dispatches the rsp42 command line. It returns a process exit code.
func Main(prog string, args []string) int {
	if len(args) == 0 {
		usage(os.Stderr, prog)
		return 2
	}
	if isHelp(args[0]) {
		usage(os.Stdout, prog)
		return 0
	}
	for _, c := range topLevelCommands {
		if c.name == args[0] {
			return c.run(prog, args[1:])
		}
	}
	fmt.Fprintf(os.Stderr, "%s: unknown command %q\n", prog, args[0])
	usage(os.Stderr, prog)
	return 2
}

// isHelp reports the conventional help spellings.
func isHelp(arg string) bool {
	switch arg {
	case "help", "--help", "-h", "-help":
		return true
	default:
		return false
	}
}

func usage(w io.Writer, prog string) {
	_, _ = fmt.Fprintf(w, "%s - SM-DP+ and SM-DS for SGP.22\n\nUsage:\n", prog)
	for _, c := range topLevelCommands {
		_, _ = fmt.Fprintf(w, "  %s %-24s %s\n", prog, c.usage, c.summary)
	}
	_, _ = fmt.Fprintf(w, `
The SM-DP+ and SM-DS roles have equal standing; neither is the default.

Run "%s admin help" for the list of admin commands.
`, prog)
}

// globalFlags registers the flags common to the serve/smds commands.
func globalFlags(prog string, _ []string) (cfgPath *string, fs *flag.FlagSet) {
	fs = flag.NewFlagSet(prog, flag.ContinueOnError)
	cfgPath = fs.String("config", defaultConfigPath, "path to the YAML configuration file")
	return cfgPath, fs
}
