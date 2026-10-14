package cli

import (
	"fmt"
	"io"
	"os"
)

func cmdAdmin(prog string, args []string) int {
	if len(args) == 0 {
		adminUsage(os.Stderr, prog)
		return 2
	}
	if isHelp(args[0]) {
		adminUsage(os.Stdout, prog)
		return 0
	}
	for _, c := range adminCommands {
		if c.name == args[0] {
			return c.run(prog, args[1:])
		}
	}
	fmt.Fprintf(os.Stderr, "%s admin: unknown command %q\n", prog, args[0])
	adminUsage(os.Stderr, prog)
	return 2
}

// adminCommands is the admin subcommand table; it drives dispatch and the help
// output, so the two cannot drift apart.
var adminCommands = []command{
	{name: "migrate", usage: "migrate           [--config FILE] [--db dp|ds|all]", summary: "apply database migrations", run: cmdMigrate},
	{name: "rekey", usage: "rekey             [--config FILE] [--db dp|ds|all]", summary: "re-encrypt sensitive columns", run: cmdRekey},
	{name: "profile", usage: "profile list|show [--config FILE] [--iccid X]", summary: "inspect the SM-DP+ profile inventory", run: cmdProfile},
	{name: "session", usage: "session gc        [--config FILE] [--db dp|ds|all]", summary: "garbage-collect expired sessions", run: cmdSession},
	{name: "gc", usage: "gc                [--config FILE] [--db dp|ds|all]", summary: "delete stale notifications/orders/audit", run: cmdGC},
	{name: "upp", usage: "upp list|import   [--config FILE] [--dir DIR]", summary: "list / import UPP templates (SM-DP+)", run: cmdUPP},
	{name: "iccid", usage: "iccid import|list|stats [--start X --end Y]", summary: "manage the ICCID pool (SM-DP+)", run: cmdICCID},
	{name: "personalization", usage: "personalization list|import|delete", summary: "manage per-ICCID personalization (SM-DP+)", run: cmdPersonalization},
	{name: "activation-code", usage: "activation-code   --fqdn F --matching-id M", summary: "generate an activation code (and QR)", run: func(_ string, args []string) int { return cmdActivationCode(args) }},
	{name: "smds", usage: "smds event list|delete", summary: "inspect SM-DS events", run: cmdSMDSAdmin},
	{name: "es2p", usage: "es2p downloadOrder|confirmOrder|...", summary: "drive an SM-DP+ over ES2+", run: cmdES2P},
	{name: "mock-operator", usage: "mock-operator     [--addr HOST:PORT]", summary: "run the test-only mock Operator", run: func(_ string, args []string) int { return cmdMockOperator(args) }},
	{name: "version", usage: "version", summary: "print build information", run: func(string, []string) int { return cmdVersion(os.Stdout) }},
}

func adminUsage(w io.Writer, prog string) {
	_, _ = fmt.Fprintf(w, "%s admin - administrative commands\n\nUsage:\n", prog)
	for _, c := range adminCommands {
		_, _ = fmt.Fprintf(w, "  %s admin %-42s %s\n", prog, c.usage, c.summary)
	}
	_, _ = fmt.Fprint(w, `
--db selects the SM-DP+ (dp) or SM-DS (ds) database, or both (all, the default).
`)
}
