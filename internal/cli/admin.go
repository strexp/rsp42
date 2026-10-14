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
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "help", "--help", "-h":
		adminUsage(os.Stdout, prog)
		return 0
	case "version":
		return cmdVersion(os.Stdout)
	case "migrate":
		return cmdMigrate(prog, rest)
	case "rekey":
		return cmdRekey(prog, rest)
	case "profile":
		return cmdProfile(prog, rest)
	case "session":
		return cmdSession(prog, rest)
	case "gc":
		return cmdGC(prog, rest)
	case "upp":
		return cmdUPP(prog, rest)
	case "personalization":
		return cmdPersonalization(prog, rest)
	case "activation-code":
		return cmdActivationCode(rest)
	case "smds":
		return cmdSMDSAdmin(prog, rest)
	case "es2p":
		return cmdES2P(prog, rest)
	case "mock-operator":
		return cmdMockOperator(rest)
	default:
		fmt.Fprintf(os.Stderr, "%s admin: unknown command %q\n", prog, sub)
		adminUsage(os.Stderr, prog)
		return 2
	}
}

func adminUsage(w io.Writer, prog string) {
	_, _ = fmt.Fprintf(w, `%s admin - administrative commands

Usage:
  %s admin migrate           [--config FILE] [--db dp|ds]   apply database migrations
  %s admin rekey             [--config FILE]               re-encrypt sensitive columns
  %s admin profile list|show [--config FILE] [--iccid X]   inspect the profile inventory
  %s admin session gc        [--config FILE]               garbage-collect expired sessions
  %s admin gc                [--config FILE] [--keep 720h] delete stale notifications/orders/audit
  %s admin upp list|import   [--config FILE] [--dir DIR]   list / import UPP templates
  %s admin personalization list|import|delete              manage per-ICCID personalization
  %s admin activation-code   --fqdn F --matching-id M      generate an activation code (and QR)
  %s admin smds event list|delete                           inspect SM-DS events
  %s admin es2p downloadOrder|confirmOrder|cancelOrder|releaseProfile
  %s admin mock-operator     [--addr HOST:PORT]            run the test-only mock Operator
`, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog)
}
