package cli

import (
	"flag"
	"fmt"
	"os"

	"rsp42/internal/config"
	"rsp42/internal/store"
)

func cmdICCID(prog string, args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s admin iccid import|list|stats [--config FILE]\n", prog)
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("iccid", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	start := fs.String("start", "", "range start ICCID")
	end := fs.String("end", "", "range end ICCID")
	note := fs.String("note", "", "range note")
	state := fs.String("state", "", "list filter: available|allocated|blocked")
	tenant := fs.String("tenant", "", "tenant id (empty = platform default)")
	limit := fs.Int("limit", 50, "list limit")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath, config.RoleDP)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	st, err := store.Open(cfg.Profiles.Store.DSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = st.Close() }()

	switch action {
	case "import":
		if *start == "" || *end == "" {
			fmt.Fprintln(os.Stderr, "import: --start and --end are required")
			return 2
		}
		id, inserted, skipped, err := st.Pool.ImportRange(*tenant, *start, *end, *note)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("imported range #%d: inserted=%d skipped=%d\n", id, inserted, skipped)
		return 0
	case "stats":
		counts, ranges, err := st.Pool.Stats(tenant)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("ranges=%d\n", ranges)
		for _, s := range []string{"available", "allocated", "blocked"} {
			fmt.Printf("%-10s %d\n", s, counts[s])
		}
		return 0
	case "list":
		items, total, err := st.Pool.ListPage(*state, "", tenant, *limit, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("%-22s %-10s %-16s %s\n", "ICCID", "STATE", "EID", "NOTE")
		for _, e := range items {
			fmt.Printf("%-22s %-10s %-16s %s\n", e.ICCID, e.State, e.EID, e.Note)
		}
		fmt.Printf("total %d\n", total)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s admin iccid: unknown action %q\n", prog, action)
		return 2
	}
}
