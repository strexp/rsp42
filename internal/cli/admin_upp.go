package cli

import (
	"flag"
	"fmt"
	"os"

	"rsp42/internal/config"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

func cmdUPP(prog string, args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s admin upp list|import [--config FILE] [--dir DIR]\n", prog)
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("upp", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	dir := fs.String("dir", "", "UPP template directory (import source)")
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
	case "list":
		items, err := st.UPP.List()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("%-45s %-8s %-14s %s\n", "NAME", "SAIP", "SHA256", "ACTIVE")
		for _, t := range items {
			active := "yes"
			if !t.Active {
				active = "no"
			}
			sum := t.SHA256
			if len(sum) > 12 {
				sum = sum[:12]
			}
			fmt.Printf("%-45s %d.%-6d %-14s %s\n", t.Name, t.SAIPMajor, t.SAIPMinor, sum, active)
		}
		return 0
	case "import":
		if *dir == "" {
			fmt.Fprintln(os.Stderr, "upp import: --dir is required")
			return 2
		}
		n, err := service.ImportUPPTemplates(*dir, st.UPP)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("imported %d UPP template(s) from %s\n", n, *dir)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s admin upp: unknown action %q\n", prog, action)
		return 2
	}
}
