package cli

import (
	"flag"
	"fmt"
	"os"

	"rsp42/internal/config"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

func cmdPersonalization(prog string, args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s admin personalization list|import|delete [--config FILE] [--iccid X]\n", prog)
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("personalization", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	iccid := fs.String("iccid", "", "ICCID (delete)")
	file := fs.String("file", "", "CSV/file path (import)")
	kind := fs.String("kind", "csv", "import source kind: csv|file|static")
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
	provider, err := newKMSProvider(&cfg.KMS)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	svc := service.NewPersonalizationService(st.Perso, provider)

	switch action {
	case "list":
		items, err := svc.List()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("%-22s %-16s %-12s %s\n", "ICCID", "IMSI", "ALGORITHM", "K?/OPc?")
		for _, d := range items {
			hasK, hasOPc := "-", "-"
			if len(d.K) > 0 {
				hasK = "K"
			}
			if len(d.OPc) > 0 {
				hasOPc = "OPc"
			}
			fmt.Printf("%-22s %-16s %-12s %s/%s\n", d.ICCID, d.IMSI, d.Algorithm, hasK, hasOPc)
		}
		return 0
	case "import":
		if *file == "" {
			fmt.Fprintln(os.Stderr, "import: --file is required")
			return 2
		}
		n, err := svc.Import(*kind, *file, nil, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("imported %d personalization record(s) from %s\n", n, *file)
		return 0
	case "delete":
		if *iccid == "" {
			fmt.Fprintln(os.Stderr, "delete: --iccid is required")
			return 2
		}
		if err := svc.Delete(*iccid); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("deleted", *iccid)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s admin personalization: unknown action %q\n", prog, action)
		return 2
	}
}
