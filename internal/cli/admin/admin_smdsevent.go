package admin

import (
	"flag"
	"fmt"
	"os"

	"rsp42/internal/service"
	"rsp42/internal/store"
)

func SMDSAdmin(prog string, args []string) int {
	if len(args) < 2 || args[0] != "event" {
		fmt.Fprintln(os.Stderr, "usage: admin smds event list|delete --config FILE")
		return 2
	}
	action := args[1]
	fs := flag.NewFlagSet("smds", flag.ContinueOnError)
	cfgPath := fs.String("config", DefaultConfigPath, "config path")
	eid := fs.String("eid", "", "EID")
	eventID := fs.String("event-id", "", "EventID")
	caller := fs.String("caller-oid", "", "caller OID")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if cfg.SMDS.Role == "" || cfg.SMDS.FQDN == "" {
		fmt.Fprintln(os.Stderr, "smds event: smds.role and smds.fqdn are required")
		return 2
	}
	st, err := store.Open(cfg.SMDS.Store.DSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = st.Close() }()
	svc := service.NewEventService(st.Events, cfg.SMDS.Role, cfg.SMDS.FQDN, 0)
	switch action {
	case "list":
		recs, err := st.Events.ListAll()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, r := range recs {
			fmt.Printf("%s %s -> %s (caller %s)\n", r.EID, r.EventID, r.RSPServerAddress, r.CallerOID)
		}
		return 0
	case "delete":
		if err := svc.Delete(*eid, *eventID, *caller); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("deleted")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown smds event subcommand %q\n", action)
		return 2
	}
}
