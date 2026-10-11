package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"rsp42/internal/config"
	"rsp42/internal/kms"
	"rsp42/internal/store"
)

func loadConfig(path string) (*config.Config, error) { return config.Load(path, config.RolePreflight) }

func cmdMigrate(prog string, args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	which := fs.String("db", "dp", "which database: dp|ds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dsn := cfg.Profiles.Store.DSN
	if *which == "ds" {
		dsn = cfg.SMDS.Store.DSN
	}
	st, err := store.Open(dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = st.Close() }()
	fmt.Printf("migrated %s database\n", *which)
	return 0
}

func cmdRekey(prog string, args []string) int {
	fs := flag.NewFlagSet("rekey", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	newKEK := fs.String("new-kek", "", "path to the new 32-byte KEK file")
	which := fs.String("db", "dp", "which database: dp|ds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *newKEK == "" {
		fmt.Fprintln(os.Stderr, "rekey: --new-kek is required")
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	oldProvider, err := newKMSProvider(&cfg.KMS)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	newProvider, err := kms.NewFileProvider(*newKEK)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dsn := cfg.Profiles.Store.DSN
	if *which == "ds" {
		dsn = cfg.SMDS.Store.DSN
	}
	st, err := store.Open(dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = st.Close() }()

	txns, err := st.Sessions.ListTransactions()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	count := 0
	for _, txn := range txns {
		s, err := st.Sessions.Get(txn)
		if err != nil {
			continue
		}
		for _, f := range []*[]byte{&s.ServerChallenge, &s.SmdpOtSK, &s.SharedSecret, &s.CCHash} {
			if len(*f) == 0 {
				continue
			}
			pt, err := oldProvider.Decrypt(*f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "rekey: decrypt %s: %v\n", txn, err)
				return 1
			}
			ct, err := newProvider.Encrypt(pt)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			*f = ct
		}
		if err := st.Sessions.Put(s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		count++
	}
	fmt.Printf("rekeyed %d session(s)\n", count)
	return 0
}

func cmdProfile(prog string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: admin profile list|show --config FILE [--iccid ICCID]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("profile", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	iccid := fs.String("iccid", "", "ICCID for show")
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
	switch sub {
	case "list":
		ps, err := st.Profiles.List()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, p := range ps {
			fmt.Printf("%-21s %-12s %s\n", p.ICCID, p.State, p.EID)
		}
		return 0
	case "show":
		p, err := st.Profiles.GetByICCID(*iccid)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(p)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown profile subcommand %q\n", sub)
		return 2
	}
}

func cmdSession(prog string, args []string) int {
	if len(args) == 0 || args[0] != "gc" {
		fmt.Fprintln(os.Stderr, "usage: admin session gc --config FILE")
		return 2
	}
	fs := flag.NewFlagSet("session", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
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
	n, err := st.Sessions.GCExpired(time.Now().UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("removed %d expired session(s)\n", n)
	return 0
}
