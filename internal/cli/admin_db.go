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

// dbTarget is one database selected by --db.
type dbTarget struct {
	name string // "dp" | "ds"
	dsn  string
}

// dbTargets resolves --db (dp|ds|all) to the database(s) to operate on. "all"
// is the neutral default: neither role is privileged.
func dbTargets(cfg *config.Config, which string) ([]dbTarget, error) {
	var dsns []dbTarget
	add := func(name, dsn string) {
		if dsn != "" {
			dsns = append(dsns, dbTarget{name, dsn})
		}
	}
	switch which {
	case "dp":
		add("dp", cfg.Profiles.Store.DSN)
	case "ds":
		add("ds", cfg.SMDS.Store.DSN)
	case "all":
		add("dp", cfg.Profiles.Store.DSN)
		add("ds", cfg.SMDS.Store.DSN)
	default:
		return nil, fmt.Errorf("invalid --db %q (want dp|ds|all)", which)
	}
	if len(dsns) == 0 {
		return nil, fmt.Errorf("no database configured for --db %q", which)
	}
	return dsns, nil
}

func cmdMigrate(prog string, args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	which := fs.String("db", "all", "which database: dp|ds|all")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	targets, err := dbTargets(cfg, *which)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, t := range targets {
		st, err := store.Open(t.dsn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate %s: %v\n", t.name, err)
			return 1
		}
		_ = st.Close()
		fmt.Printf("migrated %s database\n", t.name)
	}
	return 0
}

func cmdRekey(prog string, args []string) int {
	fs := flag.NewFlagSet("rekey", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	newKEK := fs.String("new-kek", "", "path to the new 32-byte KEK file")
	which := fs.String("db", "all", "which database: dp|ds|all")
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
	targets, err := dbTargets(cfg, *which)
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
	total := 0
	for _, t := range targets {
		st, err := store.Open(t.dsn)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		n, err := rekeySessions(st, oldProvider, newProvider)
		_ = st.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "rekey %s: %v\n", t.name, err)
			return 1
		}
		fmt.Printf("rekeyed %d session(s) in the %s database\n", n, t.name)
		total += n
	}
	_ = total
	return 0
}

func rekeySessions(st *store.Store, oldP, newP kms.Provider) (int, error) {
	txns, err := st.Sessions.ListTransactions()
	if err != nil {
		return 0, err
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
			pt, err := oldP.Decrypt(*f)
			if err != nil {
				return count, fmt.Errorf("decrypt %s: %w", txn, err)
			}
			ct, err := newP.Encrypt(pt)
			if err != nil {
				return count, err
			}
			*f = ct
		}
		if err := st.Sessions.Put(s); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
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
		fmt.Fprintln(os.Stderr, "usage: admin session gc --config FILE [--db dp|ds|all]")
		return 2
	}
	fs := flag.NewFlagSet("session", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	which := fs.String("db", "all", "which database: dp|ds|all")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	targets, err := dbTargets(cfg, *which)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	total := int64(0)
	for _, t := range targets {
		st, err := store.Open(t.dsn)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		n, err := st.Sessions.GCExpired(time.Now().UTC())
		_ = st.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "session gc %s: %v\n", t.name, err)
			return 1
		}
		fmt.Printf("removed %d expired session(s) from the %s database\n", n, t.name)
		total += n
	}
	_ = total
	return 0
}
