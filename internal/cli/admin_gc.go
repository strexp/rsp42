package cli

import (
	"flag"
	"fmt"
	"os"
	"time"

	"rsp42/internal/store"
)

// cmdGC removes stale rows (retention) from the selected database(s).
func cmdGC(prog string, args []string) int {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	keep := fs.Duration("keep", 720*time.Hour, "retain rows newer than this (e.g. 720h)")
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
	cutoff := time.Now().UTC().Add(-*keep).Unix()
	for _, t := range targets {
		st, err := store.Open(t.dsn)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		notifs, err := st.Notifs.DeleteBefore(cutoff)
		if err != nil {
			_ = st.Close()
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		orders, err := st.Orders.DeleteBefore(cutoff)
		if err != nil {
			_ = st.Close()
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		audit, err := st.Audit.DeleteBefore(cutoff)
		if err != nil {
			_ = st.Close()
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		sessions, _ := st.Sessions.GCExpired(time.Now().UTC())
		_ = st.Close()
		fmt.Printf("gc %s: notifications=%d orders=%d audit=%d sessions=%d (keep=%s)\n",
			t.name, notifs, orders, audit, sessions, *keep)
	}
	return 0
}
