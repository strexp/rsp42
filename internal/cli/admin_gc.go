package cli

import (
	"flag"
	"fmt"
	"os"
	"time"

	"rsp42/internal/config"
	"rsp42/internal/store"
)

// cmdGC removes stale rows (retention). Sessions are handled by `admin session gc`.
func cmdGC(prog string, args []string) int {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	keep := fs.Duration("keep", 720*time.Hour, "retain rows newer than this (e.g. 720h)")
	if err := fs.Parse(args); err != nil {
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

	cutoff := time.Now().UTC().Add(-*keep).Unix()
	notifs, err := st.Notifs.DeleteBefore(cutoff)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	orders, err := st.Orders.DeleteBefore(cutoff)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	audit, err := st.Audit.DeleteBefore(cutoff)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	sessions, _ := st.Sessions.GCExpired(time.Now().UTC())
	fmt.Printf("gc: notifications=%d orders=%d audit=%d sessions=%d (keep=%s)\n",
		notifs, orders, audit, sessions, *keep)
	return 0
}
