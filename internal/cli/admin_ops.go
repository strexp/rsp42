package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"rsp42/internal/activationcode"
	"rsp42/internal/api/es2plus"
	"rsp42/internal/config"
	"rsp42/internal/service"
	"rsp42/internal/store"
	"rsp42/internal/testutil/mockoperator"
)

func cmdActivationCode(args []string) int {
	fs := flag.NewFlagSet("activation-code", flag.ContinueOnError)
	fqdn := fs.String("fqdn", "", "SM-DP+ FQDN")
	matchingID := fs.String("matching-id", "", "matching id / token")
	oid := fs.String("oid", "", "SM-DP+ OID")
	cc := fs.Bool("cc", false, "confirmation code required")
	qrPath := fs.String("qr", "", "write a PNG QR code to this path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *fqdn == "" || *matchingID == "" {
		fmt.Fprintln(os.Stderr, "activation-code: --fqdn and --matching-id are required")
		return 2
	}
	c := &activationcode.Code{FQDN: *fqdn, MatchingID: *matchingID, OID: *oid, CCRequired: *cc}
	fmt.Println(c.String())
	fmt.Println(c.QRContent())
	if *qrPath != "" {
		png, err := c.PNG()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := os.WriteFile(*qrPath, png, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("wrote QR to", *qrPath)
	}
	return 0
}

func cmdSMDSAdmin(prog string, args []string) int {
	if len(args) < 2 || args[0] != "event" {
		fmt.Fprintln(os.Stderr, "usage: admin smds event list|delete --config FILE")
		return 2
	}
	action := args[1]
	fs := flag.NewFlagSet("smds", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/config.yaml", "config path")
	eid := fs.String("eid", "", "EID")
	eventID := fs.String("event-id", "", "EventID")
	caller := fs.String("caller-oid", "", "caller OID")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath, config.RoleDS)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
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

func cmdES2P(prog string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: admin es2p downloadOrder|confirmOrder|cancelOrder|releaseProfile ...")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("es2p", flag.ContinueOnError)
	url := fs.String("url", "https://127.0.0.1:8444", "SM-DP+ ES2+ base URL")
	requester := fs.String("requester", "rsp42-admin", "function requester identifier")
	iccid := fs.String("iccid", "", "ICCID")
	eid := fs.String("eid", "", "EID")
	matchingID := fs.String("matching-id", "", "matching id")
	profileType := fs.String("profile-type", "", "profile type")
	cc := fs.String("confirmation-code", "", "confirmation code")
	smds := fs.String("smds-address", "", "SM-DS address")
	release := fs.Bool("release", false, "release flag")
	final := fs.String("final-status", "", "final profile status indicator")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	client := es2plus.NewClient(*url, *requester, nil)
	ctx := context.Background()
	switch sub {
	case "downloadOrder":
		res, err := client.DownloadOrder(ctx, *eid, *iccid, *profileType)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(res.ICCID)
	case "confirmOrder":
		res, err := client.ConfirmOrder(ctx, es2plus.ConfirmOrderRequest{
			ICCID: *iccid, EID: *eid, MatchingID: *matchingID, ConfirmationCode: *cc,
			SMDSAddress: *smds, ReleaseFlag: *release,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("matchingId=%s smdpAddress=%s\n", res.MatchingID, res.SMDPAddress)
	case "cancelOrder":
		if err := client.CancelOrder(ctx, *iccid, *eid, *matchingID, *final); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("cancelled")
	case "releaseProfile":
		if err := client.ReleaseProfile(ctx, *iccid); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("released")
	default:
		fmt.Fprintf(os.Stderr, "unknown es2p subcommand %q\n", sub)
		return 2
	}
	return 0
}

func cmdMockOperator(args []string) int {
	fs := flag.NewFlagSet("mock-operator", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:9500", "listen address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	op := mockoperator.NewOperator()
	fmt.Printf("mock operator listening on http://%s\n", *addr)
	if err := http.ListenAndServe(*addr, op.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
