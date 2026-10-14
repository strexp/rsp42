package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"rsp42/internal/api/es2plus"
)

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
