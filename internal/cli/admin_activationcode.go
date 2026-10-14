package cli

import (
	"flag"
	"fmt"
	"os"

	"rsp42/internal/activationcode"
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
