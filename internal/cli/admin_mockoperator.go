package cli

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"rsp42/internal/testutil/mockoperator"
)

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
