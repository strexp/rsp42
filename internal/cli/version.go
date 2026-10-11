package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"rsp42/internal/version"
)

func cmdVersion(w io.Writer) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(version.Get()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
