// routeros-dns-preview parses DNS-static export text from stdin as data only.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/zhouchenh/secDNS/internal/importers/routeros"
)

func main() {
	preview, err := routeros.Parse(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(preview); err != nil {
		fmt.Fprintln(os.Stderr, "could not write preview")
		os.Exit(1)
	}
}
