// secdns-recordstore performs explicit offline record-store migrations only.
package main

import (
	"flag"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"io"
	"os"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("secdns-recordstore", flag.ContinueOnError)
	f.SetOutput(errOut)
	operation := f.String("operation", "", "enable-rrset-mutations (offline schema3 to4)")
	database := f.String("database", "", "Existing private record-store SQLite absolute path")
	ruleset := f.String("ruleset-id", "", "Existing ruleset identity")
	lineage := f.String("lineage-id", "", "Existing lineage identity")
	if f.Parse(args) != nil {
		return 2
	}
	if f.NArg() != 0 || *operation != "enable-rrset-mutations" || *database == "" || *ruleset == "" || *lineage == "" {
		fmt.Fprintln(errOut, "explicit operation, database and enrollment required")
		return 2
	}
	if e := recordstore.EnableRRsetMutationsSQLite(*database, recordstore.Enrollment{RulesetID: *ruleset, LineageID: *lineage}); e != nil {
		fmt.Fprintln(errOut, "offline migration failed; inspect database schema before retrying")
		return 1
	}
	fmt.Fprintln(out, "record-store schema4 enabled; existing records and receipts preserved")
	return 0
}
