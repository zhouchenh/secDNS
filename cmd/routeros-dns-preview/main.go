// routeros-dns-preview parses DNS-static export text from stdin as data only.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zhouchenh/secDNS/internal/importers/routeros"
)

const maxExactReportBytes = 16 << 20

const (
	invalidOptionsMessage = "invalid command options"
	invalidConfigMessage  = "invalid exact compiler configuration"
	exactFailureMessage   = "exact compilation failed"
)

type exactReport struct {
	Profile       string                    `json:"profile"`
	RulesetID     string                    `json:"ruleset_id"`
	Compiled      bool                      `json:"compiled"`
	CanApply      bool                      `json:"can_apply"`
	SourceSHA256  string                    `json:"source_sha256"`
	Source        *routeros.Preview         `json:"source"`
	Blockers      []routeros.CompileBlocker `json:"blockers,omitempty"`
	ContentSHA256 string                    `json:"content_sha256,omitempty"`
	Bindings      []routeros.ExactBinding   `json:"bindings,omitempty"`
	Content       json.RawMessage           `json:"content,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("routeros-dns-preview", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	compileExact := flags.Bool("compile-exact", false, "compile the complete source under the strict exact profile")
	rulesetID := flags.String("ruleset-id", "", "candidate ruleset identifier (required with --compile-exact)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*compileExact && *rulesetID != "" {
		fmt.Fprintln(stderr, invalidOptionsMessage)
		return 2
	}
	if !*compileExact {
		return runPreview(stdin, stdout, stderr)
	}
	if *rulesetID == "" {
		fmt.Fprintln(stderr, invalidConfigMessage)
		return 2
	}
	return runExact(stdin, stdout, stderr, *rulesetID)
}

func runPreview(stdin io.Reader, stdout, stderr io.Writer) int {
	preview, err := routeros.Parse(stdin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(preview); err != nil {
		fmt.Fprintln(stderr, "could not write preview")
		return 1
	}
	return 0
}

func runExact(stdin io.Reader, stdout, stderr io.Writer, rulesetID string) int {
	compilation, compileErr := routeros.CompileExact(stdin, rulesetID)
	if compilation == nil {
		switch {
		case errors.Is(compileErr, routeros.ErrExactConfig):
			fmt.Fprintln(stderr, invalidConfigMessage)
			return 2
		case compileErr != nil:
			fmt.Fprintln(stderr, compileErr)
			return 1
		default:
			fmt.Fprintln(stderr, exactFailureMessage)
			return 1
		}
	}

	source := compilation.Preview()
	report := exactReport{
		Profile:      compilation.Profile(),
		RulesetID:    rulesetID,
		Compiled:     compilation.Compiled(),
		CanApply:     compilation.CanApply(),
		SourceSHA256: source.SourceSHA256,
		Source:       source,
		Blockers:     compilation.Blockers(),
	}
	if compilation.Compiled() {
		report.ContentSHA256 = compilation.ContentSHA256()
		report.Bindings = compilation.Bindings()
		report.Content = json.RawMessage(compilation.ContentJSON())
	}
	if err := writeExactReport(stdout, report); err != nil {
		fmt.Fprintln(stderr, "could not write exact compilation")
		return 1
	}
	if compileErr != nil {
		fmt.Fprintln(stderr, compileErr)
		return 1
	}
	return 0
}

func writeExactReport(w io.Writer, report exactReport) error {
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if len(payload)+1 > maxExactReportBytes {
		return errors.New("exact compilation report limit exceeded")
	}
	payload = append(payload, '\n')
	_, err = io.Copy(w, bytes.NewReader(payload))
	return err
}
