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
	"sort"

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
	Source        *routeros.Preview         `json:"source,omitempty"`
	Blockers      []routeros.CompileBlocker `json:"blockers,omitempty"`
	Coverage      *exactCoverage            `json:"coverage,omitempty"`
	ContentSHA256 string                    `json:"content_sha256,omitempty"`
	Bindings      []routeros.ExactBinding   `json:"bindings,omitempty"`
	Content       json.RawMessage           `json:"content,omitempty"`
}

type exactCoverageCount struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// exactCoverage intentionally contains only fixed categories and aggregate
// counts. It never includes source fields, record content or row locations.
type exactCoverage struct {
	SourceEntries               int                  `json:"source_entries"`
	ParserExactRecordCandidates int                  `json:"parser_exact_record_candidates"`
	ParserUnsupportedEntries    int                  `json:"parser_unsupported_entries"`
	CompilerBlockedEntries      int                  `json:"compiler_blocked_entries"`
	CompilerGlobalBlockers      int                  `json:"compiler_global_blockers"`
	DiagnosticCounts            []exactCoverageCount `json:"diagnostic_counts,omitempty"`
	BlockerCounts               []exactCoverageCount `json:"blocker_counts,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("routeros-dns-preview", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	compileExact := flags.Bool("compile-exact", false, "compile the complete source under the strict exact profile")
	coverageOnly := flags.Bool("coverage-only", false, "omit source and candidate data from an exact compilation report")
	rulesetID := flags.String("ruleset-id", "", "candidate ruleset identifier (required with --compile-exact)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*compileExact && (*rulesetID != "" || *coverageOnly) {
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
	return runExact(stdin, stdout, stderr, *rulesetID, *coverageOnly)
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

func runExact(stdin io.Reader, stdout, stderr io.Writer, rulesetID string, coverageOnly bool) int {
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
	blockers := compilation.Blockers()
	report := exactReport{
		Profile:      compilation.Profile(),
		RulesetID:    rulesetID,
		Compiled:     compilation.Compiled(),
		CanApply:     compilation.CanApply(),
		SourceSHA256: source.SourceSHA256,
	}
	if coverageOnly {
		coverage := summarizeExactCoverage(source, blockers)
		report.Coverage = &coverage
	} else {
		report.Source = source
		report.Blockers = blockers
	}
	if compilation.Compiled() {
		report.ContentSHA256 = compilation.ContentSHA256()
		if !coverageOnly {
			report.Bindings = compilation.Bindings()
			report.Content = json.RawMessage(compilation.ContentJSON())
		}
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

func summarizeExactCoverage(source *routeros.Preview, blockers []routeros.CompileBlocker) exactCoverage {
	coverage := exactCoverage{}
	diagnosticCounts := make(map[string]int)
	blockerCounts := make(map[string]int)
	blockedEntries := make(map[int]struct{})
	for _, diagnostic := range source.Diagnostics {
		diagnosticCounts[diagnostic.Code]++
	}
	coverage.SourceEntries = len(source.Entries)
	for _, entry := range source.Entries {
		if entry.Classification == "exact_record_candidate" {
			coverage.ParserExactRecordCandidates++
		} else {
			coverage.ParserUnsupportedEntries++
		}
		for _, diagnostic := range entry.Diagnostics {
			diagnosticCounts[diagnostic.Code]++
		}
	}
	for _, blocker := range blockers {
		blockerCounts[blocker.Code]++
		if blocker.Ordinal == 0 {
			coverage.CompilerGlobalBlockers++
		} else {
			blockedEntries[blocker.Ordinal] = struct{}{}
		}
	}
	coverage.CompilerBlockedEntries = len(blockedEntries)
	coverage.DiagnosticCounts = sortedCoverageCounts(diagnosticCounts)
	coverage.BlockerCounts = sortedCoverageCounts(blockerCounts)
	return coverage
}

func sortedCoverageCounts(counts map[string]int) []exactCoverageCount {
	codes := make([]string, 0, len(counts))
	for code := range counts {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	result := make([]exactCoverageCount, 0, len(codes))
	for _, code := range codes {
		result = append(result, exactCoverageCount{Code: code, Count: counts[code]})
	}
	return result
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
