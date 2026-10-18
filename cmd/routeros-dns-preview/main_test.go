package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/zhouchenh/secDNS/internal/importers/routeros"
)

const testSection = "/ip dns static\n"

func exactARow(name string) string {
	return "add name=" + name + " type=A address=192.0.2.1 ttl=1m disabled=no match-subdomain=no\n"
}

func TestRunDefaultPreviewCompatibility(t *testing.T) {
	source := testSection + exactARow("example.invalid")
	sum := sha256.Sum256([]byte(source))
	want := fmt.Sprintf(`{
  "source_sha256": %q,
  "entries": [
    {
      "ordinal": 1,
      "line": 2,
      "fields": {
        "address": "192.0.2.1",
        "disabled": "no",
        "match-subdomain": "no",
        "name": "example.invalid",
        "ttl": "1m",
        "type": "A"
      },
      "classification": "exact_record_candidate"
    }
  ],
  "diagnostics": [
    {
      "line": 0,
      "column": 0,
      "code": "preview_only_no_apply"
    }
  ],
  "can_apply": false
}
`, hex.EncodeToString(sum[:]))
	var stdout, stderr bytes.Buffer
	if code := run(nil, strings.NewReader(source), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stdout.String() != want || stderr.Len() != 0 {
		t.Fatalf("default output changed\nwant: %s\ngot: %s\nstderr: %s", want, stdout.String(), stderr.String())
	}
}

func TestRunExactSuccess(t *testing.T) {
	source := testSection +
		"add name=V6.invalid type=AAAA address=2001:0db8::1 ttl=0 disabled=no match-subdomain=no comment=source-only\n" +
		"add name=alias.invalid type=CNAME cname=outside.invalid ttl=1h disabled=no match-subdomain=no\n"
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--compile-exact", "--ruleset-id", "cli.test"}, strings.NewReader(source), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stderr.Len() != 0 || stdout.Len() > maxExactReportBytes {
		t.Fatalf("stderr or output bound: %q / %d", stderr.String(), stdout.Len())
	}
	var report exactReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(source))
	if report.Profile != routeros.ExactProfile || report.RulesetID != "cli.test" || !report.Compiled || report.CanApply || report.Source == nil || report.Source.CanApply || report.SourceSHA256 != hex.EncodeToString(sum[:]) || report.Source.SourceSHA256 != report.SourceSHA256 {
		t.Fatalf("identity/status report: %#v", report)
	}
	if len(report.Source.Entries) != 2 || len(report.Bindings) != 2 || report.ContentSHA256 == "" || len(report.Content) == 0 || len(report.Blockers) != 0 {
		t.Fatalf("incomplete success report: %#v", report)
	}
	var content struct {
		Schema    string `json:"schema"`
		RulesetID string `json:"ruleset_id"`
		Records   []struct {
			Name       string   `json:"name"`
			Type       string   `json:"type"`
			Values     []string `json:"values"`
			TTLSeconds uint32   `json:"ttl_seconds"`
		} `json:"records"`
	}
	if err := json.Unmarshal(report.Content, &content); err != nil {
		t.Fatal(err)
	}
	if content.RulesetID != "cli.test" || len(content.Records) != 2 || content.Records[0].Name != "alias.invalid." || content.Records[1].Values[0] != "2001:db8::1" {
		t.Fatalf("canonical content: %#v", content)
	}
	for _, forbidden := range []string{`"lineage_id"`, `"revision"`, `"expires_at"`, "compiler-validation"} {
		if bytes.Contains(stdout.Bytes(), []byte(forbidden)) {
			t.Fatalf("published scratch field %q", forbidden)
		}
	}
}

func TestRunExactMixedRefusalHasNoCandidate(t *testing.T) {
	source := testSection + exactARow("valid.invalid") +
		"add regexp=\"^synthetic\" type=A address=192.0.2.2 ttl=1m disabled=no match-subdomain=no\n"
	var stdout, stderr bytes.Buffer
	code := run([]string{"--compile-exact", "--ruleset-id=mixed.test"}, strings.NewReader(source), &stdout, &stderr)
	if code != 1 || stderr.String() != routeros.ErrNotExact.Error()+"\n" {
		t.Fatalf("exit/stderr: %d %q", code, stderr.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"content", "content_sha256", "bindings"} {
		if _, ok := raw[absent]; ok {
			t.Fatalf("refusal exposed %s", absent)
		}
	}
	var report exactReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	want := []routeros.CompileBlocker{{Ordinal: 2, Line: 3, Code: "matching_policy_not_exact"}}
	if report.Compiled || report.CanApply || report.Source == nil || len(report.Source.Entries) != 2 || !reflect.DeepEqual(report.Blockers, want) || len(report.Content) != 0 || report.ContentSHA256 != "" || report.Bindings != nil {
		t.Fatalf("unsafe refusal report: %#v", report)
	}
}

type readCounter struct{ reads int }

func (r *readCounter) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("private input failure")
}

func TestRunRejectsInvalidOptionsAndConfigurationBeforeRead(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		stderr string
	}{
		{"unknown", []string{"--unknown=private"}, invalidOptionsMessage + "\n"},
		{"positional", []string{"private-file.rsc"}, invalidOptionsMessage + "\n"},
		{"ruleset-without-mode", []string{"--ruleset-id", "private"}, invalidOptionsMessage + "\n"},
		{"missing-ruleset", []string{"--compile-exact"}, invalidConfigMessage + "\n"},
		{"invalid-ruleset", []string{"--compile-exact", "--ruleset-id", "contains space"}, invalidConfigMessage + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &readCounter{}
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, reader, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != tt.stderr || reader.reads != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q reads=%d", code, stdout.String(), stderr.String(), reader.reads)
			}
		})
	}
}

func TestRunExactMalformedInputHasFixedError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--compile-exact", "--ruleset-id", "test"}, strings.NewReader(testSection+"add comment=\"private\n"), &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || stderr.String() != "RouterOS export line 3 column 1: unterminated_string\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

type rejectingWriter struct{}

func (rejectingWriter) Write([]byte) (int, error) { return 0, errors.New("private output failure") }

func TestRunOutputErrorsAreFixed(t *testing.T) {
	source := testSection + exactARow("x.invalid")
	for _, tt := range []struct {
		name   string
		args   []string
		stderr string
	}{
		{"preview", nil, "could not write preview\n"},
		{"exact", []string{"--compile-exact", "--ruleset-id", "test"}, "could not write exact compilation\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := run(tt.args, strings.NewReader(source), rejectingWriter{}, &stderr); code != 1 || stderr.String() != tt.stderr {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
		})
	}
}

func TestWriteExactReportEnforcesLimitBeforeWrite(t *testing.T) {
	report := exactReport{
		Profile:   routeros.ExactProfile,
		RulesetID: "test",
		Source: &routeros.Preview{Entries: []routeros.Entry{{
			Fields: map[string]string{"comment": strings.Repeat("x", maxExactReportBytes)},
		}}},
	}
	var output bytes.Buffer
	if err := writeExactReport(&output, report); err == nil || output.Len() != 0 {
		t.Fatalf("limit error=%v output=%d", err, output.Len())
	}
}
