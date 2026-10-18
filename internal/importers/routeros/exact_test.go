package routeros_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/zhouchenh/secDNS/internal/importers/routeros"
	"github.com/zhouchenh/secDNS/internal/recordset"
)

const section = "/ip dns static\n"

func aRow(name string) string {
	return "add name=" + name + " type=A address=192.0.2.1 ttl=1m disabled=no match-subdomain=no\n"
}

func cnameRow(name, target string) string {
	return "add name=" + name + " type=CNAME cname=" + target + " ttl=1m disabled=no match-subdomain=no\n"
}

func assertNoCandidate(t *testing.T, c *routeros.ExactCompilation) {
	t.Helper()
	if c == nil || c.Compiled() || c.CanApply() || c.Records() != nil || c.ContentJSON() != nil || c.ContentSHA256() != "" || c.Bindings() != nil {
		t.Fatal("refusal exposed a candidate")
	}
}

func TestCompileExactGoldenCanonicalContent(t *testing.T) {
	source := section +
		"add name=SHARED.example.invalid type=AAAA address=2001:0db8:0:0::1 ttl=4294967295s disabled=no match-subdomain=no comment=\"six\"\n" +
		"add name=shared.example.invalid. type=A address=192.0.2.1 ttl=0 disabled=no match-subdomain=no\n" +
		"add name=Alias.example.invalid type=CNAME cname=Z.example.invalid ttl=1w2d3h4m5s disabled=no match-subdomain=no comment=\"\"\n"
	c, err := routeros.CompileExact(strings.NewReader(source), "import.test")
	if err != nil || !c.Compiled() || c.CanApply() || c.Profile() != routeros.ExactProfile {
		t.Fatalf("compile: %v", err)
	}
	want := []recordset.Record{
		{Name: "alias.example.invalid.", Type: "CNAME", Values: []string{"z.example.invalid."}, TTLSeconds: 788645},
		{Name: "shared.example.invalid.", Type: "A", Values: []string{"192.0.2.1"}, TTLSeconds: 0},
		{Name: "shared.example.invalid.", Type: "AAAA", Values: []string{"2001:db8::1"}, TTLSeconds: 4294967295},
	}
	if !reflect.DeepEqual(c.Records(), want) {
		t.Fatalf("records: %#v", c.Records())
	}
	canonical := `{"schema":"secdns.exact-record-set.v1","ruleset_id":"import.test","records":[{"name":"alias.example.invalid.","type":"CNAME","values":["z.example.invalid."],"ttl_seconds":788645},{"name":"shared.example.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":0},{"name":"shared.example.invalid.","type":"AAAA","values":["2001:db8::1"],"ttl_seconds":4294967295}]}`
	sum := sha256.Sum256([]byte(canonical))
	if string(c.ContentJSON()) != canonical || c.ContentSHA256() != hex.EncodeToString(sum[:]) {
		t.Fatal("canonical bytes/digest differ from the fixed golden")
	}
	sealed, err := recordset.New("import.test", "unrelated-lineage", 900, want)
	if err != nil || !bytes.Equal(c.ContentJSON(), sealed.ContentJSON()) {
		t.Fatal("canonical recordset parity")
	}
	bindings := []routeros.ExactBinding{{Ordinal: 3, Name: "alias.example.invalid.", Type: "CNAME"}, {Ordinal: 2, Name: "shared.example.invalid.", Type: "A"}, {Ordinal: 1, Name: "shared.example.invalid.", Type: "AAAA"}}
	if !reflect.DeepEqual(c.Bindings(), bindings) || c.Preview().CanApply {
		t.Fatal("provenance or apply flag")
	}
	for _, forbidden := range []string{"expires_at", "lineage", "revision", "compiler-validation"} {
		wire, _ := json.Marshal(c)
		if bytes.Contains(c.ContentJSON(), []byte(forbidden)) || bytes.Contains(wire, []byte(forbidden)) {
			t.Fatal("scratch identity/expiry was published")
		}
	}
}

func TestCompileExactPrimaryRefusalsAndNoMixedSubset(t *testing.T) {
	base := aRow("second.invalid")
	tests := []struct{ name, row, code string }{
		{"missing-type", strings.Replace(base, "type=A ", "", 1), "defaults_missing"},
		{"missing-ttl", strings.Replace(base, "ttl=1m ", "", 1), "defaults_missing"},
		{"missing-disabled", strings.Replace(base, "disabled=no ", "", 1), "defaults_missing"},
		{"missing-match", strings.Replace(base, " match-subdomain=no", "", 1), "defaults_missing"},
		{"disabled", strings.Replace(base, "disabled=no", "disabled=yes", 1), "disabled_not_enabled"},
		{"invalid-boolean", strings.Replace(base, "disabled=no", "disabled=maybe", 1), "disabled_not_enabled"},
		{"fwd", strings.Replace(base, "type=A address=192.0.2.1", "type=FWD forward-to=target.invalid", 1), "unsupported_type"},
		{"negative", strings.Replace(base, "type=A address=192.0.2.1", "type=NXDOMAIN", 1), "unsupported_type"},
		{"lowercase-type", strings.Replace(base, "type=A", "type=a", 1), "unsupported_type"},
		{"regexp", strings.TrimSpace(base) + " regexp=\"^x\"\n", "matching_policy_not_exact"},
		{"empty-regexp", strings.TrimSpace(base) + " regexp=\"\"\n", "matching_policy_not_exact"},
		{"subdomain", strings.Replace(base, "match-subdomain=no", "match-subdomain=yes", 1), "matching_policy_not_exact"},
		{"other-field-empty", strings.TrimSpace(base) + " address-list=\"\"\n", "fields_not_exact"},
		{"conflicting-field", strings.TrimSpace(base) + " cname=target.invalid\n", "fields_not_exact"},
		{"ttl-fraction", strings.Replace(base, "ttl=1m", "ttl=1.5s", 1), "ttl_not_exact"},
		{"ttl-order", strings.Replace(base, "ttl=1m", "ttl=1s1m", 1), "ttl_not_exact"},
		{"ttl-overflow", strings.Replace(base, "ttl=1m", "ttl=4294967296", 1), "ttl_not_exact"},
		{"missing-name", strings.Replace(base, "name=second.invalid ", "", 1), "record_invalid"},
		{"empty-name", strings.Replace(base, "name=second.invalid", "name=\"\"", 1), "record_invalid"},
		{"wrong-family", strings.Replace(base, "type=A", "type=AAAA", 1), "record_invalid"},
		{"name-whitespace", strings.Replace(base, "name=second.invalid", "name=\" second.invalid\"", 1), "record_invalid"},
		{"address-whitespace", strings.Replace(base, "address=192.0.2.1", "address=\"192.0.2.1 \"", 1), "record_invalid"},
		{"target-whitespace", cnameRow("second.invalid", `"target.invalid "`), "record_invalid"},
		{"wildcard-name", aRow("*.invalid"), "record_invalid"},
		{"wildcard-target", cnameRow("second.invalid", "*.invalid"), "record_invalid"},
		{"unicode-name", aRow("例.invalid"), "record_invalid"},
		{"escaped-name", aRow(`"a\\046invalid"`), "record_invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := routeros.CompileExact(strings.NewReader(section+aRow("first.invalid")+tt.row), "test")
			if !errors.Is(err, routeros.ErrNotExact) {
				t.Fatalf("error: %v", err)
			}
			assertNoCandidate(t, c)
			if len(c.Preview().Entries) != 2 || !reflect.DeepEqual(c.Blockers(), []routeros.CompileBlocker{{Ordinal: 2, Line: 3, Code: tt.code}}) {
				t.Fatalf("incomplete report or wrong priority: %#v", c.Blockers())
			}
			if tt.name == "disabled" && c.Preview().Entries[1].Classification != "exact_record_candidate" {
				t.Fatal("fixture no longer exercises structural candidate vs compiler refusal")
			}
		})
	}
}

func TestCompileExactCanonicalConflictsAndCycles(t *testing.T) {
	tests := []struct {
		name, rows string
		blockers   []routeros.CompileBlocker
	}{
		{"identical", aRow("x.invalid") + aRow("x.invalid"), []routeros.CompileBlocker{{Ordinal: 2, Line: 3, Code: "duplicate_owner_type", RelatedOrdinal: 1}}},
		{"different-value-ttl-alias", aRow("X.invalid") + strings.Replace(strings.Replace(aRow("x.invalid."), "192.0.2.1", "192.0.2.2", 1), "ttl=1m", "ttl=2m", 1), []routeros.CompileBlocker{{Ordinal: 2, Line: 3, Code: "duplicate_owner_type", RelatedOrdinal: 1}}},
		{"cname-duplicate", cnameRow("x.invalid", "external.invalid") + cnameRow("X.invalid.", "other.invalid"), []routeros.CompileBlocker{{Ordinal: 2, Line: 3, Code: "duplicate_owner_type", RelatedOrdinal: 1}}},
		{"coexist", cnameRow("x.invalid", "external.invalid") + aRow("x.invalid"), []routeros.CompileBlocker{{Ordinal: 1, Line: 2, Code: "cname_owner_conflict", RelatedOrdinal: 2}, {Ordinal: 2, Line: 3, Code: "cname_owner_conflict", RelatedOrdinal: 1}}},
		{"self", cnameRow("X.invalid", "x.invalid."), []routeros.CompileBlocker{{Ordinal: 1, Line: 2, Code: "cname_cycle", RelatedOrdinal: 1}}},
		{"two-cycle-with-feeder", cnameRow("feed.invalid", "x.invalid") + cnameRow("x.invalid", "y.invalid") + cnameRow("y.invalid", "x.invalid"), []routeros.CompileBlocker{{Ordinal: 2, Line: 3, Code: "cname_cycle", RelatedOrdinal: 3}, {Ordinal: 3, Line: 4, Code: "cname_cycle", RelatedOrdinal: 2}}},
		{"priority", aRow("x.invalid") + cnameRow("x.invalid", "x.invalid") + cnameRow("x.invalid", "x.invalid"), []routeros.CompileBlocker{{Ordinal: 1, Line: 2, Code: "cname_owner_conflict", RelatedOrdinal: 2}, {Ordinal: 2, Line: 3, Code: "cname_owner_conflict", RelatedOrdinal: 1}, {Ordinal: 3, Line: 4, Code: "duplicate_owner_type", RelatedOrdinal: 2}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for n := 0; n < 3; n++ {
				c, err := routeros.CompileExact(strings.NewReader(section+tt.rows), "test")
				if !errors.Is(err, routeros.ErrNotExact) {
					t.Fatal(err)
				}
				assertNoCandidate(t, c)
				if !reflect.DeepEqual(c.Blockers(), tt.blockers) {
					t.Fatalf("blockers: %#v", c.Blockers())
				}
			}
		})
	}
	if _, err := routeros.CompileExact(strings.NewReader(section+cnameRow("x.invalid", "unresolved.invalid")), "test"); err != nil {
		t.Fatal("external target must remain external", err)
	}
}

func TestCompileExactProvenanceAndCopyOwnership(t *testing.T) {
	x, y := aRow("x.invalid"), aRow("y.invalid")
	first := section + strings.TrimSpace(x) + " comment=\"\"\n" + y
	second := strings.ReplaceAll(section+y+strings.TrimSpace(x)+" comment=\"changed # ;\"\n", "\n", "\r\n")
	a, err := routeros.CompileExact(strings.NewReader(first), "test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := routeros.CompileExact(strings.NewReader(second), "test")
	if err != nil {
		t.Fatal(err)
	}
	if a.Preview().SourceSHA256 == b.Preview().SourceSHA256 || a.ContentSHA256() != b.ContentSHA256() || !bytes.Equal(a.ContentJSON(), b.ContentJSON()) || a.Bindings()[0].Ordinal != 1 || b.Bindings()[0].Ordinal != 2 {
		t.Fatal("source provenance/content identity conflated")
	}
	sum := sha256.Sum256([]byte(first))
	p := a.Preview()
	if p.SourceSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("source hash is not raw bytes")
	}
	if v, ok := p.Entries[0].Fields["comment"]; !ok || v != "" {
		t.Fatal("empty comment lost")
	}
	if _, ok := p.Entries[1].Fields["comment"]; ok {
		t.Fatal("missing comment invented")
	}
	p.Entries[0].Fields["name"] = "changed.invalid"
	p.Entries[0].Ordinal = 999
	p.Diagnostics[0].Code = "changed"
	r := a.Records()
	r[0].Name = "changed.invalid"
	r[0].Values[0] = "192.0.2.99"
	content := a.ContentJSON()
	content[0] = 'x'
	bindings := a.Bindings()
	bindings[0].Ordinal = 999
	if a.Preview().Entries[0].Fields["name"] != "x.invalid" || a.Preview().Diagnostics[0].Code != "preview_only_no_apply" || a.Records()[0].Values[0] != "192.0.2.1" || a.Bindings()[0].Ordinal != 1 || !bytes.Equal(a.ContentJSON(), b.ContentJSON()) {
		t.Fatal("successful report accessor alias")
	}
	bad, _ := routeros.CompileExact(strings.NewReader(section+strings.Replace(x, "disabled=no", "disabled=yes", 1)), "test")
	badPreview := bad.Preview()
	badPreview.Entries[0].Diagnostics[0].Code = "changed"
	blockers := bad.Blockers()
	blockers[0].Code = "changed"
	if bad.Preview().Entries[0].Diagnostics[0].Code != "disabled_entry_retained" || bad.Blockers()[0].Code != "disabled_not_enabled" {
		t.Fatal("refusal accessor alias")
	}
}

type readSpy struct{ reads int }

func (r *readSpy) Read([]byte) (int, error) { r.reads++; return 0, errors.New("private read failure") }

func TestCompileExactConfigParseAndTargetLimits(t *testing.T) {
	for _, id := range []string{"", "contains space", strings.Repeat("x", 129), "非ASCII"} {
		r := &readSpy{}
		if c, err := routeros.CompileExact(r, id); c != nil || !errors.Is(err, routeros.ErrExactConfig) || r.reads != 0 {
			t.Fatal("configuration must fail before read")
		}
	}
	for _, r := range []io.Reader{nil, &readSpy{}} {
		c, err := routeros.CompileExact(r, "test")
		var pe *routeros.ParseError
		if c != nil || !errors.As(err, &pe) || pe.Code != "input_read_failed" || strings.Contains(err.Error(), "private") {
			t.Fatal("read failure contract")
		}
	}
	for _, bad := range []string{"add unknown=private-value\n", "add name=$private\n", "add comment=\"unterminated\n"} {
		c, err := routeros.CompileExact(strings.NewReader(section+aRow("valid.invalid")+bad), "test")
		var pe *routeros.ParseError
		if c != nil || !errors.As(err, &pe) || strings.Contains(err.Error(), "private") {
			t.Fatal("partial parse or reflected input")
		}
	}
	c, err := routeros.CompileExact(strings.NewReader(section), "test")
	if !errors.Is(err, routeros.ErrNotExact) || !reflect.DeepEqual(c.Blockers(), []routeros.CompileBlocker{{Code: "empty_source"}}) {
		t.Fatal("empty export")
	}
	assertNoCandidate(t, c)
	c, err = routeros.CompileExact(strings.NewReader(section+cnameRow("x.invalid", strings.Repeat("a", 256))), "test")
	if !errors.Is(err, routeros.ErrExactLimit) || c.Preview() == nil || c.Blockers()[0].Code != "target_limit" {
		t.Fatal("target limit error/report", err)
	}
	assertNoCandidate(t, c)
	var absent *routeros.ExactCompilation
	if absent.Compiled() || absent.Preview() != nil || absent.Records() != nil || absent.Blockers() != nil {
		t.Fatal("nil accessors")
	}
}

func TestCompileExactParserBoundaries(t *testing.T) {
	base := section + aRow("x.invalid")
	padding := routeros.MaxInputBytes - len(base)
	exactInput := base + strings.Repeat("#\n", padding/2) + strings.Repeat("\n", padding%2)
	exactToken := base[:len(base)-1] + " comment=\"" + strings.Repeat("x", routeros.MaxValueBytes-len("comment=")) + "\"\n"
	row := strings.TrimSuffix(aRow("x.invalid"), "\n")
	exactCommand := section + row + strings.Repeat(" ", routeros.MaxLogicalLineBytes-len(row)) + "\n"
	for name, source := range map[string]string{"input": exactInput, "token": exactToken, "command": exactCommand} {
		t.Run(name, func(t *testing.T) {
			if _, err := routeros.CompileExact(strings.NewReader(source), "test"); err != nil {
				t.Fatal("exact boundary", err)
			}
		})
	}
	for name, source := range map[string]string{
		"input":   exactInput + "\n",
		"token":   strings.Replace(exactToken, "\"\n", "x\"\n", 1),
		"command": strings.TrimSuffix(exactCommand, "\n") + " \n",
		"entries": section + strings.Repeat(aRow("x.invalid"), routeros.MaxEntries+1),
	} {
		t.Run("over-"+name, func(t *testing.T) {
			c, err := routeros.CompileExact(strings.NewReader(source), "test")
			var pe *routeros.ParseError
			if c != nil || !errors.As(err, &pe) {
				t.Fatal("over-bound input returned report/candidate", err)
			}
		})
	}
}

func TestCompileExactMaximumChainsAndBoundedCollisions(t *testing.T) {
	// No timing assertion: normal test timeout bounds regressions without relying on host speed.
	for _, cycle := range []bool{false, true} {
		var source strings.Builder
		source.WriteString(section)
		for i := 0; i < routeros.MaxEntries; i++ {
			target := fmt.Sprintf("n%d.invalid", i+1)
			if cycle && i == routeros.MaxEntries-1 {
				target = "n0.invalid"
			}
			source.WriteString(cnameRow(fmt.Sprintf("n%d.invalid", i), target))
		}
		c, err := routeros.CompileExact(strings.NewReader(source.String()), "test")
		if cycle {
			if !errors.Is(err, routeros.ErrNotExact) || len(c.Blockers()) != routeros.MaxEntries {
				t.Fatal("maximum cycle", err)
			}
			assertNoCandidate(t, c)
			for i, b := range c.Blockers() {
				if b.Code != "cname_cycle" || b.Ordinal != i+1 || b.RelatedOrdinal != (i+1)%routeros.MaxEntries+1 {
					t.Fatal("cycle provenance", b)
				}
			}
		} else if err != nil || len(c.Records()) != routeros.MaxEntries {
			t.Fatal("maximum path", err)
		}
	}
	source := section + strings.Repeat(aRow("same.invalid"), routeros.MaxEntries)
	a, err := routeros.CompileExact(strings.NewReader(source), "test")
	b, _ := routeros.CompileExact(strings.NewReader(source), "test")
	if !errors.Is(err, routeros.ErrNotExact) || len(a.Blockers()) != routeros.MaxEntries-1 || len(a.Blockers()) > routeros.MaxCompileBlockers || !reflect.DeepEqual(a.Blockers(), b.Blockers()) {
		t.Fatal("bounded deterministic collisions")
	}
	assertNoCandidate(t, a)
	for i, blocker := range a.Blockers() {
		if blocker.Ordinal != i+2 || blocker.RelatedOrdinal != 1 || blocker.Code != "duplicate_owner_type" {
			t.Fatal("collision ordering", blocker)
		}
	}
}

func TestCompileExactAnonymizedInventoryCannotDropRegexp(t *testing.T) {
	var source strings.Builder
	source.WriteString(section)
	// Synthetic counts only: 98 A (one unnamed regexp), 10 AAAA, 33 CNAME.
	for i := 0; i < 97; i++ {
		source.WriteString(aRow(fmt.Sprintf("a%d.invalid", i)))
	}
	source.WriteString("add regexp=\"^synthetic\" type=A address=192.0.2.1 ttl=1m disabled=no match-subdomain=no\n")
	for i := 0; i < 10; i++ {
		source.WriteString(fmt.Sprintf("add name=v6-%d.invalid type=AAAA address=2001:db8::1 ttl=1m disabled=no match-subdomain=no\n", i))
	}
	for i := 0; i < 33; i++ {
		source.WriteString(cnameRow(fmt.Sprintf("alias%d.invalid", i), "external.invalid"))
	}
	c, err := routeros.CompileExact(strings.NewReader(source.String()), "test")
	if !errors.Is(err, routeros.ErrNotExact) || len(c.Preview().Entries) != 141 || !reflect.DeepEqual(c.Blockers(), []routeros.CompileBlocker{{Ordinal: 98, Line: 99, Code: "matching_policy_not_exact"}}) {
		t.Fatal("inventory-shape refusal", err)
	}
	assertNoCandidate(t, c)
}

func FuzzCompileExactNeverReturnsPartialCandidate(f *testing.F) {
	for _, s := range []string{section + aRow("x.invalid"), section + cnameRow("x.invalid", "x.invalid"), section + "add type=FWD\n", section} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, source string) {
		c, err := routeros.CompileExact(strings.NewReader(source), "fuzz")
		if c == nil {
			if err == nil {
				t.Fatal("nil success")
			}
			return
		}
		if c.CanApply() || c.Preview().CanApply || len(c.Blockers()) > routeros.MaxCompileBlockers {
			t.Fatal("unsafe report")
		}
		if err != nil {
			assertNoCandidate(t, c)
			return
		}
		if !c.Compiled() || len(c.Blockers()) != 0 || len(c.Records()) == 0 || len(c.Records()) != len(c.Preview().Entries) {
			t.Fatal("incomplete success")
		}
	})
}
