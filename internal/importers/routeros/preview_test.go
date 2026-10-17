package routeros

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLiteralPreviewPreservesOrderAndUnsupported(t *testing.T) {
	source := "# synthetic export\r\n/ip dns static\r\n" +
		"add name=example.invalid type=A address=192.0.2.1 ttl=1d disabled=no match-subdomain=no comment=\"literal # ; \\\" \\24 \\$\"\n" +
		"add name=example.invalid type=A address=192.0.2.2 ttl=5m disabled=yes\n" +
		"add regexp=\"^host[0-9]+\\\\.invalid\\$\" type=FWD forward-to=example-forwarder \\\n  ttl=1h disabled=yes\n" +
		"add name=negative.invalid type=NXDOMAIN ttl=1m disabled=no\n"
	p, err := Parse(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	if p.CanApply || len(p.Entries) != 4 || len(p.SourceSHA256) != 64 {
		t.Fatalf("bad preview: %#v", p)
	}
	if p.Entries[0].Fields["comment"] != "literal # ; \" $ $" {
		t.Fatal("escape decoding")
	}
	if p.Entries[0].Classification != "exact_record_candidate" {
		t.Fatal(p.Entries[0].Diagnostics)
	}
	if p.Entries[1].Fields["address"] != "192.0.2.2" || p.Entries[1].Fields["disabled"] != "yes" {
		t.Fatal("ordered duplicate lost")
	}
	if p.Entries[2].Fields["regexp"] != "^host[0-9]+\\.invalid$" || p.Entries[2].Fields["forward-to"] != "example-forwarder" {
		t.Fatal("unsupported data lost")
	}
	for i, e := range p.Entries {
		if e.Ordinal != i+1 {
			t.Fatal("order")
		}
	}
}

func TestRejectsSyntaxWithoutPartialPreview(t *testing.T) {
	for _, bad := range []string{
		"add name=$variable", "add name=[/system identity get name]", "add name=\"$variable\"", "add name=\"x\"y",
		"add name=one name=two", "add password=not-for-output", "set name=x", "/system script", "add comment=\"unterminated", "add comment=\"bad\\q\"",
		"add comment=\"bad\\00\"", "add comment=\"bad\\FF\"", "add name=x\\\ninvalid", "add name=x \\ #bad\n",
	} {
		t.Run(bad, func(t *testing.T) {
			p, err := Parse(strings.NewReader("/ip dns static\nadd name=valid\n" + bad))
			if err == nil || p != nil {
				t.Fatalf("accepted or partial: %v", p)
			}
			if strings.Contains(err.Error(), "not-for-output") {
				t.Fatal("input echoed")
			}
		})
	}
}

func TestCommentsSemicolonAndOmissions(t *testing.T) {
	p, err := Parse(strings.NewReader("# ignored \\\n/ip/dns/static;add name=example.invalid address=192.0.2.1 # comment\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := p.Entries[0]
	for _, key := range []string{"type", "ttl", "disabled", "match-subdomain"} {
		if _, ok := e.Fields[key]; ok {
			t.Fatal("invented default")
		}
	}
	if len(e.Diagnostics) < 4 || p.CanApply {
		t.Fatal("omissions not diagnosed")
	}
}

func TestTTLExactAndBounded(t *testing.T) {
	for value, want := range map[string]uint32{"0": 0, "300": 300, "1d": 86400, "1w2d3h4m5s": 788645, "4294967295s": 4294967295} {
		got, err := TTLSeconds(value)
		if err != nil || got != want {
			t.Fatalf("%s: %d %v", value, got, err)
		}
	}
	for _, value := range []string{"", "-1s", "1.5s", "1ms", "1s1m", "1h2", "1h1h", "4294967296s", "999999999999999999999d", "00:01:00"} {
		if _, err := TTLSeconds(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestLimitsAndDeterministicDiagnostics(t *testing.T) {
	for _, source := range []string{strings.Repeat(" ", MaxInputBytes+1), "/ip dns static\nadd comment=\"" + strings.Repeat("x", MaxValueBytes+1) + "\"", "/ip dns static\n" + strings.Repeat("add name=x\n", MaxEntries+1)} {
		if p, err := Parse(strings.NewReader(source)); err == nil || p != nil {
			t.Fatal("limit bypass")
		}
	}
	source := "/ip dns static\nadd type=MX mx-exchange=mail.invalid mx-preference=1 srv-port=5 ttl=1m\n"
	a, _ := Parse(strings.NewReader(source))
	b, _ := Parse(strings.NewReader(source))
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		t.Fatal("nondeterministic preview")
	}
}

func FuzzParseNeverApplies(f *testing.F) {
	for _, seed := range []string{"/ip dns static\nadd name=x type=A address=192.0.2.1 ttl=1d", "/ip dns static;add comment=\"\\24 # ;\"", "/ip dns static\nadd name=$x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		p, err := Parse(strings.NewReader(source))
		if err != nil && p != nil {
			t.Fatal("partial preview")
		}
		if p != nil {
			if p.CanApply || len(p.Entries) > MaxEntries {
				t.Fatal("unsafe preview")
			}
			if _, err := json.Marshal(p); err != nil {
				t.Fatal(err)
			}
		}
	})
}
