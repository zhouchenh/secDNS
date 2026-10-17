package recordset

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) *Snapshot {
	t.Helper()
	s, e := New("internal", "epoch-1", 18446744073709551615, []Record{
		{Name: " Z.Example ", Type: "txt", Values: []string{"<safe>", ""}, TTLSeconds: 0},
		{Name: "A.Example", Type: "aaaa", Values: []string{" 2001:0db8::1 "}, TTLSeconds: 300, ExpiresAt: "2000-01-01T08:00:00.123456789+08:00"},
	})
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestGoldenContent(t *testing.T) {
	s := fixture(t)
	want := `{"schema":"secdns.exact-record-set.v1","ruleset_id":"internal","records":[{"name":"a.example.","type":"AAAA","values":["2001:db8::1"],"ttl_seconds":300,"expires_at":"2000-01-01T00:00:00.123456789Z"},{"name":"z.example.","type":"TXT","values":["\u003csafe\u003e",""],"ttl_seconds":0}]}`
	if string(s.ContentJSON()) != want {
		t.Fatalf("canonical mismatch: %s", s.ContentJSON())
	}
	if s.Metadata().ContentSHA256 != "d45cbcb4d8e23818b33531c71f8d94bf4bfe407bf97d75761d8930f185a88410" {
		t.Fatal("golden digest changed")
	}
	b, e := s.MarshalJSON()
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(b, []byte(`"revision":"18446744073709551615"`)) {
		t.Fatal("revision precision lost")
	}
	p, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	if p.Metadata() != s.Metadata() {
		t.Fatal("roundtrip")
	}
	records := s.Records()
	records[0], records[1] = records[1], records[0]
	other, e := New("internal", "epoch-2", 1, records)
	if e != nil {
		t.Fatal(e)
	}
	if other.Metadata().ContentSHA256 != s.Metadata().ContentSHA256 {
		t.Fatal("content hash depends on record input order or revision metadata")
	}
}

func TestImmutableAndExpiry(t *testing.T) {
	source := []Record{{Name: "alias.example", Type: "CNAME", Values: []string{" TARGET.Example "}, TTLSeconds: 0}}
	s, e := New("x", "y", 1, source)
	if e != nil {
		t.Fatal(e)
	}
	source[0].Values[0] = "changed"
	source[0].Name = "changed"
	r, ok := s.Lookup("ALIAS.example", "cname", time.Now())
	if !ok || r.Values[0] != "target.example." || r.TTLSeconds != 0 {
		t.Fatal("input mutation")
	}
	r.Values[0] = "changed"
	s.Records()[0].Values[0] = "changed"
	b := s.ContentJSON()
	b[0] = '!'
	wire, _ := s.MarshalJSON()
	wire[0] = '!'
	r, _ = s.Lookup("alias.example", "CNAME", time.Now())
	if r.Values[0] != "target.example." || s.ContentJSON()[0] != '{' {
		t.Fatal("accessor mutation")
	}
	old := fixture(t)
	when, _ := time.Parse(time.RFC3339Nano, "2000-01-01T00:00:00.123456789Z")
	hash := old.Metadata().ContentSHA256
	if len(old.RecordsAt(when.Add(-time.Nanosecond))) != 2 || len(old.RecordsAt(when)) != 1 || len(old.Records()) != 2 {
		t.Fatal("expiry boundary")
	}
	if _, ok := old.Lookup("a.example", "AAAA", when); ok {
		t.Fatal("expired lookup")
	}
	if old.Metadata().ContentSHA256 != hash {
		t.Fatal("read changed hash")
	}
	var wg sync.WaitGroup
	for n := 0; n < 20; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				v := old.RecordsAt(when)
				v[0].Values[0] = "caller mutation"
				old.Lookup("a.example", "AAAA", when)
				old.ContentJSON()
			}
		}()
	}
	wg.Wait()
}

func TestValidationAndBounds(t *testing.T) {
	good := Record{Name: "x.example", Type: "A", Values: []string{"192.0.2.1"}}
	cases := [][]Record{
		{{Name: "", Type: "A", Values: []string{"192.0.2.1"}}},
		{{Name: "bad name", Type: "A", Values: []string{"192.0.2.1"}}},
		{{Name: `\120.example`, Type: "A", Values: []string{"192.0.2.1"}}},
		{{Name: "x.example", Type: "AAAA", Values: []string{"::ffff:192.0.2.1"}}},
		{{Name: "x.example", Type: "TXT", Values: []string{strings.Repeat("a", 256)}}},
		{{Name: "x.example", Type: "TXT", Values: []string{string([]byte{255})}}},
		{{Name: "x.example", Type: "CNAME", Values: []string{"a", "b"}}},
		{{Name: "x.example", Type: "A", Values: []string{"192.0.2.1", "192.0.2.1"}}},
		{good, good},
		{good, {Name: "X.EXAMPLE.", Type: "CNAME", Values: []string{"target"}, ExpiresAt: "2000-01-01T00:00:00Z"}},
		{{Name: "x", Type: "A", Values: []string{"192.0.2.1"}, ExpiresAt: "0001-01-01T00:00:00Z"}},
		{{Name: "x", Type: "A", Values: []string{"192.0.2.1"}, ExpiresAt: "9999-12-31T23:59:59-23:00"}},
	}
	for i, c := range cases {
		if _, e := New("x", "y", 1, c); e == nil {
			t.Fatalf("accepted case %d", i)
		}
	}
	if _, e := New("x", "y", 0, nil); e == nil {
		t.Fatal("zero revision")
	}
	if _, e := New("x/y", "y", 1, nil); e == nil {
		t.Fatal("bad id")
	}
	if _, e := New("x", "y", 1, make([]Record, MaxRecords+1)); e != ErrLimit {
		t.Fatal("record limit")
	}
	if _, e := Parse(make([]byte, MaxBytes+1)); e != ErrLimit {
		t.Fatal("byte limit")
	}
	good.Values = make([]string, MaxValues+1)
	if _, e := New("x", "y", 1, []Record{good}); e != ErrLimit {
		t.Fatal("value limit")
	}
}

func TestAggregateLimits(t *testing.T) {
	records := make([]Record, MaxRecords)
	for i := range records {
		records[i] = Record{Name: fmt.Sprintf("n%d.invalid", i), Type: "TXT"}
		for n := 0; n < 11; n++ {
			records[i].Values = append(records[i].Values, fmt.Sprint(n))
		}
	}
	if _, e := New("x", "y", 1, records); e != ErrLimit {
		t.Fatal("total value limit not enforced", e)
	}
	records = make([]Record, 1000)
	for i := range records {
		records[i] = Record{Name: fmt.Sprintf("n%d.invalid", i), Type: "TXT"}
		for n := 0; n < 20; n++ {
			records[i].Values = append(records[i].Values, fmt.Sprint(n)+strings.Repeat("x", 250))
		}
	}
	if _, e := New("x", "y", 1, records); e != ErrLimit {
		t.Fatal("aggregate byte limit not enforced", e)
	}
}

func TestTXTRepeatedChunks(t *testing.T) {
	values := []string{"ab", "ab", "", ""}
	s, e := New("x", "y", 1, []Record{{Name: "txt.invalid", Type: "TXT", Values: values}})
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := s.MarshalJSON()
	p, e := Parse(wire)
	if e != nil {
		t.Fatal(e)
	}
	got := p.Records()[0].Values
	if len(got) != len(values) {
		t.Fatal("TXT chunks changed")
	}
	for i := range values {
		if got[i] != values[i] {
			t.Fatal("TXT order changed")
		}
	}
}

func TestStrictWire(t *testing.T) {
	s := fixture(t)
	wire, _ := s.MarshalJSON()
	base := string(wire)
	for _, raw := range []string{
		strings.Replace(base, `"revision":"18446744073709551615"`, `"revision":"01"`, 1),
		strings.Replace(base, `"revision":"18446744073709551615"`, `"revision":1`, 1),
		strings.Replace(base, `"revision":"18446744073709551615"`, `"revision":"18446744073709551616"`, 1),
		strings.Replace(base, `"schema":`, `"Schema":`, 1),
		strings.Replace(base, `"schema":`, `"unknown":1,"schema":`, 1),
		strings.Replace(base, `"lineage_id":"epoch-1"`, `"lineage_id":"epoch-1","lineage_id":"epoch-2"`, 1),
		strings.Replace(base, `"ttl_seconds":300`, `"ttl_seconds":null`, 1),
		strings.Replace(base, `"values":["2001:db8::1"]`, `"values":[null]`, 1),
		strings.Replace(base, `"ttl_seconds":300`, `"ttl_seconds":301`, 1),
		base + ` {}`, `null`,
	} {
		if _, e := Parse([]byte(raw)); e == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
	empty, e := New("x", "y", 1, nil)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ = empty.MarshalJSON()
	if !bytes.Contains(wire, []byte(`"records":[]`)) {
		t.Fatal("empty list canonicalization")
	}
	if _, e = Parse(wire); e != nil {
		t.Fatal(e)
	}
}

func FuzzParse(f *testing.F) {
	s, _ := New("test", "epoch", 1, []Record{{Name: "test.invalid", Type: "A", Values: []string{"192.0.2.1"}, TTLSeconds: 0}})
	wire, _ := s.MarshalJSON()
	f.Add(wire)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, e := Parse(raw)
		if e != nil {
			return
		}
		b, e := json.Marshal(s)
		if e != nil {
			t.Fatal(e)
		}
		p, e := Parse(b)
		if e != nil || p.Metadata() != s.Metadata() {
			t.Fatal("accepted snapshot not roundtrippable")
		}
		if len(b) > MaxBytes {
			t.Fatal("wire limit")
		}
	})
}

func TestSurrogateEscapesNeverReplaceData(t *testing.T) {
	s, e := New("x", "y", 1, []Record{{Name: "txt.invalid", Type: "TXT", Values: []string{"�"}}})
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := s.MarshalJSON()
	if _, e := Parse(wire); e != nil {
		t.Fatal("literal replacement character invalid", e)
	}
	for _, escape := range []string{`\ud800`, `\udfff`, `\ud800\ud800`, `\ud800x`} {
		bad := bytes.Replace(wire, []byte("�"), []byte(escape), 1)
		if _, e := Parse(bad); e == nil {
			t.Fatal("lossy surrogate accepted")
		}
	}
	emoji, e := New("x", "y", 1, []Record{{Name: "txt.invalid", Type: "TXT", Values: []string{"😀", `\ud800`}}})
	if e != nil {
		t.Fatal(e)
	}
	wire, _ = emoji.MarshalJSON()
	wire = bytes.Replace(wire, []byte("😀"), []byte(`\ud83d\ude00`), 1)
	parsed, e := Parse(wire)
	if e != nil {
		t.Fatal("valid surrogate pair rejected", e)
	}
	if parsed.Records()[0].Values[0] != "😀" || parsed.Records()[0].Values[1] != `\ud800` {
		t.Fatal("escape data changed")
	}
}
