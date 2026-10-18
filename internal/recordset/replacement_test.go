package recordset

import (
	"encoding/json"
	"strings"
	"testing"
)

const replacementGood = `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"1"},"operation_id":"op","records":[{"name":"x.invalid","type":"TXT","values":["","x","x"],"ttl_seconds":0,"expires_at":"2000-01-01T00:00:00.123456789Z"}]}`

func TestReplacementStrictSharedDecoder(t *testing.T) {
	r, e := ParseReplacement([]byte(replacementGood))
	if e != nil {
		t.Fatal(e)
	}
	if r.Records[0].Name != "x.invalid." || len(r.Records[0].Values) != 3 || r.Records[0].TTLSeconds != 0 {
		t.Fatal(r)
	}
	for _, bad := range []string{
		strings.Replace(replacementGood, `"operation_id":"op"`, `"operation_id":"op","operation_id":"other"`, 1),
		strings.Replace(replacementGood, `"revision":"1"`, `"revision":"01"`, 1),
		strings.Replace(replacementGood, `"revision":"1"`, `"revision":"1","Revision":"1"`, 1),
		strings.Replace(replacementGood, `"values":["","x","x"]`, `"values":[null]`, 1),
		strings.Replace(replacementGood, `"values":["","x","x"]`, `"values":["\ud800"]`, 1),
		strings.Replace(replacementGood, `"records":[`, `"records":null,"extra":[`, 1),
		strings.Replace(replacementGood, `"ttl_seconds":0`, `"ttl_seconds":0,"ttl_seconds":1`, 1),
	} {
		if _, e := ParseReplacement([]byte(bad)); e == nil {
			t.Fatal("accepted malformed replacement")
		}
	}
}

func TestReplacementOperatorSuppliedProvenance(t *testing.T) {
	legacy, err := ParseReplacement([]byte(replacementGood))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := legacy.OperatorSuppliedProvenance(); ok {
		t.Fatal("legacy request acquired provenance")
	}
	snapshot, err := New(legacy.RulesetID, legacy.LineageID, legacy.Revision, legacy.Records)
	if err != nil {
		t.Fatal(err)
	}
	content := snapshot.Metadata().ContentSHA256
	source := strings.Repeat("a", 64)
	provenanceJSON := `{"profile":"` + RouterOSExactExplicitProfile + `","source_sha256":"` + source + `","content_sha256":"` + content + `"}`
	request := strings.TrimSuffix(replacementGood, "}") + `,"operator_supplied_provenance":` + provenanceJSON + `}`
	parsed, err := ParseReplacement([]byte(request))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := parsed.OperatorSuppliedProvenance()
	if !ok || p.Profile() != RouterOSExactExplicitProfile || p.SourceSHA256() != source || p.ContentSHA256() != content {
		t.Fatal(p, ok)
	}
	canonical, err := json.Marshal(p)
	if err != nil || string(canonical) != provenanceJSON {
		t.Fatal(string(canonical), err)
	}
	for _, bad := range []string{
		strings.Replace(request, content, strings.Repeat("0", 64), 1),
		strings.Replace(request, source, strings.ToUpper(source), 1),
		strings.Replace(request, RouterOSExactExplicitProfile, "other", 1),
		strings.Replace(request, `"content_sha256":"`+content+`"`, `"content_sha256":"`+content+`","extra":true`, 1),
		strings.Replace(request, provenanceJSON, "null", 1),
		strings.TrimSuffix(request, "}") + `,"operator_supplied_provenance":` + provenanceJSON + `}`,
	} {
		if _, err := ParseReplacement([]byte(bad)); err == nil {
			t.Fatal("accepted malformed operator-supplied provenance")
		}
	}
	if _, err := NewOperatorSuppliedProvenance(RouterOSExactExplicitProfile, source, strings.Repeat("A", 64)); err == nil {
		t.Fatal("constructor accepted uppercase digest")
	}
}
