package recordset

import (
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
