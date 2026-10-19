package recordset

import (
	"strings"
	"testing"
)

func TestRRsetMutationParser(t *testing.T) {
	up := `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"1"},"operation_id":"op","action":"upsert","record":{"name":" HOST.Invalid ","type":" a ","values":["192.0.2.1"],"ttl_seconds":0}}`
	r, e := ParseRRsetMutation([]byte(up))
	if e != nil || r.Record.Name != "host.invalid." || r.Record.Type != "A" || r.Record.TTLSeconds != 0 {
		t.Fatal(r, e)
	}
	del := `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"1"},"operation_id":"op","action":"delete","key":{"name":" HOST.Invalid ","type":" txt "}}`
	r, e = ParseRRsetMutation([]byte(del))
	if e != nil || r.Key.Name != "host.invalid." || r.Key.Type != "TXT" {
		t.Fatal(r, e)
	}
	bad := []string{strings.Replace(up, `"action":"upsert"`, `"action":"upsert","action":"delete"`, 1), strings.Replace(up, `"record":`, `"key":{"name":"x","type":"A"},"record":`, 1), strings.Replace(del, `"key":`, `"record":{},"key":`, 1), strings.Replace(up, `"revision":"1"`, `"revision":1`, 1), strings.Replace(up, `"revision":"1"`, `"revision":"01"`, 1), strings.Replace(up, `"revision":"1"`, `"revision":"0"`, 1), strings.Replace(up, `"revision":"1"`, `"revision":"18446744073709551616"`, 1), strings.Replace(up, `"record":{`, `"record":null,"extra":{`, 1), strings.Replace(up, `"ttl_seconds":0`, `"ttl_seconds":0,"expires_in":5`, 1), strings.Replace(up, `HOST.Invalid`, `\ud800`, 1), strings.Replace(del, `"type":" txt "`, `"type":"MX"`, 1), strings.Replace(del, `"type":" txt "`, `"type":"TXT","type":"A"`, 1), strings.Replace(up, `"operation_id":"op"`, `"operation_id":null`, 1), strings.TrimSuffix(up, "}") + `,"operator_supplied_provenance":{}}`, up + "{}", strings.Repeat(" ", MaxBytes+1)}
	for i, input := range bad {
		if _, e := ParseRRsetMutation([]byte(input)); e == nil {
			t.Fatalf("accepted malformed %d", i)
		}
	}
}
