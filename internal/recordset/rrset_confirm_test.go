package recordset

import "testing"

// confirm_removals on an RRset request: deletion only, 0 or 1, never part of the canonical
// request (so retries, receipts and digests are unchanged by it).
func TestRRsetMutationConfirmRemovals(t *testing.T) {
	const head = `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"2"},"operation_id":"op",`
	del := head + `"action":"delete","key":{"name":"a.invalid.","type":"A"}`
	plain, err := ParseRRsetMutation([]byte(del + `}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, stated := plain.ConfirmRemovals(); stated {
		t.Fatal("unstated count reported")
	}
	for _, c := range []struct {
		extra string
		n     int
	}{{`,"confirm_removals":0`, 0}, {`,"confirm_removals":1`, 1}} {
		m, err := ParseRRsetMutation([]byte(del + c.extra + `}`))
		if err != nil {
			t.Fatal(c.extra, err)
		}
		if n, stated := m.ConfirmRemovals(); !stated || n != c.n {
			t.Fatal(c.extra, n, stated)
		}
		a, _ := plain.CanonicalJSON()
		b, _ := m.CanonicalJSON()
		if string(a) != string(b) {
			t.Fatalf("confirmation changed the canonical request: %s vs %s", a, b)
		}
	}
	for _, bad := range []string{
		del + `,"confirm_removals":2}`,
		del + `,"confirm_removals":"1"}`,
		del + `,"confirm_removals":01}`,
		del + `,"confirm_removals":null}`,
		del + `,"confirm_removals":1,"confirm_removals":1}`,
		head + `"action":"upsert","record":{"name":"a.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":1},"confirm_removals":0}`,
	} {
		if _, err := ParseRRsetMutation([]byte(bad)); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	if n, stated := plain.WithConfirmRemovals(1, true).ConfirmRemovals(); n != 1 || !stated {
		t.Fatal("WithConfirmRemovals")
	}
}
