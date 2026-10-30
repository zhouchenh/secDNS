package recordset

import (
	"strings"
	"testing"
)

func TestReplacementConfirmRemovals(t *testing.T) {
	plain, err := ParseReplacement([]byte(replacementGood))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plain.ConfirmRemovals(); ok {
		t.Fatal("request without confirm_removals reports one")
	}
	with := func(v string) string {
		return strings.Replace(replacementGood, `"operation_id":"op"`, `"operation_id":"op","confirm_removals":`+v, 1)
	}
	for v, want := range map[string]int{"0": 0, "5": 5, "44": 44, "1048576": 1 << 20} {
		r, err := ParseReplacement([]byte(with(v)))
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if n, ok := r.ConfirmRemovals(); !ok || n != want {
			t.Fatalf("%s: got %d %v", v, n, ok)
		}
	}
	for _, bad := range []string{`-1`, `1.0`, `1e2`, `05`, `"5"`, `null`, `true`, `1048577`, `99999999`, `[]`} {
		if _, err := ParseReplacement([]byte(with(bad))); err == nil {
			t.Fatalf("accepted confirm_removals %s", bad)
		}
	}
	dup := strings.Replace(with("1"), `"operation_id":"op"`, `"operation_id":"op","confirm_removals":1`, 1)
	if _, err := ParseReplacement([]byte(dup)); err == nil {
		t.Fatal("accepted duplicate confirm_removals")
	}
}
