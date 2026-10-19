package recordstore

import (
	"database/sql"
	"errors"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"math"
	"sync"
	"testing"
)

func mutation(rev uint64, id string) recordset.RRsetMutation {
	return recordset.RRsetMutation{RulesetID: "test", LineageID: "lineage", Revision: rev, OperationID: id, Action: "upsert", Record: &recordset.Record{Name: "target.invalid", Type: "TXT", Values: []string{"z", "a", "z"}, TTLSeconds: 0}}
}
func TestRRsetMutationPreservationReplayAndProvenance(t *testing.T) {
	bothRRsets(t, func(t *testing.T, s *VersionedStore) {
		initial, _ := s.Acquire()
		records := append(exactRecords("192.0.2.1"), recordset.Record{Name: "expired.invalid.", Type: "A", Values: []string{"192.0.2.2"}, TTLSeconds: 0, ExpiresAt: "2000-01-01T00:00:00Z"})
		if _, e := s.ReplaceWithOperatorSuppliedProvenance(expectation(initial), "import", records, operatorProvenance(t, records, "a")); e != nil {
			t.Fatal(e)
		}
		old, _ := s.Acquire()
		m := mutation(2, "up")
		receipt, e := s.MutateRRset(m)
		if e != nil || receipt.Revision != 3 {
			t.Fatal(receipt, e)
		}
		now, _ := s.Acquire()
		if len(now.Records()) != 3 || len(old.Records()) != 2 {
			t.Fatal("lost expired or immutable rows")
		}
		if _, ok := now.OperatorSuppliedProvenance(); ok {
			t.Fatal("stale provenance")
		}
		if _, ok := old.OperatorSuppliedProvenance(); !ok {
			t.Fatal("old view changed")
		}
		rr, ok := now.Lookup("target.invalid", "TXT")
		if !ok || rr.TTLSeconds != 0 || len(rr.Values) != 3 || rr.Values[0] != "z" || rr.Values[1] != "a" {
			t.Fatal(rr)
		}
		if _, e = s.Replace(expectation(now), "later", exactRecords("192.0.2.3")); e != nil {
			t.Fatal(e)
		}
		replay, e := s.MutateRRset(m)
		if e != nil || replay != receipt {
			t.Fatal("replay after edit", e)
		}
		cases := []recordset.RRsetMutation{mutation(3, "up"), mutation(2, "up")}
		cases[1].Record.Name = "other.invalid"
		for _, c := range cases {
			if _, e = s.MutateRRset(c); !errors.Is(e, ErrOperationConflict) {
				t.Fatal(e)
			}
		}
		del := recordset.RRsetMutation{RulesetID: "test", LineageID: "lineage", Revision: 2, OperationID: "up", Action: "delete", Key: &recordset.RecordKey{Name: "target.invalid", Type: "TXT"}}
		if _, e = s.MutateRRset(del); !errors.Is(e, ErrOperationConflict) {
			t.Fatal(e)
		}
		current, _ := s.Acquire()
		if _, e = s.Replace(expectation(current), "up", current.Records()); !errors.Is(e, ErrOperationConflict) {
			t.Fatal("cross replace", e)
		}
		del.OperationID = "delete"
		del.Revision = 4
		del.Key = &recordset.RecordKey{Name: " HOST.INVALID ", Type: " a "}
		if r, e := s.MutateRRset(del); e != nil || r.Revision != 5 {
			t.Fatal(r, e)
		}
		del.OperationID = "missing"
		del.Revision = 5
		if r, e := s.MutateRRset(del); e != nil || r.Revision != 6 {
			t.Fatal("missing advances", r, e)
		}
	})
}
func TestRRsetMutationConflictFailureAndHints(t *testing.T) {
	bothRRsets(t, func(t *testing.T, s *VersionedStore) {
		v, _ := s.Acquire()
		records := exactRecords("192.0.2.1")
		if _, e := s.ReplaceWithOperatorSuppliedProvenance(expectation(v), "import", records, operatorProvenance(t, records, "b")); e != nil {
			t.Fatal(e)
		}
		sub, e := s.SubscribeRevisions()
		if e != nil {
			t.Fatal(e)
		}
		defer sub.Close()
		receiveRevision(t, sub)
		bad := mutation(2, "bad")
		bad.Record = &recordset.Record{Name: "host.invalid", Type: "CNAME", Values: []string{"else.invalid"}, TTLSeconds: 1}
		if _, e := s.MutateRRset(bad); !errors.Is(e, ErrVersionedInput) {
			t.Fatal(e)
		}
		assertNoRevision(t, sub)
		s.hooks.beforeCommit = func(*sql.Tx) error { return errors.New("injected") }
		if _, e := s.MutateRRset(mutation(2, "fail")); !errors.Is(e, ErrVersionedStorage) {
			t.Fatal(e)
		}
		v, _ = s.Acquire()
		if v.Metadata().Revision != 2 {
			t.Fatal("published failed generation")
		}
		if _, ok := v.OperatorSuppliedProvenance(); !ok {
			t.Fatal("failed provenance changed")
		}
		if _, ok := s.receipts["fail"]; ok {
			t.Fatal("failed receipt")
		}
		assertNoRevision(t, sub)
		s.hooks.beforeCommit = nil
		r, e := s.MutateRRset(mutation(2, "fail"))
		if e != nil {
			t.Fatal(e)
		}
		if n := receiveRevision(t, sub); n.Revision != r.Revision {
			t.Fatal(n)
		}
		assertNoRevision(t, sub)
		if _, e := s.MutateRRset(mutation(2, "fail")); e != nil {
			t.Fatal(e)
		}
		assertNoRevision(t, sub)
	})
}
func TestRRsetMutationSQLiteRestart(t *testing.T) {
	path := dbPath(t)
	s := openRRsetTest(t, path)
	m := mutation(1, "up")
	first, e := s.MutateRRset(m)
	if e != nil {
		t.Fatal(e)
	}
	v, _ := s.Acquire()
	if _, e = s.Replace(expectation(v), "later", exactRecords("192.0.2.1")); e != nil {
		t.Fatal(e)
	}
	s.Close()
	reopened := openVersionedTest(t, path)
	retry, e := reopened.MutateRRset(m)
	if e != nil || retry != first {
		t.Fatal(retry, e)
	}
	v, _ = reopened.Acquire()
	if v.Metadata().Revision != 3 || len(v.Records()) != 1 {
		t.Fatal("retry reapplied")
	}
}
func TestRRsetMutationContendingCAS(t *testing.T) {
	bothRRsets(t, func(t *testing.T, s *VersionedStore) {
		start := make(chan struct{})
		out := make(chan error, 2)
		var wg sync.WaitGroup
		for _, id := range []string{"one", "two"} {
			wg.Add(1)
			go func(id string) { defer wg.Done(); <-start; _, e := s.MutateRRset(mutation(1, id)); out <- e }(id)
		}
		close(start)
		wg.Wait()
		close(out)
		passed, conflicted := 0, 0
		for e := range out {
			if e == nil {
				passed++
			} else if errors.Is(e, ErrRevisionConflict) {
				conflicted++
			} else {
				t.Fatal(e)
			}
		}
		if passed != 1 || conflicted != 1 {
			t.Fatal(passed, conflicted)
		}
	})
}
func TestRRsetMutationLimitsAndClosed(t *testing.T) {
	s, _ := NewVersionedMemory(enrollment)
	for i := 0; i < MaxOperationReceipts; i++ {
		s.receipts[string(rune(i))] = Receipt{}
	}
	if _, e := s.MutateRRset(mutation(1, "op")); !errors.Is(e, ErrReceiptCapacity) {
		t.Fatal(e)
	}
	s.receipts = map[string]Receipt{}
	snap, _ := recordset.New("test", "lineage", math.MaxUint64, nil)
	s.current.Store(&versionedGeneration{snapshot: snap})
	if _, e := s.MutateRRset(mutation(math.MaxUint64, "op")); !errors.Is(e, ErrRevisionOverflow) {
		t.Fatal(e)
	}
	s.Close()
	if _, e := s.MutateRRset(mutation(1, "op")); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
}
func TestRRsetNoOpUpsertAndDeleteReplayConflict(t *testing.T) {
	bothRRsets(t, func(t *testing.T, s *VersionedStore) {
		m := mutation(1, "first")
		a, e := s.MutateRRset(m)
		if e != nil {
			t.Fatal(e)
		}
		m.Revision = 2
		m.OperationID = "identical"
		b, e := s.MutateRRset(m)
		if e != nil || b.Revision != 3 || b.ContentSHA256 != a.ContentSHA256 {
			t.Fatal("no-op must advance", b, e)
		}
		d := recordset.RRsetMutation{RulesetID: "test", LineageID: "lineage", Revision: 3, OperationID: "delete", Action: "delete", Key: &recordset.RecordKey{Name: "TARGET.INVALID", Type: " txt "}}
		first, e := s.MutateRRset(d)
		if e != nil {
			t.Fatal(e)
		}
		retry, e := s.MutateRRset(d)
		if e != nil || retry != first {
			t.Fatal(e)
		}
		d.Key.Name = "other.invalid"
		if _, e = s.MutateRRset(d); !errors.Is(e, ErrOperationConflict) {
			t.Fatal("delete key digest", e)
		}
	})
}

func openRRsetTest(t *testing.T, path string) *VersionedStore {
	t.Helper()
	s := openVersionedTest(t, path)
	s.Close()
	if e := EnableRRsetMutationsSQLite(path, enrollment); e != nil {
		t.Fatal(e)
	}
	return openVersionedTest(t, path)
}
func bothRRsets(t *testing.T, run func(*testing.T, *VersionedStore)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		s, e := NewVersionedMemory(enrollment)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		run(t, s)
	})
	t.Run("sqlite", func(t *testing.T) { run(t, openRRsetTest(t, dbPath(t))) })
}
