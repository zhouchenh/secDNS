package recordstore

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
)

var enrollment = Enrollment{RulesetID: "test", LineageID: "lineage"}

func exactRecords(value string) []recordset.Record {
	return []recordset.Record{{Name: "host.invalid.", Type: "A", Values: []string{value}, TTLSeconds: 300}}
}

func operatorProvenance(t *testing.T, records []recordset.Record, sourceDigit string) recordset.OperatorSuppliedProvenance {
	t.Helper()
	snapshot, err := recordset.New(enrollment.RulesetID, enrollment.LineageID, 1, records)
	if err != nil {
		t.Fatal(err)
	}
	p, err := recordset.NewOperatorSuppliedProvenance(recordset.RouterOSExactExplicitProfile, strings.Repeat(sourceDigit, 64), snapshot.Metadata().ContentSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func expectation(v View) Expected {
	m := v.Metadata()
	return Expected{m.RulesetID, m.LineageID, m.Revision}
}
func openVersionedTest(t *testing.T, path string) *VersionedStore {
	t.Helper()
	s, e := OpenVersionedSQLite(path, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func bothVersioned(t *testing.T, run func(*testing.T, *VersionedStore)) {
	t.Helper()
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var s *VersionedStore
			var err error
			if kind == "memory" {
				s, err = NewVersionedMemory(enrollment)
			} else {
				s, err = OpenVersionedSQLite(dbPath(t), enrollment)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			run(t, s)
		})
	}
}
func TestVersionedCASRetryIdentityAndIsolation(t *testing.T) {
	bothVersioned(t, func(t *testing.T, s *VersionedStore) {
		v, _ := s.Acquire()
		input := exactRecords("192.0.2.1")
		first, e := s.Replace(expectation(v), "op1", input)
		if e != nil || first.Revision != 2 {
			t.Fatal(first, e)
		}
		input[0].Values[0] = "192.0.2.99"
		retry, e := s.Replace(expectation(v), "op1", exactRecords("192.0.2.1"))
		if e != nil || retry != first {
			t.Fatal(retry, e)
		}
		if _, e = s.Replace(expectation(v), "op1", exactRecords("192.0.2.2")); !errors.Is(e, ErrOperationConflict) {
			t.Fatal(e)
		}
		if _, e = s.Replace(expectation(v), "stale", nil); !errors.Is(e, ErrRevisionConflict) {
			t.Fatal(e)
		}
		current, _ := s.Acquire()
		if _, e = s.Replace(expectation(current), "op2", nil); e != nil {
			t.Fatal(e)
		}
		if retry, e = s.Replace(expectation(v), "op1", exactRecords("192.0.2.1")); e != nil || retry != first {
			t.Fatal("old receipt lost", retry, e)
		}
		record, ok := current.Lookup("host.invalid.", "A")
		if !ok || record.Values[0] != "192.0.2.1" {
			t.Fatal(record)
		}
		record.Values[0] = "192.0.2.3"
		again, _ := current.Lookup("host.invalid.", "A")
		if again.Values[0] != "192.0.2.1" {
			t.Fatal("view mutable")
		}
		bad := expectation(current)
		bad.LineageID = "wrong"
		if _, e = s.Replace(bad, "op1", nil); !errors.Is(e, ErrIdentity) {
			t.Fatal(e)
		}
		if e = s.Close(); e != nil {
			t.Fatal(e)
		}
		if _, e = s.Acquire(); !errors.Is(e, ErrClosed) {
			t.Fatal(e)
		}
		if _, e = s.Replace(expectation(current), "late", nil); !errors.Is(e, ErrClosed) {
			t.Fatal(e)
		}
		if _, ok = current.Lookup("host.invalid.", "A"); !ok {
			t.Fatal("held view closed")
		}
	})
}

func TestVersionedRequestDigestCompatibilityAndProvenanceIdentity(t *testing.T) {
	e := Expected{"r", "l", 1}
	content := strings.Repeat("a", 64)
	if got := requestDigest(e, content); got != "0233ddd6380b2d2600309ce87ad0ce7db24a59ccc6966527a390fe1e930702a7" {
		t.Fatal("legacy digest changed", got)
	}
	p, err := recordset.NewOperatorSuppliedProvenance(recordset.RouterOSExactExplicitProfile, strings.Repeat("b", 64), content)
	if err != nil {
		t.Fatal(err)
	}
	if got := requestDigestWithOperatorSuppliedProvenance(e, content, p); got != "e13f397b4b94470efe40e8f9d55bd5a4d82d20788d71afbaa708ad6d0ffe4d46" {
		t.Fatal("provenance digest changed", got)
	}
}

func TestVersionedOperatorSuppliedProvenancePublicationReplayAndClear(t *testing.T) {
	bothVersioned(t, func(t *testing.T, s *VersionedStore) {
		base, _ := s.Acquire()
		records := exactRecords("192.0.2.1")
		p := operatorProvenance(t, records, "1")
		first, err := s.ReplaceWithOperatorSuppliedProvenance(expectation(base), "with-provenance", records, p)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := first.OperatorSuppliedProvenance(); !ok || got != p {
			t.Fatal("receipt lost provenance", got, ok)
		}
		current, _ := s.Acquire()
		if got, ok := current.OperatorSuppliedProvenance(); !ok || got != p {
			t.Fatal("view lost provenance", got, ok)
		}
		if _, ok := base.OperatorSuppliedProvenance(); ok {
			t.Fatal("old pinned view changed")
		}
		replay, err := s.ReplaceWithOperatorSuppliedProvenance(expectation(base), "with-provenance", exactRecords("192.0.2.1"), p)
		if err != nil || replay != first {
			t.Fatal("exact retry changed", replay, err)
		}
		other := operatorProvenance(t, records, "2")
		if _, err = s.ReplaceWithOperatorSuppliedProvenance(expectation(base), "with-provenance", records, other); !errors.Is(err, ErrOperationConflict) {
			t.Fatal("changed provenance replay", err)
		}
		if _, err = s.Replace(expectation(base), "with-provenance", records); !errors.Is(err, ErrOperationConflict) {
			t.Fatal("present-to-absent replay", err)
		}
		if _, err = s.Replace(expectation(current), "legacy-clear", nil); err != nil {
			t.Fatal(err)
		}
		cleared, _ := s.Acquire()
		if _, ok := cleared.OperatorSuppliedProvenance(); ok {
			t.Fatal("legacy replacement retained provenance")
		}
	})
}

func TestVersionedOperatorSuppliedProvenanceAtomicGeneration(t *testing.T) {
	s, err := NewVersionedMemory(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	done := make(chan struct{})
	errorsSeen := make(chan string, 4)
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				view, acquireErr := s.Acquire()
				if acquireErr != nil {
					errorsSeen <- acquireErr.Error()
					return
				}
				records := view.Records()
				provenance, present := view.OperatorSuppliedProvenance()
				if len(records) == 0 {
					if view.Metadata().Revision != 1 || present {
						errorsSeen <- "initial generation carried provenance"
						return
					}
					continue
				}
				switch records[0].Values[0] {
				case "192.0.2.1":
					if present {
						errorsSeen <- "legacy generation carried provenance"
						return
					}
				case "192.0.2.2":
					if !present || provenance.ContentSHA256() != view.Metadata().ContentSHA256 {
						errorsSeen <- "provenance generation was torn"
						return
					}
				default:
					errorsSeen <- "unexpected published record"
					return
				}
			}
		}()
	}

	for n := 0; n < 100; n++ {
		base, acquireErr := s.Acquire()
		if acquireErr != nil {
			t.Fatal(acquireErr)
		}
		records := exactRecords("192.0.2.1")
		if n%2 == 0 {
			records = exactRecords("192.0.2.2")
			provenance := operatorProvenance(t, records, "a")
			_, err = s.ReplaceWithOperatorSuppliedProvenance(expectation(base), fmt.Sprint("atomic-", n), records, provenance)
		} else {
			_, err = s.Replace(expectation(base), fmt.Sprint("atomic-", n), records)
		}
		if err != nil {
			close(done)
			readers.Wait()
			t.Fatal(err)
		}
	}
	close(done)
	readers.Wait()
	close(errorsSeen)
	for message := range errorsSeen {
		t.Error(message)
	}
}

func TestVersionedConcurrentCAS(t *testing.T) {
	bothVersioned(t, func(t *testing.T, s *VersionedStore) {
		v, _ := s.Acquire()
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, id := range []string{"a", "b"} {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				_, e := s.Replace(expectation(v), id, exactRecords("192.0.2.1"))
				results <- e
			}(id)
		}
		wg.Wait()
		close(results)
		success, conflict := 0, 0
		for e := range results {
			if e == nil {
				success++
			} else if errors.Is(e, ErrRevisionConflict) {
				conflict++
			} else {
				t.Fatal(e)
			}
		}
		if success != 1 || conflict != 1 {
			t.Fatal(success, conflict)
		}
	})
}
func TestVersionedExpiryRetainedWithCapturedClock(t *testing.T) {
	bothVersioned(t, func(t *testing.T, s *VersionedStore) {
		now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		s.now = func() time.Time { return now }
		v, _ := s.Acquire()
		r := exactRecords("192.0.2.1")
		r[0].ExpiresAt = now.Add(time.Second).Format(time.RFC3339Nano)
		if _, e := s.Replace(expectation(v), "expiry", r); e != nil {
			t.Fatal(e)
		}
		held, _ := s.Acquire()
		now = now.Add(2 * time.Second)
		later, _ := s.Acquire()
		if _, ok := held.Lookup("host.invalid.", "A"); !ok {
			t.Fatal("held clock changed")
		}
		if _, ok := later.Lookup("host.invalid.", "A"); ok {
			t.Fatal("expired visible")
		}
		if len(later.Records()) != 1 || held.Metadata() != later.Metadata() {
			t.Fatal("expiry rewrote generation")
		}
	})
}
func TestVersionedReadersAndCloseWhileCommitBlocked(t *testing.T) {
	bothVersioned(t, func(t *testing.T, s *VersionedStore) {
		old, _ := s.Acquire()
		entered, release := make(chan struct{}), make(chan struct{})
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		s.hooks.beforeCommit = func(*sql.Tx) error { close(entered); <-release; return nil }
		write := make(chan error, 1)
		go func() { _, e := s.Replace(expectation(old), "blocked", exactRecords("192.0.2.1")); write <- e }()
		<-entered
		read := make(chan View, 1)
		go func() { v, _ := s.Acquire(); read <- v }()
		select {
		case v := <-read:
			if v.Metadata().Revision != 1 {
				t.Fatal("uncommitted visible")
			}
		case <-time.After(time.Second):
			t.Fatal("reader blocked by disk")
		}
		closed := make(chan error, 1)
		go func() { closed <- s.Close() }()
		select {
		case <-closed:
			t.Fatal("close passed in-flight write")
		case <-time.After(20 * time.Millisecond):
		}
		close(release)
		if e := <-write; e != nil {
			t.Fatal(e)
		}
		if e := <-closed; e != nil {
			t.Fatal(e)
		}
		if _, e := s.Acquire(); !errors.Is(e, ErrClosed) {
			t.Fatal(e)
		}
		if old.Metadata().Revision != 1 {
			t.Fatal("old changed")
		}
	})
}
func TestVersionedCapacityAndOverflow(t *testing.T) {
	s, _ := NewVersionedMemory(enrollment)
	defer s.Close()
	v, _ := s.Acquire()
	for n := 0; n < MaxOperationReceipts; n++ {
		s.receipts[string(rune(n+1))] = Receipt{}
	}
	if _, e := s.Replace(expectation(v), "cap", nil); !errors.Is(e, ErrReceiptCapacity) {
		t.Fatal(e)
	}
	s.receipts = map[string]Receipt{}
	boundary, e := recordset.New("test", "lineage", math.MaxUint64, nil)
	if e != nil {
		t.Fatal(e)
	}
	s.current.Store(&versionedGeneration{snapshot: boundary})
	v, _ = s.Acquire()
	if _, e = s.Replace(expectation(v), "overflow", nil); !errors.Is(e, ErrRevisionOverflow) {
		t.Fatal(e)
	}
}
func TestVersionedSQLiteRestartAndReceipt(t *testing.T) {
	p := dbPath(t)
	s := openVersionedTest(t, p)
	v, _ := s.Acquire()
	receipt, e := s.Replace(expectation(v), "durable", exactRecords("192.0.2.1"))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = openVersionedTest(t, p)
	retry, e := s.Replace(expectation(v), "durable", exactRecords("192.0.2.1"))
	if e != nil || retry != receipt {
		t.Fatal(retry, e)
	}
	if _, e = OpenVersionedSQLite(p, Enrollment{RulesetID: "test", LineageID: "wrong"}); e == nil {
		t.Fatal("concurrent opener admitted")
	}
	s.Close()
	if _, e = OpenVersionedSQLite(p, Enrollment{RulesetID: "test", LineageID: "wrong"}); !errors.Is(e, ErrIdentity) {
		t.Fatal(e)
	}
	if _, e = OpenSQLite(p); e == nil {
		t.Fatal("old opener accepted schema2")
	}
}
func assertDurableView(t *testing.T, s *VersionedStore, v View) {
	t.Helper()
	var wire []byte
	if e := s.db.QueryRow("SELECT envelope FROM snapshot_state WHERE id=1").Scan(&wire); e != nil {
		t.Fatal(e)
	}
	expected, _ := v.MarshalJSON()
	if !bytes.Equal(wire, expected) {
		t.Fatal("failed write changed durable snapshot")
	}
	var count int
	if e := s.db.QueryRow("SELECT count(*) FROM operation_receipts").Scan(&count); e != nil {
		t.Fatal(e)
	}
	if uint64(count)+1 != v.Metadata().Revision {
		t.Fatal("failed write changed receipt ledger")
	}
}
func TestVersionedFailedCommitNoPublicationThenRecovery(t *testing.T) {
	p := dbPath(t)
	s := openVersionedTest(t, p)
	v, _ := s.Acquire()
	// The pinned driver rolls back an active transaction after deferred FK failure.
	if _, e := s.db.Exec("PRAGMA foreign_keys=ON"); e != nil {
		t.Fatal(e)
	}
	s.hooks.beforeCommit = func(tx *sql.Tx) error {
		for _, q := range []string{"CREATE TABLE fault_parent(id INTEGER PRIMARY KEY)", "CREATE TABLE fault_child(id INTEGER REFERENCES fault_parent(id) DEFERRABLE INITIALLY DEFERRED)", "INSERT INTO fault_child VALUES(1)"} {
			if _, e := tx.Exec(q); e != nil {
				return e
			}
		}
		return nil
	}
	if _, e := s.Replace(expectation(v), "failed", exactRecords("192.0.2.1")); !errors.Is(e, ErrVersionedStorage) {
		t.Fatal(e)
	}
	current, _ := s.Acquire()
	if current.Metadata() != v.Metadata() || len(s.receipts) != 0 {
		t.Fatal("failed commit published")
	}
	assertDurableView(t, s, v)
	s.hooks = versionedHooks{}
	if _, e := s.Replace(expectation(v), "healthy", exactRecords("192.0.2.2")); e != nil {
		t.Fatal("failed commit poisoned connection", e)
	}
	s.Close()
	s = openVersionedTest(t, p)
	current, _ = s.Acquire()
	r, _ := current.Lookup("host.invalid.", "A")
	if r.Values[0] != "192.0.2.2" {
		t.Fatal(r)
	}
}
func TestVersionedRejectInvalidEnrollmentBeforeFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "absent.db")
	if _, e := OpenVersionedSQLite(p, Enrollment{}); !errors.Is(e, ErrVersionedInput) {
		t.Fatal(e)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("invalid enrollment touched path", e)
	}
}
