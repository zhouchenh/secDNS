package recordstore

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRRsetSchemaMigrationPreservesLegacyAndRollsBack(t *testing.T) {
	path := dbPath(t)
	s := openVersionedTest(t, path)
	v, _ := s.Acquire()
	records := exactRecords("192.0.2.9")
	old, e := s.ReplaceWithOperatorSuppliedProvenance(expectation(v), "old", records, operatorProvenance(t, records, "c"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.MutateRRset(mutation(2, "new")); !errors.Is(e, ErrRRsetSchemaRequired) {
		t.Fatal(e)
	}
	if e = EnableRRsetMutationsSQLite(path, enrollment); e == nil {
		t.Fatal("migration acquired active store")
	}
	s.Close()
	s = openVersionedTest(t, path)
	if s.schemaVersion != 3 {
		t.Fatal("automatic migration")
	}
	s.Close()
	_, e = openVersionedSQLiteMode(path, enrollment, versionedHooks{beforeCommit: func(*sql.Tx) error { return errors.New("injected") }}, true)
	if !errors.Is(e, ErrVersionedStorage) {
		t.Fatal(e)
	}
	s = openVersionedTest(t, path)
	if s.schemaVersion != 3 {
		t.Fatal("migration not rolled back")
	}
	s.Close()
	if e = EnableRRsetMutationsSQLite(path, enrollment); e != nil {
		t.Fatal(e)
	}
	s = openVersionedTest(t, path)
	if s.schemaVersion != 4 {
		t.Fatal("missing migration")
	}
	replay, e := s.ReplaceWithOperatorSuppliedProvenance(expectation(v), "old", records, operatorProvenance(t, records, "c"))
	if e != nil || replay != old {
		t.Fatal("legacy replay", e)
	}
	if _, e = s.MutateRRset(mutation(2, "new")); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s = openVersionedTest(t, path)
	defer s.Close()
	if r, e := s.ReplaceWithOperatorSuppliedProvenance(expectation(v), "old", records, operatorProvenance(t, records, "c")); e != nil || r != old {
		t.Fatal("legacy receipt after targeted reopen", e)
	}
}
func TestRRsetMigrationMissingAndWrongSchema(t *testing.T) {
	path := dbPath(t)
	if e := EnableRRsetMutationsSQLite(path, enrollment); e == nil {
		t.Fatal("missing accepted")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("missing path created", e)
	}
	s := openRRsetTest(t, path)
	s.Close()
	if e := EnableRRsetMutationsSQLite(path, enrollment); !errors.Is(e, ErrVersionedSchema) {
		t.Fatal("repeat migration", e)
	}
}
func TestRRsetPersistedRequestTamperingRejected(t *testing.T) {
	cases := map[string]string{
		"action":     "UPDATE operation_receipts SET rrset_request=CAST(replace(CAST(rrset_request AS TEXT),'upsert','delete') AS BLOB)",
		"null":       "UPDATE operation_receipts SET rrset_request=NULL",
		"text":       "UPDATE operation_receipts SET rrset_request=CAST(rrset_request AS TEXT)",
		"whitespace": "UPDATE operation_receipts SET rrset_request=CAST(' ' || CAST(rrset_request AS TEXT) AS BLOB)",
		"operation":  "UPDATE operation_receipts SET rrset_request=CAST(replace(CAST(rrset_request AS TEXT),'first','other') AS BLOB)",
		"identity":   "UPDATE operation_receipts SET rrset_request=CAST(replace(CAST(rrset_request AS TEXT),'lineage','foreign') AS BLOB)",
		"value":      "UPDATE operation_receipts SET rrset_request=CAST(replace(CAST(rrset_request AS TEXT),'target.invalid.','other.invalid.') AS BLOB)",
		"oversize":   "UPDATE operation_receipts SET rrset_request=zeroblob(131073)",
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			path := dbPath(t)
			s := openRRsetTest(t, path)
			if _, e := s.MutateRRset(mutation(1, "first")); e != nil {
				t.Fatal(e)
			}
			s.Close()
			db, e := openExclusiveDatabase(path)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(q); e != nil {
				t.Fatal(e)
			}
			db.Close()
			s, e = OpenVersionedSQLite(path, enrollment)
			if s != nil {
				s.Close()
			}
			if !errors.Is(e, ErrVersionedSchema) {
				t.Fatal("tampered metadata accepted", e)
			}
		})
	}
}

func TestRRsetAggregateReceiptCapPreservesReplay(t *testing.T) {
	s, _ := NewVersionedMemory(enrollment)
	defer s.Close()
	m := mutation(1, "first")
	first, e := s.MutateRRset(m)
	if e != nil {
		t.Fatal(e)
	}
	s.receipts["filled"] = Receipt{rrsetRequest: strings.Repeat("x", MaxRRsetReceiptBytes)}
	if r, e := s.MutateRRset(m); e != nil || r != first {
		t.Fatal("replay rejected at cap", e)
	}
	if _, e := s.MutateRRset(mutation(2, "next")); !errors.Is(e, ErrReceiptCapacity) {
		t.Fatal(e)
	}
	v, _ := s.Acquire()
	if v.Metadata().Revision != 2 {
		t.Fatal("cap published")
	}
}
func TestRRsetAggregatePersistedMetadataBound(t *testing.T) {
	path := dbPath(t)
	s := openRRsetTest(t, path)
	s.Close()
	db, e := openExclusiveDatabase(path)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 129; i++ {
		if _, e = db.Exec("INSERT INTO operation_receipts VALUES(?,?,?,?,?,?,?)", fmt.Sprint(i), "x", "2", "x", "x", nil, make([]byte, 131072)); e != nil {
			t.Fatal(e)
		}
	}
	db.Close()
	s, e = OpenVersionedSQLite(path, enrollment)
	if s != nil {
		s.Close()
	}
	if !errors.Is(e, ErrVersionedSchema) {
		t.Fatal(e)
	}
}

func TestRRsetHistoricalOutcomeCorruptionRejected(t *testing.T) {
	path := dbPath(t)
	s := openRRsetTest(t, path)
	if _, e := s.MutateRRset(mutation(1, "first")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.MutateRRset(mutation(2, "later")); e != nil {
		t.Fatal(e)
	}
	s.Close()
	db, e := openExclusiveDatabase(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("UPDATE operation_receipts SET content_sha256=? WHERE operation_id='first'", strings.Repeat("a", 64)); e != nil {
		t.Fatal(e)
	}
	db.Close()
	s, e = OpenVersionedSQLite(path, enrollment)
	if s != nil {
		s.Close()
	}
	if !errors.Is(e, ErrVersionedSchema) {
		t.Fatal("historical outcome accepted", e)
	}
}
