package recordstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type legacyRow struct {
	name           string
	typ, ttl       int64
	values, expiry string
}

func legacyFixture(t *testing.T, path string, rows []legacyRow) {
	t.Helper()
	db, e := openExclusiveDatabase(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	tx, e := db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	for _, q := range []string{tableSQL, fmt.Sprintf("PRAGMA application_id=%d", applicationID), "PRAGMA user_version=1"} {
		if _, e = tx.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	for _, r := range rows {
		if _, e = tx.Exec("INSERT INTO records VALUES(?,?,?,?,?)", r.name, r.typ, r.values, r.ttl, r.expiry); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
}
func migrationEnrollment() Enrollment { e := enrollment; e.AllowSchema1Migration = true; return e }
func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return sha256.Sum256(b)
}
func TestVersionedMigrationPreservesExpiredTTLAndTXT(t *testing.T) {
	p := dbPath(t)
	expiry := "2000-01-01T00:00:00.123456789Z"
	legacyFixture(t, p, []legacyRow{{"expired.invalid.", int64(dns.TypeA), 0, `["192.0.2.1"]`, expiry}, {"txt.invalid.", int64(dns.TypeTXT), 4294967295, `["", "repeat", "repeat"]`, ""}})
	before := fileDigest(t, p)
	if _, e := OpenVersionedSQLite(p, enrollment); !errors.Is(e, ErrMigrationRequired) {
		t.Fatal(e)
	}
	if fileDigest(t, p) != before {
		t.Fatal("unapproved migration changed file")
	}
	s, e := OpenVersionedSQLite(p, migrationEnrollment())
	if e != nil {
		t.Fatal(e)
	}
	v, _ := s.Acquire()
	records := v.Records()
	if len(records) != 2 || records[0].TTLSeconds != 0 || records[0].ExpiresAt != expiry || records[1].TTLSeconds != 4294967295 || len(records[1].Values) != 3 || records[1].Values[0] != "" || records[1].Values[1] != records[1].Values[2] {
		t.Fatal(records)
	}
	if len(v.LiveRecords()) != 1 {
		t.Fatal("expired not filtered")
	}
	s.Close()
	s = openVersionedTest(t, p)
	defer s.Close()
	again, _ := s.Acquire()
	if again.Metadata() != v.Metadata() || len(again.Records()) != 2 {
		t.Fatal("migration restarted differently")
	}
}
func TestVersionedMigrationRefusalAndSQLRollback(t *testing.T) {
	cases := [][]legacyRow{
		{{"dup.invalid.", int64(dns.TypeA), 30, `["192.0.2.1","192.0.2.1"]`, ""}},
		{{"mixed.invalid.", int64(dns.TypeA), 30, `["192.0.2.1"]`, ""}, {"mixed.invalid.", int64(dns.TypeCNAME), 30, `["target.invalid."]`, "2000-01-01T00:00:00Z"}},
		{{"text.invalid.", int64(dns.TypeTXT), 30, `[null]`, ""}},
		{{"text.invalid.", int64(dns.TypeTXT), 30, `["\ud800"]`, ""}},
		{{"bad\\046name.invalid.", int64(dns.TypeA), 30, `["192.0.2.1"]`, ""}},
	}
	for index, rows := range cases {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			p := dbPath(t)
			legacyFixture(t, p, rows)
			before := fileDigest(t, p)
			if _, e := OpenVersionedSQLite(p, migrationEnrollment()); !errors.Is(e, ErrMigrationIncompatible) {
				t.Fatal(e)
			}
			if fileDigest(t, p) != before {
				t.Fatal("refusal mutated original")
			}
		})
	}
	p := dbPath(t)
	legacyFixture(t, p, []legacyRow{{"ok.invalid.", int64(dns.TypeA), 30, `["192.0.2.1"]`, ""}})
	before := fileDigest(t, p)
	hooks := versionedHooks{beforeCommit: func(tx *sql.Tx) error { _, e := tx.Exec("INSERT INTO snapshot_state VALUES(1,'duplicate')"); return e }}
	if _, e := openVersionedSQLite(p, migrationEnrollment(), hooks); !errors.Is(e, ErrVersionedStorage) {
		t.Fatal(e)
	}
	if fileDigest(t, p) != before {
		t.Fatal("failed migration changed bytes")
	}
	s, e := OpenSQLite(p)
	if e != nil {
		t.Fatal("schema1 no longer opens", e)
	}
	s.Close()
	v, e := OpenVersionedSQLite(p, migrationEnrollment())
	if e != nil {
		t.Fatal(e)
	}
	v.Close()
}
func mutateVersionedFile(t *testing.T, path, query string, args ...any) {
	t.Helper()
	db, e := openExclusiveDatabase(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(query, args...); e != nil {
		t.Fatal(e)
	}
}
func TestVersionedRejectsCorruptLedgerAndSchema(t *testing.T) {
	for _, query := range []string{
		"UPDATE operation_receipts SET committed_revision='02'",
		"UPDATE operation_receipts SET content_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
		"UPDATE operation_receipts SET operation_id='bad id'",
		"UPDATE operation_receipts SET committed_at='2030-01-01T00:00:00+00:00'",
		"DELETE FROM operation_receipts",
		"CREATE TABLE unexpected (id INTEGER)",
		"CREATE TABLE sqliteXextra (id INTEGER)",
		"PRAGMA user_version=9",
		"UPDATE snapshot_state SET envelope='{}'",
	} {
		t.Run(query, func(t *testing.T) {
			p := dbPath(t)
			s := openVersionedTest(t, p)
			v, _ := s.Acquire()
			if _, e := s.Replace(expectation(v), "one", exactRecords("192.0.2.1")); e != nil {
				t.Fatal(e)
			}
			s.Close()
			mutateVersionedFile(t, p, query)
			if _, e := OpenVersionedSQLite(p, enrollment); !errors.Is(e, ErrVersionedSchema) {
				t.Fatal(e)
			}
		})
	}
	p := dbPath(t)
	if e := os.WriteFile(p, []byte("not sqlite"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenVersionedSQLite(p, enrollment); e == nil {
		t.Fatal("corrupt DB admitted")
	}
}
func TestVersionedReceiptInsertFailureAndReadOnly(t *testing.T) {
	s := openVersionedTest(t, dbPath(t))
	v, _ := s.Acquire()
	if _, e := s.db.Exec("CREATE TRIGGER fail_receipt BEFORE INSERT ON operation_receipts BEGIN SELECT RAISE(ABORT,'test'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Replace(expectation(v), "one", exactRecords("192.0.2.1")); !errors.Is(e, ErrVersionedStorage) {
		t.Fatal(e)
	}
	now, _ := s.Acquire()
	if now.Metadata() != v.Metadata() {
		t.Fatal("receipt failure published")
	}
	assertDurableView(t, s, v)
	if _, e := s.db.Exec("DROP TRIGGER fail_receipt"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec("PRAGMA query_only=ON"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Replace(expectation(v), "one", nil); !errors.Is(e, ErrVersionedStorage) {
		t.Fatal(e)
	}
	assertDurableView(t, s, v)
	if _, e := s.db.Exec("PRAGMA query_only=OFF"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Replace(expectation(v), "one", nil); e != nil {
		t.Fatal(e)
	}
}
func TestVersionedCrashHelper(t *testing.T) {
	mode := os.Getenv("SECDNS_VERSIONED_CRASH")
	if mode == "" {
		return
	}
	s, e := OpenVersionedSQLite(os.Getenv("SECDNS_VERSIONED_PATH"), enrollment)
	if e != nil {
		os.Exit(51)
	}
	v, _ := s.Acquire()
	exit := func() { os.Exit(23) }
	if mode == "before" {
		s.hooks.beforeCommit = func(*sql.Tx) error { exit(); return nil }
	} else {
		s.hooks.afterCommit = exit
	}
	_, e = s.Replace(expectation(v), "crash-op", exactRecords("192.0.2.1"))
	if e != nil {
		os.Exit(52)
	}
	os.Exit(53)
}
func TestVersionedCrashBeforeAndAfterCommit(t *testing.T) {
	for _, mode := range []string{"before", "after"} {
		t.Run(mode, func(t *testing.T) {
			p := dbPath(t)
			s := openVersionedTest(t, p)
			old, _ := s.Acquire()
			s.Close()
			exe, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestVersionedCrashHelper$")
			cmd.Env = append(os.Environ(), "SECDNS_VERSIONED_CRASH="+mode, "SECDNS_VERSIONED_PATH="+p)
			e = cmd.Run()
			var status *exec.ExitError
			if !errors.As(e, &status) || status.ExitCode() != 23 {
				t.Fatal("child did not reach intended boundary", e)
			}
			s = openVersionedTest(t, p)
			v, _ := s.Acquire()
			want := uint64(1)
			if mode == "after" {
				want = 2
			}
			if v.Metadata().Revision != want {
				t.Fatal("hybrid recovery", v.Metadata())
			}
			receipt, e := s.Replace(expectation(old), "crash-op", exactRecords("192.0.2.1"))
			if e != nil || receipt.Revision != 2 {
				t.Fatal("retry recovery", receipt, e)
			}
			s.Close()
		})
	}
}
func TestVersionedSQLiteExclusiveOwnership(t *testing.T) {
	checkChild := func(path string) {
		t.Helper()
		exe, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestVersionedCrashHelper$")
		cmd.Env = append(os.Environ(), "SECDNS_VERSIONED_CRASH=before", "SECDNS_VERSIONED_PATH="+path)
		e = cmd.Run()
		var status *exec.ExitError
		if !errors.As(e, &status) || status.ExitCode() != 51 {
			t.Fatal("second process acquired owner", e)
		}
	}
	p := dbPath(t)
	s := openVersionedTest(t, p)
	if _, e := OpenVersionedSQLite(p, enrollment); e == nil {
		t.Fatal("idle second owner admitted")
	}
	checkChild(p)
	v, _ := s.Acquire()
	if _, e := s.Replace(expectation(v), "one", nil); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenVersionedSQLite(p, enrollment); e == nil {
		t.Fatal("postcommit second owner admitted")
	}
	checkChild(p)
	s.Close()
	s = openVersionedTest(t, p)
	s.Close()
}
func TestVersionedExpirySurvivesRestart(t *testing.T) {
	p := dbPath(t)
	s := openVersionedTest(t, p)
	v, _ := s.Acquire()
	r := exactRecords("192.0.2.1")
	r[0].ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	if _, e := s.Replace(expectation(v), "expired", r); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s = openVersionedTest(t, p)
	v, _ = s.Acquire()
	if len(v.LiveRecords()) != 0 || len(v.Records()) != 1 || v.Records()[0].ExpiresAt != r[0].ExpiresAt {
		t.Fatal("expiry reset or pruning")
	}
}

func TestVersionedRejectsOversizedNULTailsAndSQLTypes(t *testing.T) {
	huge := "x\x00" + strings.Repeat("x", recordset.MaxBytes)
	for _, target := range []string{"legacy", "receipt", "envelope", "blob-receipt"} {
		t.Run(target, func(t *testing.T) {
			p := dbPath(t)
			if target == "legacy" {
				legacyFixture(t, p, []legacyRow{{"host.invalid.", 1, 30, huge, ""}})
				before := fileDigest(t, p)
				if _, e := OpenVersionedSQLite(p, migrationEnrollment()); !errors.Is(e, ErrMigrationIncompatible) {
					t.Fatal(e)
				}
				if fileDigest(t, p) != before {
					t.Fatal("size refusal changed file")
				}
				return
			}
			s := openVersionedTest(t, p)
			v, _ := s.Acquire()
			if _, e := s.Replace(expectation(v), "one", nil); e != nil {
				t.Fatal(e)
			}
			s.Close()
			switch target {
			case "receipt":
				mutateVersionedFile(t, p, "UPDATE operation_receipts SET operation_id=?", huge)
			case "envelope":
				mutateVersionedFile(t, p, "UPDATE snapshot_state SET envelope=?", huge)
			case "blob-receipt":
				mutateVersionedFile(t, p, "UPDATE operation_receipts SET operation_id=?", []byte("one"))
			}
			if _, e := OpenVersionedSQLite(p, enrollment); !errors.Is(e, ErrVersionedSchema) {
				t.Fatal(e)
			}
		})
	}
}
func TestVersionedDurableLedgerCapacity(t *testing.T) {
	p := dbPath(t)
	s := openVersionedTest(t, p)
	initial, _ := s.Acquire()
	snapshot, e := recordset.New("test", "lineage", MaxOperationReceipts+1, nil)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := snapshot.MarshalJSON()
	tx, e := s.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE snapshot_state SET envelope=?", wire); e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	for n := 1; n <= MaxOperationReceipts; n++ {
		request := requestDigest(Expected{"test", "lineage", uint64(n)}, snapshot.Metadata().ContentSHA256)
		if _, e = tx.Exec("INSERT INTO operation_receipts VALUES(?,?,?,?,?)", fmt.Sprint("op", n), request, fmt.Sprint(n+1), snapshot.Metadata().ContentSHA256, at); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s = openVersionedTest(t, p)
	v, _ := s.Acquire()
	if _, e = s.Replace(expectation(v), "full", nil); !errors.Is(e, ErrReceiptCapacity) {
		t.Fatal(e)
	}
	if r, e := s.Replace(expectation(initial), "op1", nil); e != nil || r.Revision != 2 {
		t.Fatal("full ledger lost retry", r, e)
	}
}
