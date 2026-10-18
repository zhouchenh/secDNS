package recordstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"os"
	"os/exec"
	"reflect"
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

func versionedV2Fixture(t *testing.T, path string) Receipt {
	t.Helper()
	records := exactRecords("192.0.2.1")
	snapshot, err := recordset.New(enrollment.RulesetID, enrollment.LineageID, 2, records)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 18, 1, 2, 3, 456, time.UTC)
	receipt := Receipt{
		OperationID:   "legacy-op",
		RequestSHA256: requestDigest(Expected{enrollment.RulesetID, enrollment.LineageID, 1}, snapshot.Metadata().ContentSHA256),
		Revision:      2,
		ContentSHA256: snapshot.Metadata().ContentSHA256,
		CommittedAt:   at,
	}
	db, err := openExclusiveDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, q := range []string{snapshotTableSQLV2, receiptTableSQLV2, fmt.Sprintf("PRAGMA application_id=%d", applicationID), "PRAGMA user_version=2"} {
		if _, err = tx.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	wire, _ := snapshot.MarshalJSON()
	if _, err = tx.Exec("INSERT INTO snapshot_state(id,envelope) VALUES(1,?)", wire); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("INSERT INTO operation_receipts(operation_id,request_sha256,committed_revision,content_sha256,committed_at) VALUES(?,?,?,?,?)", receipt.OperationID, receipt.RequestSHA256, "2", receipt.ContentSHA256, at.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return receipt
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

func TestVersionedSchema2CompatibilityMigrationAndProvenanceRestart(t *testing.T) {
	p := dbPath(t)
	legacyReceipt := versionedV2Fixture(t, p)
	s, err := OpenVersionedSQLite(p, enrollment)
	if err != nil || s.schemaVersion != 2 {
		t.Fatal("schema 2 compatibility open", s, err)
	}
	base, _ := s.Acquire()
	retry, err := s.Replace(Expected{enrollment.RulesetID, enrollment.LineageID, 1}, "legacy-op", exactRecords("192.0.2.1"))
	if err != nil || retry != legacyReceipt {
		t.Fatal("schema 2 legacy retry", retry, err)
	}
	provenance := operatorProvenance(t, exactRecords("192.0.2.2"), "3")
	if _, err = s.ReplaceWithOperatorSuppliedProvenance(expectation(base), "not-yet", exactRecords("192.0.2.2"), provenance); !errors.Is(err, ErrOperatorProvenanceUnavailable) {
		t.Fatal("schema 2 accepted provenance", err)
	}
	legacySecond, err := s.Replace(expectation(base), "legacy-second", exactRecords("192.0.2.2"))
	if err != nil || legacySecond.Revision != 3 {
		t.Fatal("schema 2 legacy write", legacySecond, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	migrate := enrollment
	migrate.AllowSchema2Migration = true
	s, err = OpenVersionedSQLite(p, migrate)
	if err != nil || s.schemaVersion != 3 {
		t.Fatal("explicit schema 2 migration", s, err)
	}
	if retry, err = s.Replace(Expected{enrollment.RulesetID, enrollment.LineageID, 1}, "legacy-op", exactRecords("192.0.2.1")); err != nil || retry != legacyReceipt {
		t.Fatal("legacy retry changed after migration", retry, err)
	}
	beforeProvenance, _ := s.Acquire()
	provenance = operatorProvenance(t, exactRecords("192.0.2.3"), "4")
	withProvenance, err := s.ReplaceWithOperatorSuppliedProvenance(expectation(beforeProvenance), "provenance-op", exactRecords("192.0.2.3"), provenance)
	if err != nil || withProvenance.Revision != 4 {
		t.Fatal(withProvenance, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = OpenVersionedSQLite(p, enrollment)
	if err != nil || s.schemaVersion != 3 {
		t.Fatal("schema 3 reopen", s, err)
	}
	defer s.Close()
	view, _ := s.Acquire()
	if got, ok := view.OperatorSuppliedProvenance(); !ok || got != provenance {
		t.Fatal("reopen lost provenance", got, ok)
	}
	if retry, err = s.ReplaceWithOperatorSuppliedProvenance(expectation(beforeProvenance), "provenance-op", exactRecords("192.0.2.3"), provenance); err != nil || retry != withProvenance {
		t.Fatal("provenance retry changed after restart", retry, err)
	}
}

func TestVersionedSchema2MigrationRollback(t *testing.T) {
	p := dbPath(t)
	versionedV2Fixture(t, p)
	before := fileDigest(t, p)
	migrate := enrollment
	migrate.AllowSchema2Migration = true
	hooks := versionedHooks{beforeCommit: func(*sql.Tx) error { return errors.New("test migration refusal") }}
	if _, err := openVersionedSQLite(p, migrate, hooks); !errors.Is(err, ErrVersionedStorage) {
		t.Fatal(err)
	}
	if fileDigest(t, p) != before {
		t.Fatal("failed schema 2 migration changed bytes")
	}
	s, err := OpenVersionedSQLite(p, enrollment)
	if err != nil || s.schemaVersion != 2 {
		t.Fatal("failed migration did not retain schema 2", err)
	}
	s.Close()
}

func TestVersionedMigrationPreservesJSONLookingTXT(t *testing.T) {
	p := dbPath(t)
	rawValues := `["\"}],\"records\":[{\"name\":\"injected.invalid.\"}],\"x\":\"","\"quoted\"","\\ud800","\ud83d\ude00","\ufffd","<>&","","repeat","repeat"]`
	values := []string{`"}],"records":[{"name":"injected.invalid."}],"x":"`, `"quoted"`, `\ud800`, "😀", "\ufffd", "<>&", "", "repeat", "repeat"}
	legacyFixture(t, p, []legacyRow{{"Quoted.TXT.Invalid.", int64(dns.TypeTXT), 0, rawValues, ""}})
	s, err := OpenVersionedSQLite(p, migrationEnrollment())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, err := s.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	want := []recordset.Record{{Name: "quoted.txt.invalid.", Type: "TXT", Values: values, TTLSeconds: 0}}
	if !reflect.DeepEqual(v.Records(), want) || v.Metadata().Revision != 1 {
		t.Fatal("migration changed literal TXT content or injected another record")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openVersionedTest(t, p)
	defer s.Close()
	reopened, err := s.Acquire()
	if err != nil || reopened.Metadata() != v.Metadata() || !reflect.DeepEqual(reopened.Records(), want) {
		t.Fatal("literal TXT content changed after reopen", err)
	}
}

func TestVersionedMigrationRejectsOriginalMalformedValueBytes(t *testing.T) {
	for name, values := range map[string]string{
		"invalid-utf8":    string([]byte{'[', '"', 0xff, '"', ']'}),
		"low-surrogate":   `["\udfff"]`,
		"reversed-pair":   `["\udfff\ud800"]`,
		"trailing-object": `["valid"] {"records":[]}`,
		"mixed-null":      `["valid",null]`,
	} {
		t.Run(name, func(t *testing.T) {
			p := dbPath(t)
			legacyFixture(t, p, []legacyRow{{"text.invalid.", int64(dns.TypeTXT), 0, values, ""}})
			before := fileDigest(t, p)
			if s, err := OpenVersionedSQLite(p, migrationEnrollment()); !errors.Is(err, ErrMigrationIncompatible) {
				if s != nil {
					s.Close()
				}
				t.Fatal("malformed original bytes were repaired or accepted", err)
			}
			if fileDigest(t, p) != before {
				t.Fatal("rejected migration changed the original database")
			}
		})
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

func TestVersionedRejectsCorruptOperatorSuppliedProvenance(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string, []byte){
		"snapshot-text-type": func(t *testing.T, path string, _ []byte) {
			mutateVersionedFile(t, path, "UPDATE snapshot_state SET operator_provenance=CAST(operator_provenance AS TEXT)")
		},
		"receipt-noncanonical": func(t *testing.T, path string, wire []byte) {
			mutateVersionedFile(t, path, "UPDATE operation_receipts SET operator_provenance=?", append([]byte(" "), wire...))
		},
		"snapshot-receipt-mismatch": func(t *testing.T, path string, wire []byte) {
			var decoded map[string]string
			if json.Unmarshal(wire, &decoded) != nil {
				t.Fatal("decode fixture")
			}
			decoded["source_sha256"] = strings.Repeat("9", 64)
			other, _ := recordset.NewOperatorSuppliedProvenance(decoded["profile"], decoded["source_sha256"], decoded["content_sha256"])
			otherWire, _ := other.MarshalJSON()
			mutateVersionedFile(t, path, "UPDATE snapshot_state SET operator_provenance=?", otherWire)
		},
		"tuple-digest-mismatch": func(t *testing.T, path string, wire []byte) {
			var decoded map[string]string
			if json.Unmarshal(wire, &decoded) != nil {
				t.Fatal("decode fixture")
			}
			decoded["source_sha256"] = strings.Repeat("9", 64)
			other, _ := recordset.NewOperatorSuppliedProvenance(decoded["profile"], decoded["source_sha256"], decoded["content_sha256"])
			otherWire, _ := other.MarshalJSON()
			mutateVersionedFile(t, path, "UPDATE snapshot_state SET operator_provenance=?", otherWire)
			mutateVersionedFile(t, path, "UPDATE operation_receipts SET operator_provenance=?", otherWire)
		},
		"tuple-content-mismatch": func(t *testing.T, path string, wire []byte) {
			var decoded map[string]string
			if json.Unmarshal(wire, &decoded) != nil {
				t.Fatal("decode fixture")
			}
			decoded["content_sha256"] = strings.Repeat("0", 64)
			other, _ := recordset.NewOperatorSuppliedProvenance(decoded["profile"], decoded["source_sha256"], decoded["content_sha256"])
			otherWire, _ := other.MarshalJSON()
			mutateVersionedFile(t, path, "UPDATE snapshot_state SET operator_provenance=?", otherWire)
			mutateVersionedFile(t, path, "UPDATE operation_receipts SET operator_provenance=?", otherWire)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := dbPath(t)
			s := openVersionedTest(t, p)
			base, _ := s.Acquire()
			records := exactRecords("192.0.2.1")
			provenance := operatorProvenance(t, records, "8")
			if _, err := s.ReplaceWithOperatorSuppliedProvenance(expectation(base), "with-provenance", records, provenance); err != nil {
				t.Fatal(err)
			}
			wire, _ := provenance.MarshalJSON()
			s.Close()
			mutate(t, p, wire)
			if _, err := OpenVersionedSQLite(p, enrollment); !errors.Is(err, ErrVersionedSchema) {
				t.Fatal(err)
			}
		})
	}
}

func TestVersionedProvenanceReceiptFailureIsAtomic(t *testing.T) {
	s := openVersionedTest(t, dbPath(t))
	defer s.Close()
	base, _ := s.Acquire()
	records := exactRecords("192.0.2.1")
	provenance := operatorProvenance(t, records, "7")
	if _, err := s.db.Exec("CREATE TRIGGER fail_provenance_receipt BEFORE INSERT ON operation_receipts BEGIN SELECT RAISE(ABORT,'test'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceWithOperatorSuppliedProvenance(expectation(base), "failed-provenance", records, provenance); !errors.Is(err, ErrVersionedStorage) {
		t.Fatal(err)
	}
	current, _ := s.Acquire()
	if current.Metadata() != base.Metadata() {
		t.Fatal("failed provenance commit published snapshot")
	}
	if _, ok := current.OperatorSuppliedProvenance(); ok {
		t.Fatal("failed provenance commit published tuple")
	}
	var stored any
	if err := s.db.QueryRow("SELECT operator_provenance FROM snapshot_state WHERE id=1").Scan(&stored); err != nil || stored != nil {
		t.Fatal("failed provenance commit changed durable tuple", stored, err)
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_provenance_receipt"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceWithOperatorSuppliedProvenance(expectation(base), "healthy-provenance", records, provenance); err != nil {
		t.Fatal(err)
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
		if _, e = tx.Exec("INSERT INTO operation_receipts(operation_id,request_sha256,committed_revision,content_sha256,committed_at) VALUES(?,?,?,?,?)", fmt.Sprint("op", n), request, fmt.Sprint(n+1), snapshot.Metadata().ContentSHA256, at); e != nil {
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
