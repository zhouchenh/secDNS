package recordstore

import (
	"database/sql"
	"errors"
	"github.com/miekg/dns"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func dbPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return filepath.Join(dir, "records.db")
}
func openDB(t *testing.T, path string) *Store {
	t.Helper()
	s, e := OpenSQLite(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestSQLiteRestartUpdateDeleteExpiry(t *testing.T) {
	p := dbPath(t)
	s := openDB(t, p)
	r := Record{Name: "host.example.", Type: dns.TypeA, Values: []string{"192.0.2.1"}, TTL: 300}
	if e := s.Set(r); e != nil {
		t.Fatal(e)
	}
	r.Values = []string{"192.0.2.2"}
	if e := s.Set(r); e != nil {
		t.Fatal(e)
	}
	exp := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	if e := s.Set(Record{Name: "ttl.example.", Type: dns.TypeTXT, Values: []string{"expires"}, TTL: 86400, ExpiresAt: exp}); e != nil {
		t.Fatal(e)
	}
	if e := s.Set(Record{Name: "old.example.", Type: dns.TypeTXT, Values: []string{"old"}, TTL: 100, ExpiresAt: time.Now().Add(-time.Second)}); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s = openDB(t, p)
	got, ok := s.Get("host.example.", dns.TypeA)
	if !ok || got.Values[0] != "192.0.2.2" || got.TTL != 300 {
		t.Fatal("restart lost update")
	}
	got, ok = s.Get("ttl.example.", dns.TypeTXT)
	if !ok || !got.ExpiresAt.Equal(exp) || got.TTL != 86400 {
		t.Fatal("expiry reset or TTL changed")
	}
	if _, ok = s.Get("old.example.", dns.TypeTXT); ok {
		t.Fatal("expired record resurrected")
	}
	if deleted, e := s.Delete("host.example.", dns.TypeA); e != nil || !deleted {
		t.Fatal("delete")
	}
	if deleted, e := s.Delete("absent.example.", dns.TypeA); e != nil || deleted {
		t.Fatal("absent delete")
	}
	s.Close()
	s = openDB(t, p)
	if _, ok = s.Get("host.example.", dns.TypeA); ok {
		t.Fatal("delete resurrected")
	}
}
func TestSQLiteMutationFailureRollback(t *testing.T) {
	p := dbPath(t)
	s := openDB(t, p)
	r := Record{Name: "host.example.", Type: dns.TypeA, Values: []string{"192.0.2.1"}, TTL: 300}
	if e := s.Set(r); e != nil {
		t.Fatal(e)
	}
	for _, q := range []string{"PRAGMA foreign_keys=ON", "CREATE TABLE parent(id INTEGER PRIMARY KEY)", "CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)", "CREATE TRIGGER fail_commit AFTER UPDATE ON records BEGIN INSERT INTO child VALUES(99); END"} {
		if _, e := s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	r.Values = []string{"192.0.2.2"}
	if e := s.Set(r); e == nil {
		t.Fatal("commit should fail")
	}
	got, _ := s.Get(r.Name, r.Type)
	if got.Values[0] != "192.0.2.1" {
		t.Fatal("failed commit published")
	}
	for _, q := range []string{"DROP TRIGGER fail_commit", "DROP TABLE child", "DROP TABLE parent", "CREATE TRIGGER fail_delete BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT,'test failure'); END"} {
		if _, e := s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	if deleted, e := s.Delete(r.Name, r.Type); e == nil || deleted {
		t.Fatal("failed delete reported success")
	}
	if _, ok := s.Get(r.Name, r.Type); !ok {
		t.Fatal("failed delete changed memory")
	}
	mustExec(t, s.db, "DROP TRIGGER fail_delete")
	// Driver cleanup after failed Commit must permit the next transaction.
	if e := s.Set(Record{Name: "recovery.example.", Type: dns.TypeTXT, Values: []string{"ok"}, TTL: 60}); e != nil {
		t.Fatal("connection not usable after failed commit", e)
	}
	s.Close()
	s = openDB(t, p)
	got, _ = s.Get(r.Name, r.Type)
	if got.Values[0] != "192.0.2.1" {
		t.Fatal("failed commit changed disk")
	}
}
func TestSQLiteCorruptionSchemaAndInvalidRows(t *testing.T) {
	for _, mode := range []string{"corrupt", "version", "row", "expired-row"} {
		t.Run(mode, func(t *testing.T) {
			p := dbPath(t)
			if mode == "corrupt" {
				os.WriteFile(p, []byte("not sqlite"), 0600)
			} else {
				s := openDB(t, p)
				switch mode {
				case "version":
					mustExec(t, s.db, "PRAGMA user_version=99")
				case "row", "expired-row":
					expiry := ""
					if mode == "expired-row" {
						expiry = "2000-01-01T00:00:00Z"
					}
					mustExec(t, s.db, "INSERT INTO records VALUES(?,?,?,?,?)", "bad.example.", 1, `["bad-ip"]`, 60, expiry)
				}
				s.Close()
			}
			if s, e := OpenSQLite(p); e == nil {
				s.Close()
				t.Fatal("invalid database opened")
			}
		})
	}
}
func TestSQLiteExclusiveProcessOwner(t *testing.T) {
	if p := os.Getenv("SECDNS_TEST_DB_OPEN"); p != "" {
		s, e := OpenSQLite(p)
		if e == nil {
			s.Close()
			os.Exit(2)
		}
		os.Exit(0)
	}
	p := dbPath(t)
	s := openDB(t, p)
	for _, afterWrite := range []bool{false, true} {
		if afterWrite {
			if e := s.Set(Record{Name: "host.example.", Type: dns.TypeA, Values: []string{"192.0.2.1"}, TTL: 60}); e != nil {
				t.Fatal(e)
			}
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestSQLiteExclusiveProcessOwner$")
		cmd.Env = append(os.Environ(), "SECDNS_TEST_DB_OPEN="+p)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("second process opened owned database: %v %s", e, out)
		}
	}
	s.Close()
	s = openDB(t, p)
}
func TestSQLiteCloseConcurrencyAndValidation(t *testing.T) {
	s := openDB(t, dbPath(t))
	var wg sync.WaitGroup
	for j := 0; j < 4; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 20; k++ {
				e := s.Set(Record{Name: "host.example.", Type: dns.TypeA, Values: []string{"192.0.2.1"}, TTL: 60})
				if e != nil && !errors.Is(e, ErrClosed) {
					t.Error(e)
				}
				s.Get("host.example.", dns.TypeA)
				s.List()
			}
		}()
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	wg.Wait()
	if e := s.Set(Record{}); !errors.Is(e, ErrClosed) {
		t.Fatal("write after close")
	}
	if _, e := s.Delete("x.example.", dns.TypeA); !errors.Is(e, ErrClosed) {
		t.Fatal("delete after close")
	}
}
func TestSQLitePrepareRollbackIdentityAndPermissions(t *testing.T) {
	p := dbPath(t)
	closeStores, e := Prepare(map[string]string{"persist-test": p})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Prepare(map[string]string{"persist-test": dbPath(t)}); e == nil {
		t.Fatal("name replacement")
	}
	closeStores()
	closeStores()
	bad := filepath.Join(t.TempDir(), "missing", "db")
	if _, e = Prepare(map[string]string{"a-test": p, "z-test": bad}); e == nil {
		t.Fatal("expected partial failure")
	}
	registryMu.Lock()
	_, exists := registry["a-test"]
	registryMu.Unlock()
	if exists {
		t.Fatal("partial startup published")
	}
	s := openDB(t, p)
	s.Close()
	link := filepath.Join(filepath.Dir(p), "hardlink.db")
	if e = os.Link(p, link); e == nil {
		if _, e = Prepare(map[string]string{"one": p, "two": link}); e == nil {
			t.Fatal("hardlink alias accepted")
		}
	}
	if runtime.GOOS != "windows" {
		os.Chmod(p, 0644)
		if _, e = OpenSQLite(p); e == nil {
			t.Fatal("public file accepted")
		}
		os.Chmod(p, 0600)
	}
}

func mustExec(t *testing.T, db *sql.DB, statement string, args ...interface{}) {
	t.Helper()
	if _, err := db.Exec(statement, args...); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteSweepDurableAndFailure(t *testing.T) {
	p := dbPath(t)
	s := openDB(t, p)
	old := Record{Name: "old.example.", Type: dns.TypeTXT, Values: []string{"old"}, TTL: 60, ExpiresAt: time.Now().Add(-time.Second)}
	if e := s.Set(old); e != nil {
		t.Fatal(e)
	}
	mustExec(t, s.db, "CREATE TRIGGER deny_sweep BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT,'test'); END")
	if e := s.sweep(); e == nil {
		t.Fatal("sweep should fail")
	}
	if len(s.records) != 1 {
		t.Fatal("failed sweep removed memory")
	}
	if len(s.List()) != 0 {
		t.Fatal("failed sweep served expired data")
	}
	mustExec(t, s.db, "DROP TRIGGER deny_sweep")
	if e := s.sweep(); e != nil {
		t.Fatal(e)
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM records").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 || len(s.records) != 0 {
		t.Fatal("sweep did not persist")
	}
	if e := s.Set(old); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s = openDB(t, p)
	if err := s.db.QueryRow("SELECT count(*) FROM records").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("startup did not reclaim expired row")
	}
}

func TestSQLiteAbruptProcessRecovery(t *testing.T) {
	if path := os.Getenv("SECDNS_TEST_CRASH_DB"); path != "" {
		s, e := OpenSQLite(path)
		if e != nil {
			os.Exit(3)
		}
		if os.Getenv("SECDNS_TEST_CRASH_MODE") == "committed" {
			if e = s.Set(Record{Name: "committed.example.", Type: dns.TypeA, Values: []string{"192.0.2.1"}, TTL: 300}); e != nil {
				os.Exit(4)
			}
		} else {
			tx, e := s.db.Begin()
			if e != nil {
				os.Exit(5)
			}
			if _, e = tx.Exec("INSERT INTO records VALUES(?,?,?,?,?)", "pending.example.", 1, `["192.0.2.2"]`, 60, ""); e != nil {
				os.Exit(6)
			}
		}
		// Deliberately exit without Close or deferred cleanup.
		os.Exit(0)
	}
	path := dbPath(t)
	for _, mode := range []string{"committed", "pending"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSQLiteAbruptProcessRecovery$")
		cmd.Env = append(os.Environ(), "SECDNS_TEST_CRASH_DB="+path, "SECDNS_TEST_CRASH_MODE="+mode)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("crash helper: %v %s", e, out)
		}
		s := openDB(t, path)
		if _, ok := s.Get("committed.example.", dns.TypeA); !ok {
			t.Fatal("acknowledged mutation lost")
		}
		if _, ok := s.Get("pending.example.", dns.TypeA); ok {
			t.Fatal("uncommitted mutation recovered")
		}
		s.Close()
	}
}
