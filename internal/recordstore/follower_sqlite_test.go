package recordstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func openFollowerTest(t *testing.T, p string) *FollowerStore {
	t.Helper()
	s, e := OpenFollowerSQLite(p, followerEnrollment)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestFollowerSQLiteCreateOpenAndOwnership(t *testing.T) {
	p := dbPath(t)
	if _, e := OpenFollowerSQLite(p, followerEnrollment); !errors.Is(e, ErrFollowerStorage) {
		t.Fatal(e)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("open created missing file")
	}
	s, e := CreateFollowerSQLite(p, followerEnrollment)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if _, e = CreateFollowerSQLite(p, followerEnrollment); !errors.Is(e, ErrFollowerExists) {
		t.Fatal(e)
	}
	if _, e = OpenFollowerSQLite(p, followerEnrollment); e == nil {
		t.Fatal("second owner admitted")
	}
	s.Close()
	wrong := followerEnrollment
	wrong.AuthorityEpoch = "other"
	if _, e = OpenFollowerSQLite(p, wrong); !errors.Is(e, ErrFollowerIdentity) {
		t.Fatal(e)
	}
	openFollowerTest(t, p).Close()
	for _, content := range [][]byte{nil, []byte("not sqlite")} {
		q := filepath.Join(t.TempDir(), "existing.db")
		if e = os.WriteFile(q, content, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = CreateFollowerSQLite(q, followerEnrollment); !errors.Is(e, ErrFollowerExists) {
			t.Fatal(e)
		}
		if _, e = OpenFollowerSQLite(q, followerEnrollment); e == nil {
			t.Fatal("invalid file opened")
		}
		after, _ := os.ReadFile(q)
		if !bytes.Equal(after, content) {
			t.Fatal("invalid file replaced")
		}
	}
	for _, kind := range []string{"legacy", "writer"} {
		t.Run(kind, func(t *testing.T) {
			q := dbPath(t)
			if kind == "legacy" {
				v, e := OpenSQLite(q)
				if e != nil {
					t.Fatal(e)
				}
				v.Close()
			} else {
				v, e := OpenVersionedSQLite(q, enrollment)
				if e != nil {
					t.Fatal(e)
				}
				v.Close()
			}
			before := fileDigest(t, q)
			if _, e := OpenFollowerSQLite(q, followerEnrollment); !errors.Is(e, ErrFollowerSchema) {
				t.Fatal(e)
			}
			if fileDigest(t, q) != before {
				t.Fatal("unrelated schema altered")
			}
		})
	}
}
func TestFollowerSQLiteStrictStoredState(t *testing.T) {
	cases := []struct {
		name, query string
		args        []any
	}{
		{"application", "PRAGMA application_id=1", nil}, {"version", "PRAGMA user_version=2", nil},
		{"extra-object", "CREATE TABLE sqliteXextra(id INTEGER)", nil}, {"trigger", "CREATE TRIGGER extra AFTER UPDATE ON follower_state BEGIN SELECT 1; END", nil},
		{"missing-state", "DELETE FROM follower_state", nil}, {"flag", "UPDATE follower_enrollment SET has_snapshot=0", nil},
		{"missing-enrollment", "DELETE FROM follower_enrollment", nil}, {"invalid-tuple", "UPDATE follower_enrollment SET cluster_id=?", []any{"x\x00" + strings.Repeat("x", 200)}},
		{"revision", "UPDATE follower_state SET revision='01'", nil}, {"revision-nul", "UPDATE follower_state SET revision=?", []any{"1\x00" + strings.Repeat("1", 200)}},
		{"digest", "UPDATE follower_state SET content_sha256=?", []any{strings.Repeat("A", 64)}},
		{"envelope-type", "UPDATE follower_state SET envelope=CAST(envelope AS TEXT)", nil},
		{"envelope-large", "UPDATE follower_state SET envelope=zeroblob(?)", []any{recordset.MaxBytes + 1}},
		{"envelope-nul-text", "UPDATE follower_state SET envelope=?", []any{"{}\x00" + strings.Repeat("x", recordset.MaxBytes)}},
		{"envelope-invalid", "UPDATE follower_state SET envelope=?", []any{[]byte(`{}`)}},
		{"watermark-mismatch", "UPDATE follower_state SET revision='99'", nil},
		{"canonical", "UPDATE follower_state SET envelope=CAST(' ' || CAST(envelope AS TEXT) AS BLOB)", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := dbPath(t)
			s, e := CreateFollowerSQLite(p, followerEnrollment)
			if e != nil {
				t.Fatal(e)
			}
			acceptFollower(t, s, followerWire(t, 7, followerA("192.0.2.1")), "initial")
			s.Close()
			mutateVersionedFile(t, p, c.query, c.args...)
			if x, e := OpenFollowerSQLite(p, followerEnrollment); x != nil || !errors.Is(e, ErrFollowerSchema) {
				if x != nil {
					x.Close()
				}
				t.Fatalf("bad state admitted: %v", e)
			}
			db, e := openExclusiveDatabase(p)
			if e != nil {
				t.Fatal("constructor leaked handle", e)
			}
			if _, e = db.Exec("BEGIN EXCLUSIVE"); e != nil {
				t.Fatal("constructor leaked lock", e)
			}
			db.Exec("ROLLBACK")
			db.Close()
		})
	}
}
func TestFollowerSQLiteWriteCommitAndRollbackFailures(t *testing.T) {
	for _, mode := range []string{"write", "commit", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			p := dbPath(t)
			s, e := CreateFollowerSQLite(p, followerEnrollment)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { s.Close() })
			old := followerWire(t, 4, followerA("192.0.2.1"))
			next := followerWire(t, 8, followerA("192.0.2.2"))
			acceptFollower(t, s, old, "initial")
			held := followerView(t, s)
			s.hooks.beforeCommit = func(tx *sql.Tx) error {
				switch mode {
				case "write":
					_, e := tx.Exec("INSERT INTO follower_state(id,revision,content_sha256,envelope) VALUES(1,'1','bad',X'00')")
					return e
				case "commit":
					for _, q := range []string{"CREATE TABLE fault_parent(id INTEGER PRIMARY KEY)", "CREATE TABLE fault_child(id INTEGER REFERENCES fault_parent(id) DEFERRABLE INITIALLY DEFERRED)", "INSERT INTO fault_child VALUES(1)"} {
						if _, e := tx.Exec(q); e != nil {
							return e
						}
					}
					return nil
				default:
					if e := tx.Rollback(); e != nil {
						t.Fatal(e)
					}
					return errors.New("test rollback confirmation unavailable")
				}
			}
			rejectFollower(t, s, followerEnrollment, next, ErrFollowerStorage)
			if !bytes.Equal(held.EnvelopeJSON(), old) {
				t.Fatal("held view changed")
			}
			if mode == "write" {
				if !bytes.Equal(followerView(t, s).EnvelopeJSON(), old) {
					t.Fatal("precommit published")
				}
			} else {
				if _, e = s.Acquire(); !errors.Is(e, ErrFollowerFaulted) {
					t.Fatal("ambiguous state not faulted", e)
				}
				rejectFollower(t, s, FollowerEnrollment{}, nil, ErrFollowerFaulted)
			}
			s.Close()
			s = openFollowerTest(t, p)
			if !bytes.Equal(followerView(t, s).EnvelopeJSON(), old) {
				t.Fatal("fault rollback durable state")
			}
			acceptFollower(t, s, next, "advanced")
		})
	}
}
func TestFollowerSQLiteUnchangedDoesNotWrite(t *testing.T) {
	p := dbPath(t)
	s, e := CreateFollowerSQLite(p, followerEnrollment)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	raw := followerWire(t, 2)
	acceptFollower(t, s, raw, "initial")
	s.hooks.beforeCommit = func(*sql.Tx) error { t.Fatal("unchanged wrote transaction"); return nil }
	acceptFollower(t, s, raw, "unchanged")
	if _, e = s.db.Exec("PRAGMA query_only=ON"); e != nil {
		t.Fatal(e)
	}
	rejectFollower(t, s, followerEnrollment, followerWire(t, 3), ErrFollowerStorage)
	if followerView(t, s).State().Snapshot.Revision != 2 {
		t.Fatal("failed write published")
	}
}
func TestFollowerCrashHelper(t *testing.T) {
	p := os.Getenv("SECDNS_FOLLOWER_TEST_PATH")
	if p == "" {
		return
	}
	mode := os.Getenv("SECDNS_FOLLOWER_TEST_MODE")
	s, e := OpenFollowerSQLite(p, followerEnrollment)
	if mode == "exclusive" {
		if e != nil {
			os.Exit(73)
		}
		s.Close()
		os.Exit(74)
	}
	if e != nil {
		t.Fatal(e)
	}
	exit := func() { os.Exit(71) }
	if strings.HasPrefix(mode, "before") {
		s.hooks.beforeCommit = func(*sql.Tx) error { exit(); return nil }
	} else {
		s.hooks.afterCommit = exit
	}
	raw := followerWire(t, 9007199254740993)
	if strings.HasSuffix(mode, "-changed") {
		raw = followerWire(t, 9007199254740993, followerA("192.0.2.2"))
	}
	_, e = s.Accept(followerEnrollment, raw)
	t.Fatalf("crash hook not reached: %v", e)
}
func followerChild(t *testing.T, p, mode string, code int) {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestFollowerCrashHelper$")
	cmd.Env = append(os.Environ(), "SECDNS_FOLLOWER_TEST_PATH="+p, "SECDNS_FOLLOWER_TEST_MODE="+mode)
	out, e := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != code || ctx.Err() != nil {
		t.Fatalf("helper boundary not proven: %v %s", e, out)
	}
}
func TestFollowerSQLiteCrashAndExclusiveProcess(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		for _, mode := range []string{"before", "after"} {
			t.Run(fmt.Sprintf("%t-%s", initialized, mode), func(t *testing.T) {
				p := dbPath(t)
				s, e := CreateFollowerSQLite(p, followerEnrollment)
				if e != nil {
					t.Fatal(e)
				}
				if initialized {
					acceptFollower(t, s, followerWire(t, 3), "initial")
				}
				followerChild(t, p, "exclusive", 73)
				s.Close()
				followerChild(t, p, mode, 71)
				s = openFollowerTest(t, p)
				if mode == "before" && !initialized {
					if _, e = s.Acquire(); !errors.Is(e, ErrFollowerNotReady) {
						t.Fatal(e)
					}
					acceptFollower(t, s, followerWire(t, 9007199254740993), "initial")
				} else {
					want := uint64(9007199254740993)
					if mode == "before" {
						want = 3
					}
					v := followerView(t, s)
					if v.State().Snapshot.Revision != want || len(v.Records()) != 0 {
						t.Fatal("crash recovered wrong generation")
					}
					acceptFollower(t, s, followerWire(t, want), "unchanged")
					rejectFollower(t, s, followerEnrollment, followerWire(t, 1), ErrFollowerRollback)
				}
			})
		}
	}
}

// The channel barrier holds a real SQL transaction after both state writes and
// before Commit. Deadlines bound failures; no timer guesses transaction entry.
func TestFollowerSQLiteBlockedCommitReadAndClose(t *testing.T) {
	p := dbPath(t)
	s, e := CreateFollowerSQLite(p, followerEnrollment)
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { unblock(); s.Close() })
	old := followerWire(t, 4, followerA("192.0.2.1"))
	next := followerWire(t, 8, followerA("192.0.2.2"))
	acceptFollower(t, s, old, "initial")
	held := followerView(t, s)
	s.hooks.beforeCommit = func(*sql.Tx) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("test barrier timeout")
		}
	}
	type result struct {
		acceptance FollowerAcceptance
		err        error
	}
	accepted := make(chan result, 1)
	go func() { r, e := s.Accept(followerEnrollment, next); accepted <- result{r, e} }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("transaction did not reach barrier")
	}
	read := make(chan FollowerView, 1)
	readError := make(chan error, 1)
	go func() {
		v, e := s.Acquire()
		if e != nil {
			readError <- e
		} else {
			read <- v
		}
	}()
	select {
	case v := <-read:
		if v.State() != held.State() || !bytes.Equal(v.EnvelopeJSON(), old) {
			t.Fatal("uncommitted state visible")
		}
	case e := <-readError:
		t.Fatal(e)
	case <-time.After(time.Second):
		t.Fatal("Acquire blocked behind SQL transaction")
	}
	closeStarted, closed := make(chan struct{}), make(chan error, 1)
	go func() { close(closeStarted); closed <- s.Close() }()
	<-closeStarted
	select {
	case e := <-closed:
		t.Fatalf("Close completed before transaction release: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	if !bytes.Equal(held.EnvelopeJSON(), old) {
		t.Fatal("held view changed during transaction")
	}
	unblock()
	select {
	case r := <-accepted:
		if r.err != nil || r.acceptance.Outcome != "advanced" || r.acceptance.State.Snapshot.Revision != 8 {
			t.Fatalf("acceptance failed: %#v %v", r.acceptance, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("acceptance did not finish")
	}
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish")
	}
	if _, e = s.Acquire(); !errors.Is(e, ErrClosed) {
		t.Fatal("publication resurrected closed store", e)
	}
	rejectFollower(t, s, followerEnrollment, next, ErrClosed)
	if !bytes.Equal(held.EnvelopeJSON(), old) || held.State().Snapshot.Revision != 4 {
		t.Fatal("held view changed after Close")
	}
	reopened := openFollowerTest(t, p)
	v := followerView(t, reopened)
	if !bytes.Equal(v.EnvelopeJSON(), next) {
		t.Fatal("committed generation absent on reopen")
	}
}
func TestFollowerSQLiteChangedContentCrash(t *testing.T) {
	for _, mode := range []string{"before-changed", "after-changed"} {
		t.Run(mode, func(t *testing.T) {
			p := dbPath(t)
			s, e := CreateFollowerSQLite(p, followerEnrollment)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { s.Close() })
			old := followerWire(t, 3, followerA("192.0.2.1"))
			next := followerWire(t, 9007199254740993, followerA("192.0.2.2"))
			acceptFollower(t, s, old, "initial")
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			followerChild(t, p, mode, 71)
			s = openFollowerTest(t, p)
			v := followerView(t, s)
			want := next
			if mode == "before-changed" {
				want = old
			}
			expected, e := recordset.Parse(want)
			if e != nil {
				t.Fatal(e)
			}
			state := FollowerState{Enrollment: followerEnrollment, Snapshot: expected.Metadata()}
			if v.State() != state || !bytes.Equal(v.EnvelopeJSON(), want) || !reflect.DeepEqual(v.Records(), expected.Records()) {
				t.Fatal("crash recovered mixed tuple/revision/digest/content")
			}
			acceptFollower(t, s, want, "unchanged")
			if mode == "after-changed" {
				rejectFollower(t, s, followerEnrollment, old, ErrFollowerRollback)
			}
		})
	}
}
