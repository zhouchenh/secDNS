package adminauth

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"
)

func sessionAgent(t *testing.T, s *Store) (string, Credential) {
	t.Helper()
	g, e := s.CreateBootstrap(BootstrapEnvelope{Scopes: []Scope{UIView, RecordsRead}}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	token, c, e := s.BootstrapIssueAgent(g, CredentialRequest{Name: "viewer", Scopes: []Scope{UIView, RecordsRead}}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	return token, c
}
func TestSessionLifecycleAndRevocation(t *testing.T) {
	s, _, _ := testStore(t)
	bearer, c := sessionAgent(t, s)
	sessions := NewSessions(s)
	token, csrf, i, e := sessions.Exchange(bearer, "realm-a", "node-a", testNow)
	if e != nil || !i.Actor.Allows(UIView) {
		t.Fatal(e)
	}
	if token == bearer || csrf == bearer || token == csrf {
		t.Fatal("credential separation")
	}
	if _, e = sessions.Authenticate(token, "wrong", true, true, testNow); e != ErrDenied {
		t.Fatal(e)
	}
	if _, e = sessions.Authenticate(token, "", false, false, testNow.Add(14*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if _, e = sessions.Authenticate(token, "", false, false, testNow.Add(15*time.Minute)); e != ErrDenied {
		t.Fatal("background read extended idle", e)
	}
	token, csrf, _, e = sessions.Exchange(bearer, "realm-a", "node-a", testNow)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sessions.Authenticate(token, csrf, true, true, testNow.Add(14*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if _, e = sessions.Authenticate(token, "", false, false, testNow.Add(16*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if _, e = NewSessions(s).Authenticate(token, "", false, false, testNow); e != ErrDenied {
		t.Fatal("restart session survived")
	}
	if e = s.RevokeLocal(c.ID, testNow); e != nil {
		t.Fatal(e)
	}
	if _, e = sessions.Authenticate(token, "", false, false, testNow); e != ErrDenied {
		t.Fatal("revoke session survived", e)
	}
}
func TestSessionAbsoluteLogoutAndAuditFailure(t *testing.T) {
	s, _, _ := testStore(t)
	bearer, _ := sessionAgent(t, s)
	ss := NewSessions(s)
	token, csrf, _, e := ss.Exchange(bearer, "realm-a", "node-a", testNow)
	if e != nil {
		t.Fatal(e)
	}
	for n := 1; n < 12; n++ {
		if _, e = ss.Authenticate(token, csrf, true, true, testNow.Add(time.Duration(n)*10*time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = ss.Authenticate(token, csrf, true, true, testNow.Add(2*time.Hour)); e != ErrDenied {
		t.Fatal(e)
	}
	token, csrf, _, e = ss.Exchange(bearer, "realm-a", "node-a", testNow)
	if e != nil {
		t.Fatal(e)
	}
	if e = ss.Logout(token, csrf, testNow); e != nil {
		t.Fatal(e)
	}
	if _, e = ss.Authenticate(token, "", false, false, testNow); e != ErrDenied {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("CREATE TRIGGER reject_session BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'synthetic'); END"); e != nil {
		t.Fatal(e)
	}
	if token, _, _, e = ss.Exchange(bearer, "realm-a", "node-a", testNow); e != ErrUnavailable || token != "" {
		t.Fatal("unaudited session", e)
	}
}
func TestExplicitSchemaMigration(t *testing.T) {
	s, path, key := testStore(t)
	bearer, _ := sessionAgent(t, s)
	s.Close()
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("PRAGMA user_version=1"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if _, e = Open(path, key, testIdentity, nil); e != ErrInvalid {
		t.Fatal("automatic migration", e)
	}
	if e = MigrateSchema1(path, key, testIdentity, nil); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Verify(bearer, "realm-a", "node-a", testNow); e != nil {
		t.Fatal("migration lost credential", e)
	}
}

func TestSessionCloseAndMetadataOwnership(t *testing.T) {
	s, _, _ := testStore(t)
	bearer, _ := sessionAgent(t, s)
	ss := NewSessions(s)
	token, _, initial, e := ss.Exchange(bearer, "realm-a", "node-a", testNow)
	if e != nil {
		t.Fatal(e)
	}
	permissions := initial.Actor.Scopes()
	permissions[0] = AuditRead
	current, e := ss.Authenticate(token, "", false, false, testNow)
	if e != nil || current.Actor.Allows(AuditRead) {
		t.Fatal("metadata alias", e)
	}
	ss.Close()
	if _, e = ss.Authenticate(token, "", false, false, testNow); e != ErrUnavailable {
		t.Fatal("closed session accepted", e)
	}
	if _, _, _, e = ss.Exchange(bearer, "realm-a", "node-a", testNow); e != ErrUnavailable {
		t.Fatal("closed registry reopened", e)
	}
}

func TestMigrationFailureIsTransactionalAndAmbiguityRequiresReopen(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "committed-error"}[committed], func(t *testing.T) {
			s, path, key := testStore(t)
			bearer, _ := sessionAgent(t, s)
			s.Close()
			db, e := sql.Open("sqlite", path)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec("PRAGMA user_version=1"); e != nil {
				t.Fatal(e)
			}
			db.Close()
			before, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			handle, e := openWithCommit(path, key, testIdentity, nil, false, true, func(tx *sql.Tx) error {
				if committed {
					if e := tx.Commit(); e != nil {
						return e
					}
				}
				return errors.New("synthetic commit uncertainty")
			})
			if e != ErrUnavailable || handle != nil {
				t.Fatal("uncertain migration accepted", e)
			}
			after, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if !committed {
				if sha256.Sum256(before) != sha256.Sum256(after) {
					t.Fatal("failed migration changed database")
				}
				if _, e = Open(path, key, testIdentity, nil); e != ErrInvalid {
					t.Fatal("schema1 accepted", e)
				}
				if e = MigrateSchema1(path, key, testIdentity, nil); e != nil {
					t.Fatal(e)
				}
			} else if e = MigrateSchema1(path, key, testIdentity, nil); e != ErrInvalid {
				t.Fatal("migration replay accepted", e)
			}
			s, e = Open(path, key, testIdentity, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if _, e = s.Verify(bearer, "realm-a", "node-a", testNow); e != nil {
				t.Fatal("credential lost", e)
			}
		})
	}
}

func TestCapacityPrunesDurablyExpiredCredentialSessions(t *testing.T) {
	s, _, _ := testStore(t)
	permissions := []Scope{UIView, RecordsRead}
	expiry := testNow.Add(time.Minute)
	grant, e := s.CreateBootstrap(BootstrapEnvelope{Scopes: permissions, CredentialExpiresAt: expiry}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	bearer, _, e := s.BootstrapIssueAgent(grant, CredentialRequest{Name: "short-lived", Scopes: permissions, ExpiresAt: expiry}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	ss := NewSessions(s)
	for n := 0; n < MaxSessions; n++ {
		if _, _, _, e = ss.Exchange(bearer, "realm-a", "node-a", testNow); e != nil {
			t.Fatal(n, e)
		}
	}
	if _, _, _, e = ss.Exchange(bearer, "realm-a", "node-a", testNow); e != ErrUnavailable {
		t.Fatal("capacity not enforced", e)
	}
	later := testNow.Add(2 * time.Minute)
	grant, e = s.CreateBootstrap(BootstrapEnvelope{Scopes: permissions}, later)
	if e != nil {
		t.Fatal(e)
	}
	fresh, _, e := s.BootstrapIssueAgent(grant, CredentialRequest{Name: "fresh", Scopes: permissions}, later)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = ss.Exchange(fresh, "realm-a", "node-a", later); e != nil {
		t.Fatal("expired credentials monopolized capacity", e)
	}
	if len(ss.entries) != 1 {
		t.Fatal("expired sessions retained")
	}
}
