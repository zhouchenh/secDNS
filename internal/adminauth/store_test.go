package adminauth

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testIdentity = Identity{"realm-a", "node-a", "Test realm"}
var testNow = time.Unix(1800000000, 0).UTC()

func testStore(t *testing.T) (*Store, string, string) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path, key := filepath.Join(dir, "auth.db"), filepath.Join(dir, "auth.key")
	if e := CreateKey(key); e != nil {
		t.Fatal(e)
	}
	s, e := Create(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, path, key
}
func issue(t *testing.T, s *Store) (string, Credential) {
	t.Helper()
	grant, e := s.CreateBootstrap(BootstrapEnvelope{Scopes: []Scope{UIView, RecordsRead}}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	token, c, e := s.BootstrapIssueAgent(grant, CredentialRequest{Name: "reader", Scopes: []Scope{RecordsRead}}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	return token, c
}

func TestIssueVerifyRevokeRestart(t *testing.T) {
	s, path, key := testStore(t)
	token, c := issue(t, s)
	a, e := s.Verify(token, "realm-a", "node-a", testNow)
	if e != nil || !a.Allows(RecordsRead) || a.Allows(RecordsWrite) || a.Kind() != "agent" {
		t.Fatalf("actor: %v", e)
	}
	c.Scopes[0] = RecordsWrite
	copy := a.Scopes()
	copy[0] = RecordsWrite
	if !a.Allows(RecordsRead) || a.Allows(RecordsWrite) {
		t.Fatal("scope alias")
	}
	if _, e = s.Verify(token, "realm-a", "node-b", testNow); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Verify(token, "realm-a", "node-a", testNow); e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeLocal(c.ID, testNow.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Verify(token, "realm-a", "node-a", testNow.Add(time.Second)); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	events, e := s.AuditLocal(100)
	if e != nil || len(events) != 3 {
		t.Fatalf("events %d %v", len(events), e)
	}
	for _, a := range events {
		if strings.Contains(a.Action, token) {
			t.Fatal("token audit leakage")
		}
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Verify(token, "realm-a", "node-a", testNow); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
}
func TestBootstrapAtomicSubsetExpiry(t *testing.T) {
	s, _, _ := testStore(t)
	cap := testNow.Add(time.Hour)
	grant, e := s.CreateBootstrap(BootstrapEnvelope{[]Scope{RecordsRead}, cap}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range []CredentialRequest{{Name: "bad", Scopes: []Scope{RecordsWrite}, ExpiresAt: cap}, {Name: "bad", Scopes: []Scope{RecordsRead}}, {Name: "bad", Scopes: []Scope{RecordsRead}, ExpiresAt: cap.Add(time.Second)}} {
		if _, _, e = s.BootstrapIssueAgent(grant, r, testNow); !errors.Is(e, ErrDenied) {
			t.Fatal(e)
		}
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, e := s.BootstrapIssueAgent(grant, CredentialRequest{Name: "reader", Scopes: []Scope{RecordsRead}, ExpiresAt: cap}, testNow)
			if e == nil {
				successes.Add(1)
			} else if !errors.Is(e, ErrDenied) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("grant redeemed more than once")
	}
	g, e := s.CreateBootstrap(BootstrapEnvelope{Scopes: []Scope{RecordsRead}}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.BootstrapIssueAgent(g, CredentialRequest{Name: "late", Scopes: []Scope{RecordsRead}}, testNow.Add(10*time.Minute)); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
}
func TestAuditFailureRollsBackAndCommitUncertaintyFaults(t *testing.T) {
	s, path, key := testStore(t)
	grant, e := s.CreateBootstrap(BootstrapEnvelope{Scopes: []Scope{RecordsRead}}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("CREATE TRIGGER reject_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'private backend detail'); END"); e != nil {
		t.Fatal(e)
	}
	req := CredentialRequest{Name: "reader", Scopes: []Scope{RecordsRead}}
	token, _, e := s.BootstrapIssueAgent(grant, req, testNow)
	if e != ErrUnavailable || token != "" {
		t.Fatal("audit failure not redacted/atomic", e)
	}
	var n int
	if e = s.db.QueryRow("SELECT count(*) FROM credentials").Scan(&n); e != nil || n != 0 {
		t.Fatal("partial credential")
	}
	if e = s.db.QueryRow("SELECT count(*) FROM bootstrap").Scan(&n); e != nil || n != 1 {
		t.Fatal("consumed grant")
	}
	if _, e = s.db.Exec("DROP TRIGGER reject_audit"); e != nil {
		t.Fatal(e)
	}
	s.commit = func(tx *sql.Tx) error {
		if e := tx.Commit(); e != nil {
			return e
		}
		return errors.New("simulated lost commit acknowledgement")
	}
	token, _, e = s.BootstrapIssueAgent(grant, req, testNow)
	if e != ErrUnavailable || token != "" {
		t.Fatal(e)
	}
	if _, e = s.AuditLocal(1); e != ErrUnavailable {
		t.Fatal("faulted handle published state")
	}
	s.Close()
	s, e = Open(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, _, e = s.BootstrapIssueAgent(grant, req, testNow); e != ErrDenied {
		t.Fatal("replayed committed grant", e)
	}
}
func TestStrictOpenAndKeyIdentity(t *testing.T) {
	s, path, key := testStore(t)
	token, _ := issue(t, s)
	if _, e := Open(path, key, testIdentity, nil); e == nil {
		t.Fatal("second owner accepted")
	}
	s.Close()
	if _, e := Create(path, key, testIdentity, nil); e != ErrExists {
		t.Fatal(e)
	}
	other := filepath.Join(filepath.Dir(key), "other.key")
	if e := CreateKey(other); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(path, other, testIdentity, nil); e == nil {
		t.Fatal("wrong key accepted")
	}
	bad := testIdentity
	bad.NodeID = "node-b"
	if _, e := Open(path, key, bad, nil); e == nil {
		t.Fatal("wrong node accepted")
	}
	if _, e := Open(path, key, testIdentity, []string{token}); e == nil {
		t.Fatal("legacy collision accepted")
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("CREATE TABLE extra(x)"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if _, e := Open(path, key, testIdentity, nil); e == nil {
		t.Fatal("extra schema accepted")
	}
}
func TestExpiryCloseAndConcurrentRevoke(t *testing.T) {
	s, _, _ := testStore(t)
	g, e := s.CreateBootstrap(BootstrapEnvelope{Scopes: []Scope{RecordsRead}}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	token, c, e := s.BootstrapIssueAgent(g, CredentialRequest{Name: "short", Scopes: []Scope{RecordsRead}, ExpiresAt: testNow.Add(time.Second)}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Verify(token, "realm-a", "node-a", testNow.Add(time.Second)); e != ErrDenied {
		t.Fatal("expiry boundary", e)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.Verify(token, "realm-a", "node-a", testNow)
			if e != nil && e != ErrDenied {
				t.Error(e)
			}
		}()
	}
	if e = s.RevokeLocal(c.ID, testNow); e != nil {
		t.Fatal(e)
	}
	wg.Wait()
	if _, e = s.Verify(token, "realm-a", "node-a", testNow); e != ErrDenied {
		t.Fatal(e)
	}
	s.Close()
	if _, e = s.Verify(token, "realm-a", "node-a", testNow); e != ErrUnavailable {
		t.Fatal(e)
	}
	if (Actor{}).Allows(RecordsRead) {
		t.Fatal("zero actor has authority")
	}
}

func TestCapacityDoesNotEvictAndRevokeAuditIsAtomic(t *testing.T) {
	s, _, _ := testStore(t)
	firstToken, first := issue(t, s)
	for i := 1; i < maxCredentials; i++ {
		issue(t, s)
	}
	grant, e := s.CreateBootstrap(BootstrapEnvelope{Scopes: []Scope{RecordsRead}}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if token, _, e := s.BootstrapIssueAgent(grant, CredentialRequest{Name: "over-cap", Scopes: []Scope{RecordsRead}}, testNow); e != ErrDenied || token != "" {
		t.Fatal("capacity admitted", e)
	}
	if _, e = s.Verify(firstToken, "realm-a", "node-a", testNow); e != nil {
		t.Fatal("capacity evicted credential", e)
	}
	if _, e = s.db.Exec("CREATE TRIGGER reject_revoke_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'synthetic'); END"); e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeLocal(first.ID, testNow); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, e = s.Verify(firstToken, "realm-a", "node-a", testNow); e != nil {
		t.Fatal("failed audit partially revoked", e)
	}
	if _, e = s.db.Exec("DROP TRIGGER reject_revoke_audit"); e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeLocal(first.ID, testNow); e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeLocal(first.ID, testNow); e != ErrDenied {
		t.Fatal("repeat revoke must not create success event", e)
	}
	if e = s.RevokeLocal(strings.Repeat("0", 32), testNow); e != ErrDenied {
		t.Fatal(e)
	}
}
