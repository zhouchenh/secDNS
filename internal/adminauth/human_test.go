package adminauth

import (
	"database/sql"
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const humanPassword = "A private phrase with spaces 2091!"

func humanStore(t *testing.T) (*Store, *Sessions, *HumanAuth, string, string) {
	t.Helper()
	s, p, k := testStore(t)
	s.Close()
	if e := EnableHumanSchema(p, k, testIdentity, nil); e != nil {
		t.Fatal(e)
	}
	s, e := Open(p, k, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	ss := NewSessions(s)
	h := NewHumanAuth(s, ss)
	t.Cleanup(func() { h.Close(); ss.Close(); s.Close() })
	return s, ss, h, p, k
}
func enrollmentOTP(t *testing.T, en Enrollment, now time.Time) string {
	t.Helper()
	b, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en.Secret)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(b)
	return otp(b, now.Unix()/30)
}
func setupHuman(t *testing.T, s *Store, h *HumanAuth) (HumanResult, Enrollment) {
	t.Helper()
	g, e := s.CreateHumanGrant(false, testNow)
	if e != nil {
		t.Fatal(e)
	}
	en, e := h.BeginEnrollment(g, "owner", "Owner", humanPassword, "127.0.0.1", false, testNow)
	if e != nil {
		t.Fatal(e)
	}
	r, e := h.Confirm(en.Challenge, enrollmentOTP(t, en, testNow), "127.0.0.1", testNow)
	if e != nil {
		t.Fatal(e)
	}
	return r, en
}
func TestHumanSetupLoginRecoveryAndReopen(t *testing.T) {
	s, ss, h, path, key := humanStore(t)
	result, en := setupHuman(t, s, h)
	if len(result.RecoveryCodes) != 10 || result.Session.Actor.Kind() != "human" {
		t.Fatal("human result")
	}
	if result.Session.ExpiresAt.Sub(testNow) != 12*time.Hour || result.Session.IdleExpiresAt.Sub(testNow) != 30*time.Minute {
		t.Fatal("human limits")
	}
	if _, e := h.Confirm(en.Challenge, enrollmentOTP(t, en, testNow), "127.0.0.1", testNow); e != ErrDenied {
		t.Fatal("ceremony replay", e)
	}
	now := testNow.Add(30 * time.Second)
	challenge, e := h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	login, e := h.Confirm(challenge, enrollmentOTP(t, en, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	challenge, e = h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Confirm(challenge, enrollmentOTP(t, en, now), "127.0.0.1", now); e != ErrDenied {
		t.Fatal("OTP replay", e)
	}
	now = now.Add(30 * time.Second)
	recovery, e := h.BeginCodeRecovery("owner", humanPassword, result.RecoveryCodes[0], "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	// Starting recovery retains the working owner and existing sessions.
	if _, e = ss.Authenticate(login.Token, "", false, false, now); e != nil {
		t.Fatal("pending recovery invalidated session", e)
	}
	recovered, e := h.Confirm(recovery.Challenge, enrollmentOTP(t, recovery, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if len(recovered.RecoveryCodes) != 10 {
		t.Fatal("new codes")
	}
	if _, e = ss.Authenticate(login.Token, "", false, false, now); e != ErrDenied {
		t.Fatal("old epoch alive", e)
	}
	if _, e = h.BeginCodeRecovery("owner", humanPassword, result.RecoveryCodes[0], "127.0.0.1", now.Add(time.Minute)); e != ErrDenied {
		t.Fatal("old recovery code alive", e)
	}
	h.Close()
	ss.Close()
	s.Close()
	s, e = Open(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal("strict reopen", e)
	}
	defer s.Close()
	fresh := NewSessions(s)
	defer fresh.Close()
	if _, e = fresh.Authenticate(recovered.Token, "", false, false, now); e != ErrDenied {
		t.Fatal("restart retained session", e)
	}
}
func TestHumanEnrollmentCommitFailureKeepsGrantAndOldState(t *testing.T) {
	s, _, h, _, _ := humanStore(t)
	g, e := s.CreateHumanGrant(false, testNow)
	if e != nil {
		t.Fatal(e)
	}
	en, e := h.BeginEnrollment(g, "owner", "Owner", humanPassword, "peer", false, testNow)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	s.commit = func(tx *sql.Tx) error {
		calls++
		if calls == 1 {
			return tx.Commit()
		}
		return errors.New("test commit")
	}
	if _, e = h.Confirm(en.Challenge, enrollmentOTP(t, en, testNow), "peer", testNow); e != ErrUnavailable {
		t.Fatal(e)
	}
	if !s.faulted {
		t.Fatal("uncertain handle not faulted")
	}
	var n int
	s.db.QueryRow("SELECT count(*) FROM human").Scan(&n)
	if n != 0 {
		t.Fatal("owner published")
	}
	s.db.QueryRow("SELECT count(*) FROM human_grant").Scan(&n)
	if n != 1 {
		t.Fatal("grant consumed")
	}
}
func TestHumanPasswordAndSeedBounds(t *testing.T) {
	for _, v := range []string{"short", strings.Repeat("x", 257), "password123456789", "line\nbreak-long-password"} {
		if validPassword(v, "owner") {
			t.Fatal("bad password allowed")
		}
	}
	if !validPassword("  A long exact phrase  ", "owner") {
		t.Fatal("spaces normalized")
	}
	p, e := passwordHash(humanPassword)
	if e != nil {
		t.Fatal(e)
	}
	if passwordVerify(humanPassword, p) != nil || passwordVerify(humanPassword+" ", p) != ErrDenied {
		t.Fatal("password exactness")
	}
	if _, _, e = parsePHC(strings.Replace(p, "m=65536", "m=65536000", 1)); e == nil {
		t.Fatal("unbounded PHC")
	}
}
func TestHumanRateLimitPersistsAndSourceBound(t *testing.T) {
	s, _, h, path, key := humanStore(t)
	g, e := s.CreateHumanGrant(false, testNow)
	if e != nil {
		t.Fatal(e)
	}
	en, e := h.BeginEnrollment(g, "owner", "Owner", humanPassword, "peer-a", false, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Confirm(en.Challenge, enrollmentOTP(t, en, testNow), "peer-b", testNow); e != ErrDenied {
		t.Fatal("source changed")
	}
	for i := 0; i < 8; i++ {
		_ = s.rateAttempt("peer-a", testNow)
	}
	s.Close()
	s, e = Open(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.rateAttempt("peer-a", testNow); e != ErrDenied {
		t.Fatal("rate reset at restart", e)
	}
}

func TestHumanGrantConcurrentOneWinner(t *testing.T) {
	s, _, h, _, _ := humanStore(t)
	grant, e := s.CreateHumanGrant(false, testNow)
	if e != nil {
		t.Fatal(e)
	}
	first, e := h.BeginEnrollment(grant, "owner", "Owner", humanPassword, "peer", false, testNow)
	if e != nil {
		t.Fatal(e)
	}
	second, e := h.BeginEnrollment(grant, "other", "Other", humanPassword, "peer", false, testNow)
	if e != nil {
		t.Fatal(e)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for _, en := range []Enrollment{first, second} {
		wg.Add(1)
		go func(en Enrollment) {
			defer wg.Done()
			if _, e := h.Confirm(en.Challenge, enrollmentOTP(t, en, testNow), "peer", testNow); e == nil {
				wins.Add(1)
			}
		}(en)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("grant redemption winners", wins.Load())
	}
}
func TestHumanRootRecoveryAndSecurityScopes(t *testing.T) {
	s, ss, h, _, _ := humanStore(t)
	initial, en := setupHuman(t, s, h)
	now := testNow.Add(30 * time.Second)
	challenge, e := h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	other, e := h.Confirm(challenge, enrollmentOTP(t, en, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.RevokeOtherSessions(initial.Token, initial.Session.CSRF, now); e != nil {
		t.Fatal(e)
	}
	if _, e = ss.Authenticate(other.Token, "", false, false, now); e != ErrDenied {
		t.Fatal("other session retained")
	}
	if _, e = h.RegenerateRecovery(initial.Token, initial.Session.CSRF, testNow.Add(5*time.Minute)); e != ErrDenied {
		t.Fatal("stale reauth allowed", e)
	}
	now = testNow.Add(time.Minute)
	reauth, e := h.Reauthenticate(initial.Token, initial.Session.CSRF, humanPassword, enrollmentOTP(t, en, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ss.Authenticate(initial.Token, "", false, false, now); e != ErrDenied {
		t.Fatal("reauth did not rotate")
	}
	if _, e = h.RegenerateRecovery(reauth.Token, reauth.Session.CSRF, now); e != nil {
		t.Fatal(e)
	}
	bearer, _ := sessionAgent(t, s)
	agent, csrf, _, e := ss.Exchange(bearer, "realm-a", "node-a", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.ChangePassword(agent, csrf, "Another strong phrase from the owner!", now); e != ErrDenied {
		t.Fatal("agent changed owner password", e)
	}
	grant, e := s.CreateHumanGrant(true, now)
	if e != nil {
		t.Fatal(e)
	}
	recovery, e := h.BeginEnrollment(grant, "recovered", "Recovered", "New private phrase after recovery!", "127.0.0.1", true, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ss.Authenticate(reauth.Token, "", false, false, now); e != nil {
		t.Fatal("pending local recovery ended session")
	}
	result, e := h.Confirm(recovery.Challenge, enrollmentOTP(t, recovery, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ss.Authenticate(reauth.Token, "", false, false, now); e != ErrDenied {
		t.Fatal("root recovery left old session")
	}
	if _, e = h.BeginEnrollment(grant, "recovered", "Recovered", "New private phrase after recovery!", "127.0.0.1", true, now); e != ErrDenied {
		t.Fatal("root grant replay", e)
	}
	if result.Session.Actor.Kind() != "human" {
		t.Fatal("missing recovered human")
	}
}
func TestHumanStrictReopenAndTOTPVector(t *testing.T) {
	if otp([]byte("12345678901234567890"), 1) != "287082" {
		t.Fatal("RFC6238 vector")
	}
	s, _, h, path, key := humanStore(t)
	setupHuman(t, s, h)
	s.Close()
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("UPDATE human SET seed=zeroblob(48)"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if reopened, e := Open(path, key, testIdentity, nil); e == nil {
		reopened.Close()
		t.Fatal("corrupt encrypted seed opened")
	}
}

func TestHumanReplacementRequiresRecentSessionAndKeepsOldUntilCommit(t *testing.T) {
	s, ss, h, _, _ := humanStore(t)
	initial, old := setupHuman(t, s, h)
	now := testNow.Add(30 * time.Second)
	en, e := h.BeginReplacement(initial.Token, initial.Session.CSRF, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Confirm(en.Challenge, enrollmentOTP(t, en, now), "127.0.0.1", now); e != ErrDenied {
		t.Fatal("public confirmation replaced factor", e)
	}
	login, e := h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Confirm(login, enrollmentOTP(t, old, now), "127.0.0.1", now); e != nil {
		t.Fatal("old factor lost before replacement", e)
	}
	result, e := h.ConfirmReplacement(initial.Token, initial.Session.CSRF, en.Challenge, enrollmentOTP(t, en, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ss.Authenticate(initial.Token, "", false, false, now); e != ErrDenied {
		t.Fatal("old session survived replacement")
	}
	if result.Session.Actor.Kind() != "human" {
		t.Fatal("replacement session")
	}
}

func TestHumanMigrationFaultAndPasswordChangeDoesNotExtendMFA(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "uncertain-committed"}[committed], func(t *testing.T) {
			s, path, key := testStore(t)
			s.commit = func(tx *sql.Tx) error {
				if committed {
					if e := tx.Commit(); e != nil {
						return e
					}
				}
				return errors.New("migration uncertainty")
			}
			s.mu.Lock()
			e := s.enableHumanSchema()
			s.mu.Unlock()
			if e != ErrUnavailable || !s.faulted {
				t.Fatal("migration ambiguity", e)
			}
			s.Close()
			reopened, e := Open(path, key, testIdentity, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if reopened.HumanEnabled() != committed {
				t.Fatal("unexpected durable migration state")
			}
		})
	}
	s, _, h, _, _ := humanStore(t)
	initial, _ := setupHuman(t, s, h)
	now := testNow.Add(4 * time.Minute)
	changed, e := h.ChangePassword(initial.Token, initial.Session.CSRF, "Another private password phrase 2092!", now)
	if e != nil {
		t.Fatal(e)
	}
	if !changed.Session.AuthenticatedAt.Equal(testNow) {
		t.Fatal("password rotation renewed MFA")
	}
	if _, e = h.RecentHuman(changed.Token, changed.Session.CSRF, testNow.Add(5*time.Minute)); e != ErrDenied {
		t.Fatal("reauth window extended", e)
	}
}

func TestHumanCapacityPrunesOnlyInvalidEpochAfterPasswordChange(t *testing.T) {
	s, ss, h, _, _ := humanStore(t)
	owner, _ := setupHuman(t, s, h)
	bearer, _ := sessionAgent(t, s)
	agent, _, _, e := ss.Exchange(bearer, "realm-a", "node-a", testNow)
	if e != nil {
		t.Fatal(e)
	}
	for len(ss.entries) < MaxSessions {
		if _, _, e = ss.issueHuman(owner.Session.Actor, testNow); e != nil {
			t.Fatal(e)
		}
	}
	changed, e := h.ChangePassword(owner.Token, owner.Session.CSRF, "Another private password phrase 2092!", testNow.Add(time.Second))
	if e != nil {
		t.Fatal("durable password change must issue new session", e)
	}
	if len(ss.entries) != 2 {
		t.Fatal("invalid epoch entries retained", len(ss.entries))
	}
	if _, e = ss.Authenticate(agent, "", false, false, testNow.Add(time.Second)); e != nil {
		t.Fatal("valid agent evicted", e)
	}
	if _, e = ss.Authenticate(changed.Token, "", false, false, testNow.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	for len(ss.entries) < MaxSessions {
		if _, _, e = ss.issueHuman(changed.Session.Actor, testNow.Add(time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	if _, _, e = ss.issueHuman(changed.Session.Actor, testNow.Add(time.Second)); e != ErrUnavailable {
		t.Fatal("current epoch evicted", e)
	}
	if len(ss.entries) != MaxSessions {
		t.Fatal("valid session eviction")
	}
	s.faulted = true
	if _, _, e = ss.issueHuman(changed.Session.Actor, testNow.Add(time.Second)); e != ErrUnavailable {
		t.Fatal("fault not closed", e)
	}
	if len(ss.entries) != MaxSessions {
		t.Fatal("fault evicted sessions")
	}
}

func TestHumanLoginReauthSingleAuditAndAtomicFailure(t *testing.T) {
	s, ss, h, _, _ := humanStore(t)
	owner, en := setupHuman(t, s, h)
	before, e := s.AuditLocal(100)
	if e != nil {
		t.Fatal(e)
	}
	now := testNow.Add(30 * time.Second)
	ch, e := h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	logged, e := h.Confirm(ch, enrollmentOTP(t, en, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	events, e := s.AuditLocal(100)
	if e != nil || len(events) != len(before)+1 || events[0].Action != "human_login" {
		t.Fatal("login audit", events, e)
	}
	now = now.Add(30 * time.Second)
	rotated, e := h.Reauthenticate(logged.Token, logged.Session.CSRF, humanPassword, enrollmentOTP(t, en, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	events, e = s.AuditLocal(100)
	if e != nil || len(events) != len(before)+2 || events[0].Action != "human_reauth" || events[1].Action != "human_login" {
		t.Fatal("reauth audit", events, e)
	}
	if _, e = ss.Authenticate(logged.Token, "", false, false, now); e != ErrDenied {
		t.Fatal("old rotation session", e)
	}
	count := len(ss.entries)
	var counter int64
	if e = s.db.QueryRow("SELECT counter FROM human").Scan(&counter); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("CREATE TRIGGER reject_human_audit BEFORE INSERT ON audit WHEN NEW.action IN ('human_login','human_reauth') BEGIN SELECT RAISE(ABORT,'test'); END"); e != nil {
		t.Fatal(e)
	}
	now = now.Add(30 * time.Second)
	if _, e = h.Reauthenticate(rotated.Token, rotated.Session.CSRF, humanPassword, enrollmentOTP(t, en, now), "127.0.0.1", now); e != ErrUnavailable {
		t.Fatal("audit failure", e)
	}
	if len(ss.entries) != count {
		t.Fatal("undisclosed session")
	}
	if _, e = ss.Authenticate(rotated.Token, "", false, false, now); e != nil {
		t.Fatal("old session lost on failed rotation", e)
	}
	var after int64
	if e = s.db.QueryRow("SELECT counter FROM human").Scan(&after); e != nil || after != counter {
		t.Fatal("failed audit consumed OTP", after, e)
	}
	events, e = s.AuditLocal(100)
	if e != nil || len(events) != len(before)+2 {
		t.Fatal("failed audit changed history", e)
	}
	ch, e = h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Confirm(ch, enrollmentOTP(t, en, now), "127.0.0.1", now); e != ErrUnavailable {
		t.Fatal(e)
	}
	if len(ss.entries) != count {
		t.Fatal("failed login published session")
	}
	if _, e = s.db.Exec("DROP TRIGGER reject_human_audit"); e != nil {
		t.Fatal(e)
	}
	if _, e = ss.Authenticate(owner.Token, "", false, false, now); e != nil {
		t.Fatal(e)
	}
}

func TestHumanRecoverySetCorruptionRefusesReopen(t *testing.T) {
	for _, predicate := range []string{"id=1", "1=1"} {
		t.Run(predicate, func(t *testing.T) {
			s, _, h, path, key := humanStore(t)
			setupHuman(t, s, h)
			if _, e := s.db.Exec("DELETE FROM recovery_codes WHERE " + predicate); e != nil {
				t.Fatal(e)
			}
			s.Close()
			reopened, e := Open(path, key, testIdentity, nil)
			if e == nil {
				reopened.Close()
				t.Fatal("incomplete recovery set accepted")
			}
		})
	}
}
