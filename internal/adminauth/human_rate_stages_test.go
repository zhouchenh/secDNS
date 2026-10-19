package adminauth

import (
	"testing"
	"time"
)

func TestHumanPasswordDebtDoesNotBlockItsMFAChallenge(t *testing.T) {
	s, _, h, _, _ := humanStore(t)
	_, en := setupHuman(t, s, h)
	now := testNow.Add(time.Minute)
	for i := 0; i < 13; i++ {
		if e := s.rateAttempt("127.0.0.1", now); e != nil {
			t.Fatal(e)
		}
		now = now.Add(513 * time.Second)
	}
	challenge, e := h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.rateAttempt("127.0.0.1", now); e != ErrDenied {
		t.Fatal("password admission did not preserve debt", e)
	}
	if _, e = h.Confirm(challenge, enrollmentOTP(t, en, now), "127.0.0.1", now); e != nil {
		t.Fatal("valid MFA could not complete within five minutes", e)
	}
	if _, e = h.Confirm(challenge, enrollmentOTP(t, en, now), "127.0.0.1", now); e != ErrDenied {
		t.Fatal("replayed completed challenge", e)
	}
}

func TestHumanWrongMFADebtSurvivesCeremonyAndRestart(t *testing.T) {
	s, ss, h, path, key := humanStore(t)
	_, en := setupHuman(t, s, h)
	now := testNow.Add(time.Minute)
	challenge, e := h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 6; i++ {
		if i == 5 {
			challenge, e = h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
			if e != nil {
				t.Fatal(e)
			}
		}
		if _, e = h.Confirm(challenge, "not-an-otp", "127.0.0.1", now); e != ErrDenied {
			t.Fatal("invalid OTP accepted", e)
		}
	}
	if _, e = h.PasswordLogin("owner", humanPassword, "127.0.0.1", now); e != ErrDenied {
		t.Fatal("new ceremony bypassed MFA cooldown", e)
	}
	h.Close()
	ss.Close()
	s.Close()
	s, e = Open(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ss = NewSessions(s)
	defer ss.Close()
	h = NewHumanAuth(s, ss)
	defer h.Close()
	if e = s.mfaEligible("127.0.0.1", now); e != ErrDenied {
		t.Fatal("restart erased durable MFA debt", e)
	}
	if _, e = h.Confirm(challenge, enrollmentOTP(t, en, now), "127.0.0.1", now); e != ErrDenied {
		t.Fatal("restart revived challenge", e)
	}
	now = now.Add(3 * time.Second)
	challenge, e = h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Confirm(challenge, enrollmentOTP(t, en, now), "127.0.0.1", now); e != nil {
		t.Fatal("valid recovery from cooldown failed", e)
	}
	if e = s.mfaEligible("127.0.0.1", now); e != nil {
		t.Fatal("complete authentication did not clear MFA debt", e)
	}
}

func TestHumanAllCeremoniesAndReauthRespectMFADebt(t *testing.T) {
	s, _, h, _, _ := humanStore(t)
	current, en := setupHuman(t, s, h)
	now := testNow.Add(time.Minute)
	for i := 0; i < 6; i++ {
		if e := s.rateAttemptMFA("127.0.0.1", now); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := h.BeginReplacement(current.Token, current.Session.CSRF, "127.0.0.1", now); e != ErrDenied {
		t.Fatal("replacement bypassed cooldown", e)
	}
	grant, e := s.CreateHumanGrant(true, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.BeginEnrollment(grant, "owner", "Owner", humanPassword, "127.0.0.1", true, now); e != ErrDenied {
		t.Fatal("local recovery bypassed cooldown", e)
	}
	if _, e = h.BeginCodeRecovery("owner", humanPassword, current.RecoveryCodes[0], "127.0.0.1", now); e != ErrDenied {
		t.Fatal("code recovery bypassed cooldown", e)
	}
	if _, e = h.Reauthenticate(current.Token, current.Session.CSRF, humanPassword, enrollmentOTP(t, en, now), "127.0.0.1", now); e != ErrDenied {
		t.Fatal("combined reauth bypassed cooldown", e)
	}
	if _, e = h.sessions.Authenticate(current.Token, current.Session.CSRF, true, false, now); e != nil {
		t.Fatal("cooldown changed original session", e)
	}
	if e = s.mfaEligible("127.0.0.1", now.Add(24*time.Hour+time.Second)); e != nil {
		t.Fatal("stale budget mismatch", e)
	}
	later := now.Add(3 * time.Second)
	if _, e = h.Reauthenticate(current.Token, current.Session.CSRF, humanPassword, enrollmentOTP(t, en, later), "127.0.0.1", later); e != nil {
		t.Fatal("reauth after cooldown", e)
	}
}

func TestHumanMFAAccountingFailureDoesNotAuthenticate(t *testing.T) {
	s, _, h, _, _ := humanStore(t)
	_, en := setupHuman(t, s, h)
	now := testNow.Add(time.Minute)
	challenge, e := h.PasswordLogin("owner", humanPassword, "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("CREATE TRIGGER reject_mfa_rate BEFORE INSERT ON human_rate BEGIN SELECT RAISE(ABORT,'synthetic'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e = h.Confirm(challenge, enrollmentOTP(t, en, now), "127.0.0.1", now); e != ErrUnavailable {
		t.Fatal("undurable MFA budget permitted authentication", e)
	}
	if _, e = s.db.Exec("DROP TRIGGER reject_mfa_rate"); e != nil {
		t.Fatal(e)
	}
	if _, e = h.Confirm(challenge, enrollmentOTP(t, en, now), "127.0.0.1", now); e != nil {
		t.Fatal("failed budget write consumed valid OTP", e)
	}
}
