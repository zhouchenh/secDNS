package adminauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"strings"
	"testing"
	"time"
)

const testPasskeyOrigin = "https://admin.invalid"

func passkeyFixture(t *testing.T) (*Store, *Sessions, *HumanAuth, *PasskeyAuth, HumanResult) {
	t.Helper()
	s, ss, h, _, _ := humanStore(t)
	r, _ := setupHuman(t, s, h)
	s.mu.Lock()
	e := s.enablePasskeySchema(testPasskeyOrigin, "admin.invalid")
	s.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	p, e := NewPasskeyAuth(h, testPasskeyOrigin, "admin.invalid")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	return s, ss, h, p, r
}
func TestPasskeySchemaRequiresExplicitInitializedRealm(t *testing.T) {
	s, _, h, path, key := humanStore(t)
	s.mu.Lock()
	e := s.enablePasskeySchema(testPasskeyOrigin, "admin.invalid")
	s.mu.Unlock()
	if e != ErrDenied {
		t.Fatal(e)
	}
	var v int
	if s.db.QueryRow("PRAGMA user_version").Scan(&v) != nil || v != 3 {
		t.Fatal("migration rollback")
	}
	setupHuman(t, s, h)
	s.Close()
	if e := EnablePasskeySchema(path, key, testIdentity, nil, testPasskeyOrigin, "admin.invalid"); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.version != 4 {
		t.Fatal("version")
	}
	var n int
	if s.db.QueryRow("SELECT count(*) FROM passkeys").Scan(&n) != nil || n != 0 {
		t.Fatal("implicit credential")
	}
	if _, e := NewPasskeyAuth(NewHumanAuth(s, NewSessions(s)), "https://other.invalid", "other.invalid"); e != ErrInvalid {
		t.Fatal("RP drift", e)
	}
}
func TestPasskeyChallengeSingleUseSourceSessionAndExpiry(t *testing.T) {
	_, ss, _, p, r := passkeyFixture(t)
	begin := func() PasskeyOptions {
		o, e := p.BeginRegistration(r.Token, r.Session.CSRF, "My device", "127.0.0.1", testNow)
		if e != nil {
			t.Fatal(e)
		}
		return o
	}
	o := begin()
	raw, e := json.Marshal(o.Options)
	if e != nil {
		t.Fatal(e)
	}
	var options struct {
		PublicKey struct {
			RP struct {
				Name string `json:"name"`
			} `json:"rp"`
		} `json:"publicKey"`
	}
	if e = json.Unmarshal(raw, &options); e != nil || options.PublicKey.RP.Name != "secDNS" {
		t.Fatal("authenticator product spelling", e)
	}
	if e := p.FinishRegistration(r.Token, r.Session.CSRF, o.Challenge, "127.0.0.2", []byte(`{}`), testNow); e != ErrDenied {
		t.Fatal(e)
	}
	if e := p.FinishRegistration(r.Token, r.Session.CSRF, o.Challenge, "127.0.0.1", []byte(`{}`), testNow); e != ErrDenied {
		t.Fatal("replay", e)
	}
	o = begin()
	if e := p.FinishRegistration(r.Token, r.Session.CSRF, o.Challenge, "127.0.0.1", []byte(`{}`), testNow.Add(5*time.Minute)); e != ErrDenied {
		t.Fatal("expiry", e)
	}
	o = begin()
	if e := ss.Logout(r.Token, r.Session.CSRF, testNow); e != nil {
		t.Fatal(e)
	}
	if e := p.FinishRegistration(r.Token, r.Session.CSRF, o.Challenge, "127.0.0.1", []byte(`{}`), testNow); e != ErrDenied {
		t.Fatal("logout", e)
	}
}
func TestPasskeyRecentSessionAndSchemaFailureRefuse(t *testing.T) {
	s, _, h, p, r := passkeyFixture(t)
	if _, e := h.Passkeys(r.Token, r.Session.CSRF, testNow.Add(5*time.Minute)); e != ErrDenied {
		t.Fatal("recent", e)
	}
	if _, e := p.BeginRegistration(r.Token, strings.Repeat("x", 102), "Device", "127.0.0.1", testNow); e != ErrDenied {
		t.Fatal("CSRF", e)
	}
	if e := s.write(func(tx *sql.Tx) error { _, e := tx.Exec("DELETE FROM passkey_realm"); return e }); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	e := s.validateVersionMustTest()
	s.mu.Unlock()
	if e == nil {
		t.Fatal("missing RP accepted")
	}
}
func (s *Store) validateVersionMustTest() error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	return s.validateVersion(tx, 4)
}

func TestPasskeyMigrationCommitFailureIsAtomicAndFaultsHandle(t *testing.T) {
	s, _, h, path, key := humanStore(t)
	setupHuman(t, s, h)
	s.commit = func(tx *sql.Tx) error { return errors.New("injected uncertainty") }
	s.mu.Lock()
	e := s.enablePasskeySchema(testPasskeyOrigin, "admin.invalid")
	s.mu.Unlock()
	if e != ErrUnavailable || !s.faulted {
		t.Fatal("fault", e)
	}
	s.Close()
	reopened, e := Open(path, key, testIdentity, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if reopened.version != 3 {
		t.Fatal("migration not rolled back")
	}
}
func TestPasskeyMigrationWithoutRuntimeIdentityChange(t *testing.T) {
	for _, v := range [][2]string{{"https://admin.invalid", "invalid"}, {"http://admin.invalid", "admin.invalid"}, {"https://admin.invalid:443", "admin.invalid"}, {"", "admin.invalid"}, {"https://admin.invalid", "admin.invalid:443"}} {
		if ValidatePasskeyOrigin(v[0], v[1]) == nil {
			t.Fatal("accepted mismatched identity", v)
		}
	}
}

func insertSyntheticPasskey(t *testing.T, s *Store) string {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7}, Curve: 1, XCoord: key.X.FillBytes(make([]byte, 32)), YCoord: key.Y.FillBytes(make([]byte, 32))})
	if e != nil {
		t.Fatal(e)
	}
	id := make([]byte, 32)
	rand.Read(id)
	c := webauthn.Credential{ID: id, PublicKey: pub, Flags: webauthn.CredentialFlags{UserPresent: true, UserVerified: true}}
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = decodePasskey(raw, id); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("INSERT INTO passkeys VALUES(?,?,?, ?,0,0)", id, "Synthetic key", raw, testNow.Unix()); e != nil {
		t.Fatal(e)
	}
	return base64.RawURLEncoding.EncodeToString(id)
}
func TestPasskeyRemovalAtomicAuditAndAllHumanSessionRevocation(t *testing.T) {
	s, ss, h, _, r := passkeyFixture(t)
	id := insertSyntheticPasskey(t, s)
	if _, e := s.db.Exec("CREATE TRIGGER fail_passkey_remove BEFORE INSERT ON audit WHEN NEW.action='passkey_removed' BEGIN SELECT RAISE(ABORT,'injected'); END"); e != nil {
		t.Fatal(e)
	}
	if e := h.RemovePasskey(r.Token, r.Session.CSRF, id, testNow); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, e := ss.Authenticate(r.Token, r.Session.CSRF, true, false, testNow); e != nil {
		t.Fatal("audit failure invalidated session", e)
	}
	list, e := h.Passkeys(r.Token, r.Session.CSRF, testNow)
	if e != nil || len(list) != 1 {
		t.Fatal("audit failure deleted key", e)
	}
	s.db.Exec("DROP TRIGGER fail_passkey_remove")
	if e := h.RemovePasskey(r.Token, r.Session.CSRF, id, testNow); e != nil {
		t.Fatal(e)
	}
	if _, e := ss.Authenticate(r.Token, r.Session.CSRF, true, false, testNow); e != ErrDenied {
		t.Fatal("removed key retained human authority", e)
	}
	var n int
	s.db.QueryRow("SELECT count(*) FROM passkeys").Scan(&n)
	if n != 0 {
		t.Fatal("key retained")
	}
}
func TestPasskeyStrictCredentialCorruption(t *testing.T) {
	s, _, _, _, _ := passkeyFixture(t)
	insertSyntheticPasskey(t, s)
	if e := s.validateVersionMustTest(); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec("UPDATE passkeys SET record=CAST('{}' AS BLOB)"); e != nil {
		t.Fatal(e)
	}
	if e := s.validateVersionMustTest(); e == nil {
		t.Fatal("malformed public credential accepted")
	}
}

func TestPasskeyRecoveryRemovesCredentialsOnlyOnConfirmedRecovery(t *testing.T) {
	s, ss, h, _, initial := passkeyFixture(t)
	insertSyntheticPasskey(t, s)
	now := testNow.Add(30 * time.Second)
	recovery, e := h.BeginCodeRecovery("owner", humanPassword, initial.RecoveryCodes[0], "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	var n int
	if e = s.db.QueryRow("SELECT count(*) FROM passkeys").Scan(&n); e != nil || n != 1 {
		t.Fatal("pending recovery changed credentials", e)
	}
	result, e := h.Confirm(recovery.Challenge, enrollmentOTP(t, recovery, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.db.QueryRow("SELECT count(*) FROM passkeys").Scan(&n); e != nil || n != 0 {
		t.Fatal("recovery retained credentials", e)
	}
	if _, e = ss.Authenticate(initial.Token, "", false, false, now); e != ErrDenied {
		t.Fatal("old authority retained", e)
	}
	if _, e = ss.Authenticate(result.Token, "", false, false, now); e != nil {
		t.Fatal("recovery session unavailable", e)
	}
	if e = s.validateVersionMustTest(); e != nil {
		t.Fatal("recovered schema invalid", e)
	}
}
