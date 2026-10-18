package adminauth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"sync"
	"time"
)

type passkeyUser struct {
	actor       Actor
	handle      []byte
	username    string
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.handle }
func (u *passkeyUser) WebAuthnName() string                       { return u.username }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.actor.name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type passkeyQuery interface {
	QueryRow(string, ...any) *sql.Row
	Query(string, ...any) (*sql.Rows, error)
}

func (s *Store) passkeyUser(q passkeyQuery) (*passkeyUser, error) {
	u := &passkeyUser{}
	if q.QueryRow("SELECT id,username,name,epoch FROM human WHERE singleton=1").Scan(&u.actor.id, &u.username, &u.actor.name, &u.actor.humanEpoch) != nil {
		return nil, ErrUnavailable
	}
	if q.QueryRow("SELECT handle FROM passkey_realm WHERE singleton=1").Scan(&u.handle) != nil {
		return nil, ErrUnavailable
	}
	u.actor.realm, u.actor.node = s.identity.RealmID, s.identity.NodeID
	u.actor.permissions, _ = scopes(allScopes)
	rows, e := q.Query("SELECT id,record FROM passkeys ORDER BY id")
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw []byte
		if rows.Scan(&id, &raw) != nil {
			return nil, ErrUnavailable
		}
		c, e := decodePasskey(raw, id)
		if e != nil {
			return nil, ErrUnavailable
		}
		u.credentials = append(u.credentials, c)
	}
	if e = rows.Err(); e != nil {
		return nil, ErrUnavailable
	}
	return u, nil
}

type passkeyCeremony struct {
	purpose, source, name string
	session               [32]byte
	actor                 Actor
	data                  webauthn.SessionData
	expires               time.Time
}
type PasskeyAuth struct {
	mu      sync.Mutex
	closed  bool
	human   *HumanAuth
	web     *webauthn.WebAuthn
	pending map[[32]byte]passkeyCeremony
}
type PasskeyOptions struct {
	Challenge string    `json:"challenge"`
	Options   any       `json:"options"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (*PasskeyAuth) String() string     { return "adminauth.PasskeyAuth[redacted]" }
func (*PasskeyAuth) GoString() string   { return "adminauth.PasskeyAuth[redacted]" }
func (PasskeyOptions) String() string   { return "adminauth.PasskeyOptions[redacted]" }
func (PasskeyOptions) GoString() string { return "adminauth.PasskeyOptions[redacted]" }
func NewPasskeyAuth(h *HumanAuth, origin, rp string) (*PasskeyAuth, error) {
	if h == nil || ValidatePasskeyOrigin(origin, rp) != nil {
		return nil, ErrInvalid
	}
	s := h.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.healthy() || s.version != 4 {
		return nil, ErrUnavailable
	}
	var actualOrigin, actualRP string
	if s.db.QueryRow("SELECT origin,rp FROM passkey_realm WHERE singleton=1").Scan(&actualOrigin, &actualRP) != nil || actualOrigin != origin || actualRP != rp {
		return nil, ErrInvalid
	}
	web, e := webauthn.New(&webauthn.Config{RPID: rp, RPDisplayName: "secDNS", RPOrigins: []string{origin}, AttestationPreference: protocol.PreferNoAttestation, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}})
	if e != nil {
		return nil, ErrInvalid
	}
	return &PasskeyAuth{human: h, web: web, pending: map[[32]byte]passkeyCeremony{}}, nil
}
func (p *PasskeyAuth) Close() { p.mu.Lock(); defer p.mu.Unlock(); p.closed = true; clear(p.pending) }
func (p *PasskeyAuth) add(c passkeyCeremony, options any, now time.Time) (PasskeyOptions, error) {
	for k, v := range p.pending {
		if !now.Before(v.expires) {
			delete(p.pending, k)
		}
	}
	if len(p.pending) >= 32 {
		return PasskeyOptions{}, ErrUnavailable
	}
	token, _, e := secret("sdnp")
	if e != nil {
		return PasskeyOptions{}, e
	}
	d := p.human.digest(token)
	if _, ok := p.pending[d]; ok {
		return PasskeyOptions{}, ErrUnavailable
	}
	c.expires = now.Add(5 * time.Minute)
	c.data.Expires = time.Time{} // This bounded process map owns expiry, including injected-clock tests.
	p.pending[d] = c
	return PasskeyOptions{token, options, c.expires}, nil
}
func (p *PasskeyAuth) take(challenge, source, purpose string, now time.Time) (passkeyCeremony, error) {
	d := p.human.digest(challenge)
	c, ok := p.pending[d]
	delete(p.pending, d)
	if !ok || len(challenge) != 102 || c.source != source || c.purpose != purpose || !validNow(now) || now.Before(c.expires.Add(-5*time.Minute)) || !now.Before(c.expires) {
		return c, ErrDenied
	}
	return c, nil
}
func (p *PasskeyAuth) BeginRegistration(token, csrf, name, source string, now time.Time) (PasskeyOptions, error) {
	if !label(name, 128) || !validNow(now) {
		return PasskeyOptions{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return PasskeyOptions{}, ErrUnavailable
	}
	var user *passkeyUser
	e := p.human.sessions.withRecentHuman(token, csrf, now, func(tx *sql.Tx, a Actor) error {
		var e error
		user, e = p.human.store.passkeyUser(tx)
		if e != nil {
			return e
		}
		if len(user.credentials) >= MaxPasskeys {
			return ErrUnavailable
		}
		return nil
	})
	if e != nil {
		return PasskeyOptions{}, e
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(user.credentials))
	for _, c := range user.credentials {
		exclusions = append(exclusions, c.Descriptor())
	}
	options, data, e := p.web.BeginRegistration(user, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired), webauthn.WithExclusions(exclusions))
	if e != nil {
		return PasskeyOptions{}, ErrUnavailable
	}
	return p.add(passkeyCeremony{purpose: "register", source: source, name: name, actor: user.actor, session: p.human.digest(token), data: *data}, options, now)
}
func (p *PasskeyAuth) FinishRegistration(token, csrf, challenge, source string, response []byte, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrUnavailable
	}
	c, e := p.take(challenge, source, "register", now)
	if e != nil {
		return e
	}
	if len(response) == 0 || len(response) > 32768 || p.human.digest(token) != c.session {
		return ErrDenied
	}
	parsed, e := protocol.ParseCredentialCreationResponseBytes(response)
	if e != nil {
		return ErrDenied
	}
	return p.human.sessions.withRecentHuman(token, csrf, now, func(tx *sql.Tx, a Actor) error {
		if a.id != c.actor.id || a.humanEpoch != c.actor.humanEpoch {
			return ErrDenied
		}
		user, e := p.human.store.passkeyUser(tx)
		if e != nil {
			return e
		}
		if len(user.credentials) >= MaxPasskeys {
			return ErrUnavailable
		}
		cred, e := p.web.CreateCredential(user, c.data, parsed)
		if e != nil {
			return ErrDenied
		}
		raw, e := json.Marshal(cred)
		if e != nil {
			return ErrUnavailable
		}
		if _, e = decodePasskey(raw, cred.ID); e != nil {
			return ErrDenied
		}
		var n int
		if tx.QueryRow("SELECT count(*) FROM passkeys WHERE id=?", cred.ID).Scan(&n) != nil {
			return ErrUnavailable
		}
		if n != 0 {
			return ErrDenied
		}
		if _, e = tx.Exec("INSERT INTO passkeys VALUES(?,?,?,?,0,0)", cred.ID, c.name, raw, now.Unix()); e != nil {
			return ErrUnavailable
		}
		return audit(tx, now, "passkey_added", a.id)
	})
}
func (p *PasskeyAuth) BeginLogin(token, csrf, source string, reauth bool, now time.Time) (PasskeyOptions, error) {
	if !validNow(now) {
		return PasskeyOptions{}, ErrDenied
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return PasskeyOptions{}, ErrUnavailable
	}
	if e := p.human.store.rateAttempt(source, now); e != nil {
		return PasskeyOptions{}, e
	}
	var session [32]byte
	if reauth {
		i, e := p.human.sessions.Authenticate(token, csrf, true, false, now)
		if e != nil || i.Actor.Kind() != "human" {
			return PasskeyOptions{}, ErrDenied
		}
		session = p.human.digest(token)
	}
	s := p.human.store
	s.mu.Lock()
	if !s.healthy() || s.version != 4 {
		s.mu.Unlock()
		return PasskeyOptions{}, ErrUnavailable
	}
	user, e := s.passkeyUser(s.db)
	s.mu.Unlock()
	if e != nil {
		return PasskeyOptions{}, e
	}
	if len(user.credentials) == 0 {
		return PasskeyOptions{}, ErrDenied
	}
	options, data, e := p.web.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if e != nil {
		return PasskeyOptions{}, ErrUnavailable
	}
	purpose := "login"
	if reauth {
		purpose = "reauth"
	}
	return p.add(passkeyCeremony{purpose: purpose, source: source, actor: user.actor, session: session, data: *data}, options, now)
}
func (p *PasskeyAuth) FinishLogin(token, csrf, challenge, source string, reauth bool, response []byte, now time.Time) (HumanResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return HumanResult{}, ErrUnavailable
	}
	purpose, action, replace := "login", "passkey_login", ""
	if reauth {
		purpose, action, replace = "reauth", "passkey_reauth", token
	}
	c, e := p.take(challenge, source, purpose, now)
	if e != nil {
		return HumanResult{}, e
	}
	if len(response) == 0 || len(response) > 32768 {
		return HumanResult{}, ErrDenied
	}
	if reauth {
		if p.human.digest(token) != c.session {
			return HumanResult{}, ErrDenied
		}
		i, e := p.human.sessions.Authenticate(token, csrf, true, false, now)
		if e != nil || i.Actor.id != c.actor.id || i.Actor.humanEpoch != c.actor.humanEpoch {
			return HumanResult{}, ErrDenied
		}
	}
	parsed, e := protocol.ParseCredentialRequestResponseBytes(response)
	if e != nil {
		return HumanResult{}, ErrDenied
	}
	s := p.human.store
	s.mu.Lock()
	if !s.healthy() || s.version != 4 {
		s.mu.Unlock()
		return HumanResult{}, ErrUnavailable
	}
	user, e := s.passkeyUser(s.db)
	s.mu.Unlock()
	if e != nil {
		return HumanResult{}, e
	}
	if user.actor.id != c.actor.id || user.actor.humanEpoch != c.actor.humanEpoch {
		return HumanResult{}, ErrDenied
	}
	_, credential, e := p.web.ValidatePasskeyLogin(func(id, handle []byte) (webauthn.User, error) {
		if !bytes.Equal(handle, user.handle) {
			return nil, ErrDenied
		}
		return user, nil
	}, c.data, parsed)
	if e != nil {
		return HumanResult{}, ErrDenied
	}
	var before []byte
	for _, v := range user.credentials {
		if bytes.Equal(v.ID, credential.ID) {
			before, _ = json.Marshal(v)
			break
		}
	}
	if before == nil {
		return HumanResult{}, ErrDenied
	}
	raw, e := json.Marshal(credential)
	if e != nil {
		return HumanResult{}, ErrUnavailable
	}
	check := func(tx *sql.Tx) error {
		if e := s.activeActorSQL(tx, c.actor, now); e != nil {
			return e
		}
		var current []byte
		if tx.QueryRow("SELECT record FROM passkeys WHERE id=?", credential.ID).Scan(&current) != nil || !bytes.Equal(current, before) {
			return ErrDenied
		}
		return nil
	}
	if credential.Authenticator.CloneWarning {
		s.mu.Lock()
		e = s.write(func(tx *sql.Tx) error {
			if e := check(tx); e != nil {
				return e
			}
			if _, e := tx.Exec("UPDATE passkeys SET warning=1 WHERE id=?", credential.ID); e != nil {
				return ErrUnavailable
			}
			return audit(tx, now, "passkey_warning", c.actor.id)
		})
		s.mu.Unlock()
		if e != nil {
			return HumanResult{}, e
		}
		return HumanResult{}, ErrDenied
	}
	issued, info, e := p.human.sessions.issueHumanCommit(c.actor, now, now, action, func(tx *sql.Tx) (Actor, error) {
		if e := check(tx); e != nil {
			return Actor{}, e
		}
		if _, e := tx.Exec("UPDATE passkeys SET record=?,used=? WHERE id=?", raw, now.Unix(), credential.ID); e != nil {
			return Actor{}, ErrUnavailable
		}
		if e := s.clearRateSQL(tx, source); e != nil {
			return Actor{}, e
		}
		return c.actor, nil
	}, replace)
	if e != nil {
		return HumanResult{}, e
	}
	return HumanResult{Token: issued, Session: info}, nil
}
