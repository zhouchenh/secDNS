package adminauth

import (
	"crypto/hmac"
	"database/sql"
	"sync"
	"time"
)

const MaxSessions = 256
const SessionIdle = 15 * time.Minute
const SessionLifetime = 2 * time.Hour

// Sessions is process-local. A new instance invalidates every previous session.
// No bearer credential is retained in a session or returned in its metadata.
type Sessions struct {
	mu      sync.Mutex
	closed  bool
	store   *Store
	entries map[[32]byte]session
}

func (*Sessions) String() string   { return "adminauth.Sessions[redacted]" }
func (*Sessions) GoString() string { return "adminauth.Sessions[redacted]" }

type session struct {
	actor         Actor
	csrf          [32]byte
	csrfValue     string
	created, last time.Time
}
type SessionInfo struct {
	CSRF                                string
	Actor                               Actor
	CreatedAt, ExpiresAt, IdleExpiresAt time.Time
}

func NewSessions(store *Store) *Sessions {
	return &Sessions{store: store, entries: make(map[[32]byte]session)}
}
func cloneActor(a Actor) Actor { a.permissions = append([]Scope(nil), a.permissions...); return a }
func (s *Sessions) digest(v string) [32]byte {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	return s.store.digest(v)
}
func info(v session) SessionInfo {
	return SessionInfo{v.csrfValue, cloneActor(v.actor), v.created, v.created.Add(SessionLifetime), v.last.Add(SessionIdle)}
}
func expired(v session, now time.Time) bool {
	return now.Before(v.created) || now.Before(v.last) || !now.Before(v.created.Add(SessionLifetime)) || !now.Before(v.last.Add(SessionIdle))
}

// Exchange authenticates a dedicated agent bearer and requires UI scope. The
// caller enforces HTTPS origin and transport/HTTP constraints before invoking it.
func (s *Sessions) Exchange(bearer, realm, node string, now time.Time) (string, string, SessionInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", "", SessionInfo{}, ErrUnavailable
	}
	a, e := s.store.Verify(bearer, realm, node, now)
	if e != nil {
		return "", "", SessionInfo{}, e
	}
	if !a.Allows(UIView) {
		return "", "", SessionInfo{}, ErrDenied
	}
	token, _, e := secret("sdns")
	if e != nil {
		return "", "", SessionInfo{}, e
	}
	csrf, _, e := secret("sdnc")
	if e != nil {
		return "", "", SessionInfo{}, e
	}
	for k, v := range s.entries {
		if expired(v, now) {
			delete(s.entries, k)
		}
	}
	if len(s.entries) >= MaxSessions {
		checked := map[string]error{}
		for key, value := range s.entries {
			result, seen := checked[value.actor.id]
			if !seen {
				result = s.store.activeActor(value.actor, now)
				checked[value.actor.id] = result
			}
			if result == ErrDenied {
				delete(s.entries, key)
			} else if result != nil {
				return "", "", SessionInfo{}, result
			}
		}
		if len(s.entries) >= MaxSessions {
			return "", "", SessionInfo{}, ErrUnavailable
		}
	}
	d, cd := s.digest(token), s.digest(csrf)
	if _, exists := s.entries[d]; exists {
		return "", "", SessionInfo{}, ErrUnavailable
	}
	if e = s.store.sessionAudit(a, now, "session_created"); e != nil {
		return "", "", SessionInfo{}, e
	}
	v := session{cloneActor(a), cd, csrf, now, now}
	s.entries[d] = v
	return token, csrf, info(v), nil
}

// Authenticate rechecks durable credential status on every request. CSRF is
// required for state-changing requests. Background reads do not refresh idle
// expiry; only explicit user activity should set activity=true.
func (s *Sessions) Authenticate(token, csrf string, mutation, activity bool, now time.Time) (SessionInfo, error) {
	if len(token) != 102 || !validNow(now) {
		return SessionInfo{}, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return SessionInfo{}, ErrUnavailable
	}
	d := s.digest(token)
	v, ok := s.entries[d]
	if !ok {
		return SessionInfo{}, ErrDenied
	}
	if expired(v, now) {
		delete(s.entries, d)
		return SessionInfo{}, ErrDenied
	}
	if mutation {
		cd := s.digest(csrf)
		if len(csrf) != 102 || !hmac.Equal(cd[:], v.csrf[:]) {
			return SessionInfo{}, ErrDenied
		}
	}
	if e := s.store.activeActor(v.actor, now); e != nil {
		delete(s.entries, d)
		return SessionInfo{}, e
	}
	if activity {
		v.last = now
		s.entries[d] = v
	}
	return info(v), nil
}
func (s *Sessions) Logout(token, csrf string, now time.Time) error {
	if _, e := s.Authenticate(token, csrf, true, false, now); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.digest(token)
	v, ok := s.entries[d]
	if !ok {
		return ErrDenied
	}
	// Delete even if durable auditing faults: an audit outage must not keep a
	// requested session alive. The caller receives unavailable, not success.
	delete(s.entries, d)
	return s.store.sessionAudit(v.actor, now, "session_revoked")
}
func (s *Sessions) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true; clear(s.entries) }

func (s *Store) activeActor(a Actor, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.healthy() {
		return ErrUnavailable
	}
	return s.activeActorSQL(s.db, a, now)
}

type queryer interface{ QueryRow(string, ...any) *sql.Row }

func (s *Store) activeActorSQL(q queryer, a Actor, now time.Time) error {
	if a.id == "" || a.realm != s.identity.RealmID || a.node != s.identity.NodeID {
		return ErrDenied
	}
	var raw string
	var created, expiry, revoked int64
	e := q.QueryRow("SELECT scopes,created,expires,revoked FROM credentials WHERE id=?", a.id).Scan(&raw, &created, &expiry, &revoked)
	if e == sql.ErrNoRows {
		return ErrDenied
	}
	if e != nil {
		return ErrUnavailable
	}
	if now.Unix() < created || revoked != 0 || (expiry != 0 && now.Unix() >= expiry) || encodeScopes(a.permissions) != raw {
		return ErrDenied
	}
	return nil
}
func (s *Store) sessionAudit(a Actor, now time.Time, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(func(tx *sql.Tx) error {
		if e := s.activeActorSQL(tx, a, now); e != nil {
			return e
		}
		return audit(tx, now, action, a.id)
	})
}
