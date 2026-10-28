package adminauth

import (
	"crypto/hmac"
	"database/sql"
	"time"
)

// withRecentHuman serializes the current session check with the credential write.
// Logout cannot interleave between authorization and commit. Lock order is
// sessions -> store, matching issuance and reauthentication.
func (s *Sessions) withRecentHuman(token, csrf string, now time.Time, fn func(*sql.Tx, Actor) error) error {
	if len(token) != 102 || len(csrf) != 102 || !validNow(now) {
		return ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if !s.store.healthy() || s.store.version != 4 {
		return ErrUnavailable
	}
	d, cd := s.store.digest(token), s.store.digest(csrf)
	v, ok := s.entries[d]
	if !ok || expired(v, now) || v.actor.Kind() != "human" || !hmac.Equal(cd[:], v.csrf[:]) || now.Before(v.authenticated) || !now.Before(v.authenticated.Add(RecentAuthenticationWindow)) {
		return ErrDenied
	}
	return s.store.write(func(tx *sql.Tx) error {
		if e := s.store.activeActorSQL(tx, v.actor, now); e != nil {
			return e
		}
		return fn(tx, cloneActor(v.actor))
	})
}
