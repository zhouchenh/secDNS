package adminauth

import (
	"database/sql"
	"time"
)

// RecentHuman returns metadata, not an issuance capability. Every sensitive
// method below independently verifies the actual session and CSRF binding.
func (h *HumanAuth) RecentHuman(token, csrf string, now time.Time) (SessionInfo, error) {
	i, e := h.sessions.Authenticate(token, csrf, true, false, now)
	if e != nil {
		return SessionInfo{}, e
	}
	if i.Actor.Kind() != "human" || now.Before(i.AuthenticatedAt) || !now.Before(i.AuthenticatedAt.Add(RecentAuthenticationWindow)) {
		return SessionInfo{}, ErrDenied
	}
	return i, nil
}
func (h *HumanAuth) Reauthenticate(token, csrf, password, code, source string, now time.Time) (HumanResult, error) {
	i, e := h.sessions.Authenticate(token, csrf, true, false, now)
	if e != nil {
		return HumanResult{}, e
	}
	if i.Actor.Kind() != "human" {
		return HumanResult{}, ErrDenied
	}
	if !h.mu.TryLock() {
		return HumanResult{}, ErrUnavailable
	}
	defer h.mu.Unlock()
	if h.closed {
		return HumanResult{}, ErrUnavailable
	}
	if e = h.store.rateAttempt(source, now); e != nil {
		return HumanResult{}, e
	}
	s := h.store
	s.mu.Lock()
	if !s.healthy() {
		s.mu.Unlock()
		return HumanResult{}, ErrUnavailable
	}
	var user string
	e = s.db.QueryRow("SELECT username FROM human WHERE singleton=1").Scan(&user)
	s.mu.Unlock()
	if e != nil {
		return HumanResult{}, ErrUnavailable
	}
	p, e := h.checkPassword(user, password)
	if e != nil {
		return HumanResult{}, e
	}
	if p.id != i.Actor.id || p.epoch != i.Actor.humanEpoch {
		return HumanResult{}, ErrDenied
	}
	p.source = source
	if e := h.store.rateAttemptMFA(source, now); e != nil {
		return HumanResult{}, e
	}
	return h.confirmLogin([32]byte{}, p, code, now, token)
}
func (h *HumanAuth) RegenerateRecovery(token, csrf string, now time.Time) ([]string, error) {
	i, e := h.RecentHuman(token, csrf, now)
	if e != nil {
		return nil, e
	}
	if !h.mu.TryLock() {
		return nil, ErrUnavailable
	}
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrUnavailable
	}
	codes, hashes, e := recoveryCodes()
	if e != nil {
		return nil, e
	}
	s := h.store
	s.mu.Lock()
	defer s.mu.Unlock()
	e = s.write(func(tx *sql.Tx) error {
		if e := s.activeActorSQL(tx, i.Actor, now); e != nil {
			return e
		}
		if _, e := tx.Exec("DELETE FROM recovery_codes"); e != nil {
			return ErrUnavailable
		}
		for n, v := range hashes {
			if _, e := tx.Exec("INSERT INTO recovery_codes VALUES(?,?)", n+1, v); e != nil {
				return ErrUnavailable
			}
		}
		return audit(tx, now, "human_codes", i.Actor.id)
	})
	if e != nil {
		return nil, e
	}
	return codes, nil
}
func (h *HumanAuth) ChangePassword(token, csrf, password string, now time.Time) (HumanResult, error) {
	i, e := h.RecentHuman(token, csrf, now)
	if e != nil {
		return HumanResult{}, e
	}
	if !h.mu.TryLock() {
		return HumanResult{}, ErrUnavailable
	}
	defer h.mu.Unlock()
	if h.closed {
		return HumanResult{}, ErrUnavailable
	}
	s := h.store
	s.mu.Lock()
	if !s.healthy() {
		s.mu.Unlock()
		return HumanResult{}, ErrUnavailable
	}
	var user string
	e = s.db.QueryRow("SELECT username FROM human WHERE singleton=1").Scan(&user)
	s.mu.Unlock()
	if e != nil {
		return HumanResult{}, ErrUnavailable
	}
	if !validPassword(password, user) {
		return HumanResult{}, ErrDenied
	}
	phc, e := passwordHash(password)
	if e != nil {
		return HumanResult{}, e
	}
	s.mu.Lock()
	a := i.Actor
	e = s.write(func(tx *sql.Tx) error {
		if e := s.activeActorSQL(tx, a, now); e != nil {
			return e
		}
		if a.humanEpoch >= int64(^uint64(0)>>1) {
			return ErrUnavailable
		}
		a.humanEpoch++
		if _, e := tx.Exec("UPDATE human SET password=?,epoch=? WHERE singleton=1", phc, a.humanEpoch); e != nil {
			return ErrUnavailable
		}
		return audit(tx, now, "human_password", a.id)
	})
	s.mu.Unlock()
	if e != nil {
		return HumanResult{}, e
	}
	newToken, info, e := h.sessions.issueHuman(a, now, i.AuthenticatedAt)
	return HumanResult{Token: newToken, Session: info}, e
}
func (h *HumanAuth) RevokeOtherSessions(token, csrf string, now time.Time) error {
	i, e := h.RecentHuman(token, csrf, now)
	if e != nil {
		return e
	}
	ss := h.sessions
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.closed {
		return ErrUnavailable
	}
	if e = ss.store.sessionAudit(i.Actor, now, "human_sessions_revoked"); e != nil {
		return e
	}
	keep := ss.digest(token)
	for d, v := range ss.entries {
		if v.actor.Kind() == "human" && d != keep {
			delete(ss.entries, d)
		}
	}
	return nil
}

func (h *HumanAuth) BeginReplacement(token, csrf, source string, now time.Time) (Enrollment, error) {
	i, e := h.RecentHuman(token, csrf, now)
	if e != nil {
		return Enrollment{}, e
	}
	if !h.mu.TryLock() {
		return Enrollment{}, ErrUnavailable
	}
	defer h.mu.Unlock()
	if h.closed {
		return Enrollment{}, ErrUnavailable
	}
	s := h.store
	s.mu.Lock()
	if !s.healthy() {
		s.mu.Unlock()
		return Enrollment{}, ErrUnavailable
	}
	if e = s.activeActorSQL(s.db, i.Actor, now); e != nil {
		s.mu.Unlock()
		return Enrollment{}, e
	}
	p := &humanCeremony{purpose: "replace", id: i.Actor.id, epoch: i.Actor.humanEpoch, source: source}
	e = s.db.QueryRow("SELECT username,name,password FROM human WHERE singleton=1").Scan(&p.user, &p.name, &p.phc)
	s.mu.Unlock()
	if e != nil {
		return Enrollment{}, ErrUnavailable
	}
	seed, encoded, e := newSeed()
	if e != nil {
		return Enrollment{}, e
	}
	p.seed = seed
	challenge, e := h.add(p, now)
	if e != nil {
		clear(seed)
		return Enrollment{}, e
	}
	return Enrollment{challenge, encoded, p.expires}, nil
}
func (h *HumanAuth) ConfirmReplacement(token, csrf, challenge, code, source string, now time.Time) (HumanResult, error) {
	i, e := h.RecentHuman(token, csrf, now)
	if e != nil {
		return HumanResult{}, e
	}
	return h.confirm(challenge, code, source, now, &i.Actor)
}
