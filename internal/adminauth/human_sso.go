package adminauth

import (
	"database/sql"
	"time"
)

// RecentAuthenticationWindow is how long a password+TOTP or passkey ceremony
// counts as recent for credential management.
const RecentAuthenticationWindow = 5 * time.Minute

// TrustedOwnerLogin issues the existing owner's normal human session after the
// HTTP layer has verified a trusted single sign-on assertion from the local
// edge. It never creates, enrolls or changes a credential, and it requires a
// completed owner setup.
//
// The session uses the same token, CSRF, lifetime, idle and audit path as a
// password+TOTP login (durable audit action "human_login", so the database stays
// readable by earlier releases after a rollback).
//
// The session counts as a recent authentication only when the identity
// provider authenticated the owner within RecentAuthenticationWindow (authTime,
// the ID token's auth_time, verified by the edge); a silent single sign-on reuse
// with an older or missing auth_time is not recent. A fresh identity-provider
// sign-in is therefore the step-up for sensitive changes on the SSO path.
func (h *HumanAuth) TrustedOwnerLogin(now, authTime time.Time) (HumanResult, error) {
	if !validNow(now) {
		return HumanResult{}, ErrDenied
	}
	if !h.mu.TryLock() {
		return HumanResult{}, ErrUnavailable
	}
	defer h.mu.Unlock()
	if h.closed {
		return HumanResult{}, ErrUnavailable
	}
	s := h.store
	authenticated := now.Add(-RecentAuthenticationWindow)
	if !authTime.IsZero() && !authTime.After(now.Add(30*time.Second)) && now.Sub(authTime) < RecentAuthenticationWindow {
		authenticated = authTime
		if authenticated.After(now) {
			authenticated = now
		}
	}
	token, i, e := h.sessions.issueHumanCommit(Actor{}, now, authenticated, "human_login", func(tx *sql.Tx) (Actor, error) {
		var id, name string
		var epoch, created int64
		e := tx.QueryRow("SELECT id,name,epoch,created FROM human WHERE singleton=1").Scan(&id, &name, &epoch, &created)
		if e == sql.ErrNoRows {
			return Actor{}, ErrDenied
		}
		if e != nil {
			return Actor{}, ErrUnavailable
		}
		if now.Unix() < created {
			return Actor{}, ErrDenied
		}
		permissions, _ := scopes(allScopes)
		return Actor{id: id, realm: s.identity.RealmID, node: s.identity.NodeID, name: name, permissions: permissions, humanEpoch: epoch}, nil
	}, "")
	if e != nil {
		return HumanResult{}, e
	}
	if i, e = h.sessions.markSSO(token, now); e != nil {
		return HumanResult{}, e
	}
	return HumanResult{Token: token, Session: i}, nil
}
