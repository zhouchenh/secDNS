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
// readable by earlier releases after a rollback). It is deliberately NOT a recent
// authentication: changing the password, authenticator, recovery codes, passkeys
// or other sessions still requires password+TOTP or passkey reauthentication.
func (h *HumanAuth) TrustedOwnerLogin(now time.Time) (HumanResult, error) {
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
	notRecent := now.Add(-RecentAuthenticationWindow)
	token, i, e := h.sessions.issueHumanCommit(Actor{}, now, notRecent, "human_login", func(tx *sql.Tx) (Actor, error) {
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
	return HumanResult{Token: token, Session: i}, nil
}
