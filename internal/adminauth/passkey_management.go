package adminauth

import (
	"database/sql"
	"encoding/base64"
	"time"
)

type PasskeyInfo struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	CounterWarning bool       `json:"counter_warning"`
}

func passkeyID(encoded string) ([]byte, error) {
	b, e := base64.RawURLEncoding.DecodeString(encoded)
	if e != nil || len(b) == 0 || len(b) > 1024 || base64.RawURLEncoding.EncodeToString(b) != encoded {
		return nil, ErrInvalid
	}
	return b, nil
}

// Passkeys returns public metadata only. It never returns public-key blobs or
// WebAuthn challenge state; recent human authentication is required.
func (h *HumanAuth) Passkeys(token, csrf string, now time.Time) ([]PasskeyInfo, error) {
	out := []PasskeyInfo{}
	e := h.sessions.withRecentHuman(token, csrf, now, func(tx *sql.Tx, a Actor) error {
		rows, e := tx.Query("SELECT id,name,created,used,warning FROM passkeys ORDER BY created,id")
		if e != nil {
			return ErrUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var id []byte
			var name string
			var created, used int64
			var warning int
			if rows.Scan(&id, &name, &created, &used, &warning) != nil {
				return ErrUnavailable
			}
			v := PasskeyInfo{ID: base64.RawURLEncoding.EncodeToString(id), Name: name, CreatedAt: time.Unix(created, 0).UTC(), CounterWarning: warning != 0}
			if used != 0 {
				t := time.Unix(used, 0).UTC()
				v.LastUsedAt = &t
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, e
}
func (h *HumanAuth) RenamePasskey(token, csrf, id, name string, now time.Time) error {
	raw, e := passkeyID(id)
	if e != nil || !label(name, 128) {
		return ErrInvalid
	}
	return h.sessions.withRecentHuman(token, csrf, now, func(tx *sql.Tx, a Actor) error {
		r, e := tx.Exec("UPDATE passkeys SET name=? WHERE id=?", name, raw)
		if e != nil {
			return ErrUnavailable
		}
		n, e := r.RowsAffected()
		if e != nil || n != 1 {
			return ErrDenied
		}
		return audit(tx, now, "passkey_renamed", a.id)
	})
}
func (h *HumanAuth) RemovePasskey(token, csrf, id string, now time.Time) error {
	raw, e := passkeyID(id)
	if e != nil {
		return e
	}
	return h.sessions.withRecentHuman(token, csrf, now, func(tx *sql.Tx, a Actor) error {
		r, e := tx.Exec("DELETE FROM passkeys WHERE id=?", raw)
		if e != nil {
			return ErrUnavailable
		}
		n, e := r.RowsAffected()
		if e != nil || n != 1 {
			return ErrDenied
		}
		// Conservatively invalidate every human session, including sessions issued
		// with the removed key; password/TOTP and other keys remain enrolled.
		result, e := tx.Exec("UPDATE human SET epoch=epoch+1 WHERE singleton=1 AND epoch<9223372036854775807")
		if e != nil {
			return ErrUnavailable
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return ErrUnavailable
		}
		return audit(tx, now, "passkey_removed", a.id)
	})
}
