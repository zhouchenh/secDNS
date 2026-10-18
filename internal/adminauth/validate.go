package adminauth

import (
	"crypto/hmac"
	"database/sql"
	"encoding/hex"
)

func (s *Store) validate(tx *sql.Tx) error {
	var id, version int
	var integrity string
	if tx.QueryRow("PRAGMA application_id").Scan(&id) != nil || tx.QueryRow("PRAGMA user_version").Scan(&version) != nil || tx.QueryRow("PRAGMA quick_check").Scan(&integrity) != nil || id != applicationID || version != 1 || integrity != "ok" {
		return ErrInvalid
	}
	rows, e := tx.Query("SELECT name,type,sql FROM sqlite_schema WHERE substr(name,1,7) != 'sqlite_'")
	if e != nil {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for rows.Next() {
		var name, kind, ddl string
		if rows.Scan(&name, &kind, &ddl) != nil || kind != "table" || schema[name] != ddl || seen[name] {
			rows.Close()
			return ErrInvalid
		}
		seen[name] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(seen) != len(schema) {
		return ErrInvalid
	}
	var n int
	var realm, node, name, setup string
	var check []byte
	if tx.QueryRow("SELECT count(*) FROM realm").Scan(&n) != nil || n != 1 {
		return ErrInvalid
	}
	if tx.QueryRow("SELECT realm,node,name,key_check,setup FROM realm WHERE singleton=1 AND typeof(realm)='text' AND length(CAST(realm AS BLOB))<=64 AND typeof(node)='text' AND length(CAST(node AS BLOB))<=64 AND typeof(name)='text' AND length(CAST(name AS BLOB))<=128 AND typeof(key_check)='blob'").Scan(&realm, &node, &name, &check, &setup) != nil {
		return ErrInvalid
	}
	expected := s.digest("realm-key-check:" + s.identity.RealmID + ":" + s.identity.NodeID)
	if realm != s.identity.RealmID || node != s.identity.NodeID || name != s.identity.DisplayName || setup != "pending" || !hmac.Equal(check, expected[:]) {
		return ErrInvalid
	}
	// Validate type/byte limits before reading any attacker-controlled variable field.
	var invalid int
	if tx.QueryRow(`SELECT count(*) FROM credentials WHERE typeof(id)!='text' OR length(CAST(id AS BLOB))!=32 OR typeof(digest)!='blob' OR length(digest)!=32 OR typeof(name)!='text' OR length(CAST(name AS BLOB))>128 OR typeof(purpose)!='text' OR length(CAST(purpose AS BLOB))>256 OR typeof(scopes)!='text' OR length(CAST(scopes AS BLOB))>256 OR typeof(created)!='integer' OR created<=0 OR typeof(expires)!='integer' OR expires<0 OR (expires!=0 AND expires<=created) OR typeof(used)!='integer' OR used<0 OR typeof(revoked)!='integer' OR revoked<0`).Scan(&invalid) != nil || invalid != 0 {
		return ErrInvalid
	}
	if tx.QueryRow("SELECT count(*) FROM credentials").Scan(&n) != nil || n > maxCredentials {
		return ErrInvalid
	}
	rows, e = tx.Query("SELECT id,digest,name,purpose,scopes FROM credentials")
	if e != nil {
		return ErrInvalid
	}
	for rows.Next() {
		var id, name, purpose, raw string
		var digest []byte
		if rows.Scan(&id, &digest, &name, &purpose, &raw) != nil {
			rows.Close()
			return ErrInvalid
		}
		b, e := hex.DecodeString(id)
		_, se := decodeScopes(raw)
		if e != nil || len(b) != 16 || hex.EncodeToString(b) != id || !label(name, 128) || (purpose != "" && !label(purpose, 256)) || se != nil {
			rows.Close()
			return ErrInvalid
		}
		for _, legacy := range s.legacy {
			if hmac.Equal(legacy[:], digest) {
				rows.Close()
				return ErrInvalid
			}
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrInvalid
	}
	if tx.QueryRow(`SELECT count(*) FROM bootstrap WHERE typeof(digest)!='blob' OR length(digest)!=32 OR typeof(scopes)!='text' OR length(CAST(scopes AS BLOB))>256 OR typeof(expires)!='integer' OR expires<=0 OR typeof(credential_expires)!='integer' OR credential_expires<0`).Scan(&invalid) != nil || invalid != 0 {
		return ErrInvalid
	}
	rows, e = tx.Query("SELECT digest,scopes FROM bootstrap")
	if e != nil {
		return ErrInvalid
	}
	n = 0
	var grantDigest []byte
	for rows.Next() {
		n++
		var raw string
		if rows.Scan(&grantDigest, &raw) != nil {
			rows.Close()
			return ErrInvalid
		}
		if _, e = decodeScopes(raw); e != nil {
			rows.Close()
			return ErrInvalid
		}
		for _, legacy := range s.legacy {
			if hmac.Equal(legacy[:], grantDigest) {
				rows.Close()
				return ErrInvalid
			}
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil || n > 1 {
		return ErrInvalid
	}
	if n == 1 {
		if tx.QueryRow("SELECT count(*) FROM credentials WHERE digest=?", grantDigest).Scan(&n) != nil || n != 0 {
			return ErrInvalid
		}
	}
	if tx.QueryRow(`SELECT count(*) FROM audit WHERE typeof(sequence)!='integer' OR sequence<=0 OR typeof(at)!='integer' OR at<=0 OR typeof(action)!='text' OR action NOT IN ('bootstrap_created','bootstrap_cancelled','agent_issued','agent_revoked') OR typeof(credential_id)!='text' OR (action IN ('bootstrap_created','bootstrap_cancelled') AND credential_id!='') OR (action IN ('agent_issued','agent_revoked') AND length(CAST(credential_id AS BLOB))!=32)`).Scan(&invalid) != nil || invalid != 0 {
		return ErrInvalid
	}
	if tx.QueryRow("SELECT count(*) FROM audit").Scan(&n) != nil || n > maxAudit {
		return ErrInvalid
	}
	return nil
}

// AuditLocal is for local inspection or a future separately authorized adapter.
// It never returns submitted tokens, labels, names, or record content.
func (s *Store) AuditLocal(limit int) ([]AuditEvent, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.healthy() {
		return nil, ErrUnavailable
	}
	rows, e := s.db.Query("SELECT sequence,at,action,credential_id FROM audit ORDER BY sequence DESC LIMIT ?", limit)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var a AuditEvent
		var at int64
		if rows.Scan(&a.Sequence, &at, &a.Action, &a.CredentialID) != nil {
			return nil, ErrUnavailable
		}
		a.At = instant(at)
		out = append(out, a)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
