package adminauth

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

const MaxPasskeys = 16

var passkeySchema = map[string]string{
	"passkey_realm": `CREATE TABLE passkey_realm (singleton INTEGER PRIMARY KEY CHECK(singleton=1), origin TEXT NOT NULL, rp TEXT NOT NULL, human_id TEXT NOT NULL, handle BLOB NOT NULL CHECK(length(handle)=32))`,
	"passkeys":      `CREATE TABLE passkeys (id BLOB PRIMARY KEY, name TEXT NOT NULL, record BLOB NOT NULL, created INTEGER NOT NULL, used INTEGER NOT NULL, warning INTEGER NOT NULL)`,
}

// ValidatePasskeyOrigin intentionally supports only the exact origin hostname,
// not parent-domain or multi-origin credentials.
func ValidatePasskeyOrigin(origin, rp string) error {
	if ValidateOrigin(origin) != nil {
		return ErrInvalid
	}
	u, e := url.Parse(origin)
	if e != nil || rp == "" || rp != u.Hostname() || strings.Contains(rp, ":") {
		return ErrInvalid
	}
	return nil
}

// EnablePasskeySchema is an explicit offline operation on an initialized human
// realm. No runtime opener creates tables or changes the RP identity.
func EnablePasskeySchema(path, keyPath string, id Identity, legacy []string, origin, rp string) error {
	if ValidatePasskeyOrigin(origin, rp) != nil {
		return ErrInvalid
	}
	s, e := Open(path, keyPath, id, legacy)
	if e != nil {
		return e
	}
	defer s.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enablePasskeySchema(origin, rp)
}

func (s *Store) enablePasskeySchema(origin, rp string) error {
	if s.version != 3 || ValidatePasskeyOrigin(origin, rp) != nil {
		return ErrInvalid
	}
	handle := make([]byte, 32)
	if _, e := rand.Read(handle); e != nil {
		return ErrUnavailable
	}
	e := s.write(func(tx *sql.Tx) error {
		var n int
		if tx.QueryRow("SELECT count(*) FROM human").Scan(&n) != nil || n != 1 {
			return ErrDenied
		}
		for _, ddl := range passkeySchema {
			if _, e := tx.Exec(ddl); e != nil {
				return ErrUnavailable
			}
		}
		if _, e := tx.Exec("INSERT INTO passkey_realm SELECT 1,?,?,id,? FROM human WHERE singleton=1", origin, rp, handle); e != nil {
			return ErrUnavailable
		}
		if _, e := tx.Exec("PRAGMA user_version=4"); e != nil {
			return ErrUnavailable
		}
		return s.validateVersion(tx, 4)
	})
	if e == nil {
		s.version = 4
	}
	return e
}

func decodePasskey(raw, id []byte) (webauthn.Credential, error) {
	var c webauthn.Credential
	if len(raw) == 0 || len(raw) > 16384 || len(id) == 0 || len(id) > 1024 || json.Unmarshal(raw, &c) != nil || !bytes.Equal(c.ID, id) || len(c.PublicKey) == 0 || len(c.PublicKey) > 4096 || len(c.Transport) > 8 {
		return c, ErrInvalid
	}
	canonical, e := json.Marshal(c)
	if e != nil || !bytes.Equal(canonical, raw) {
		return c, ErrInvalid
	}
	if _, e := webauthncose.ParsePublicKey(c.PublicKey); e != nil {
		return c, ErrInvalid
	}
	if !c.Flags.UserPresent || !c.Flags.UserVerified || (c.Flags.BackupState && !c.Flags.BackupEligible) {
		return c, ErrInvalid
	}
	return c, nil
}

func (s *Store) validatePasskeys(tx *sql.Tx) error {
	var n int
	if tx.QueryRow("SELECT count(*) FROM human").Scan(&n) != nil || n != 1 {
		return ErrInvalid
	}
	if tx.QueryRow("SELECT count(*) FROM passkey_realm").Scan(&n) != nil || n != 1 {
		return ErrInvalid
	}
	var origin, rp string
	var handle []byte
	if tx.QueryRow("SELECT origin,rp,handle FROM passkey_realm WHERE singleton=1 AND typeof(origin)='text' AND length(CAST(origin AS BLOB))<=2048 AND typeof(rp)='text' AND length(CAST(rp AS BLOB))<=253 AND typeof(human_id)='text' AND human_id=(SELECT id FROM human WHERE singleton=1) AND typeof(handle)='blob' AND length(handle)=32").Scan(&origin, &rp, &handle) != nil || ValidatePasskeyOrigin(origin, rp) != nil {
		return ErrInvalid
	}
	if tx.QueryRow(`SELECT count(*) FROM passkeys WHERE typeof(id)!='blob' OR length(id)<1 OR length(id)>1024 OR typeof(name)!='text' OR length(CAST(name AS BLOB))>128 OR typeof(record)!='blob' OR length(record)<1 OR length(record)>16384 OR typeof(created)!='integer' OR created<=0 OR typeof(used)!='integer' OR used<0 OR typeof(warning)!='integer' OR warning NOT IN (0,1)`).Scan(&n) != nil || n != 0 {
		return ErrInvalid
	}
	if tx.QueryRow("SELECT count(*) FROM passkeys").Scan(&n) != nil || n > MaxPasskeys {
		return ErrInvalid
	}
	rows, e := tx.Query("SELECT id,name,record FROM passkeys")
	if e != nil {
		return ErrInvalid
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw []byte
		var name string
		if rows.Scan(&id, &name, &raw) != nil || !label(name, 128) {
			return ErrInvalid
		}
		if _, e := decodePasskey(raw, id); e != nil {
			return e
		}
	}
	return rows.Err()
}
