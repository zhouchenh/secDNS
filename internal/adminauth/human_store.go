package adminauth

import (
	"crypto/hmac"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"
)

var humanSchema = map[string]string{
	"human":          `CREATE TABLE human (singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL, username TEXT NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL, seed BLOB NOT NULL, counter INTEGER NOT NULL, epoch INTEGER NOT NULL, created INTEGER NOT NULL)`,
	"recovery_codes": `CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY CHECK(id BETWEEN 1 AND 10), verifier TEXT NOT NULL)`,
	"human_grant":    `CREATE TABLE human_grant (singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest BLOB NOT NULL, purpose TEXT NOT NULL CHECK(purpose IN ('setup','recover')), expires INTEGER NOT NULL)`,
	"human_rate":     `CREATE TABLE human_rate (bucket BLOB PRIMARY KEY, failures INTEGER NOT NULL, until_at INTEGER NOT NULL, updated INTEGER NOT NULL)`,
}

// EnableHumanSchema is an explicit offline migration. Runtime opening never
// adds tables. Existing agent identities and record data are not modified.
func EnableHumanSchema(path, keyPath string, id Identity, legacy []string) error {
	s, e := Open(path, keyPath, id, legacy)
	if e != nil {
		return e
	}
	defer s.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enableHumanSchema()
}
func (s *Store) enableHumanSchema() error {
	if s.version != 2 {
		return ErrInvalid
	}
	e := s.write(func(tx *sql.Tx) error {
		for _, ddl := range humanSchema {
			if _, e := tx.Exec(ddl); e != nil {
				return ErrUnavailable
			}
		}
		if _, e := tx.Exec("PRAGMA user_version=3"); e != nil {
			return ErrUnavailable
		}
		return s.validateVersion(tx, 3)
	})
	if e == nil {
		s.version = 3
	}
	return e
}
func (s *Store) HumanEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.healthy() && s.version == 3
}
func (s *Store) HumanReady() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.healthy() || s.version != 3 {
		return false, ErrUnavailable
	}
	var n int
	if s.db.QueryRow("SELECT count(*) FROM human").Scan(&n) != nil {
		return false, ErrUnavailable
	}
	return n == 1, nil
}

func (s *Store) validateHuman(tx *sql.Tx) error {
	var bad, n int
	checks := []string{
		`SELECT count(*) FROM human WHERE typeof(id)!='text' OR length(CAST(id AS BLOB))!=32 OR typeof(username)!='text' OR length(CAST(username AS BLOB))>64 OR typeof(name)!='text' OR length(CAST(name AS BLOB))>128 OR typeof(password)!='text' OR length(CAST(password AS BLOB))>160 OR typeof(seed)!='blob' OR length(seed)!=48 OR typeof(counter)!='integer' OR counter<0 OR typeof(epoch)!='integer' OR epoch<1 OR typeof(created)!='integer' OR created<=0`,
		`SELECT count(*) FROM recovery_codes WHERE typeof(id)!='integer' OR id<1 OR id>10 OR typeof(verifier)!='text' OR length(CAST(verifier AS BLOB))>160`,
		`SELECT count(*) FROM human_grant WHERE typeof(digest)!='blob' OR length(digest)!=32 OR typeof(purpose)!='text' OR purpose NOT IN ('setup','recover') OR typeof(expires)!='integer' OR expires<=0`,
		`SELECT count(*) FROM human_rate WHERE typeof(bucket)!='blob' OR length(bucket)!=32 OR typeof(failures)!='integer' OR failures<1 OR failures>20 OR typeof(until_at)!='integer' OR until_at<=0 OR typeof(updated)!='integer' OR updated<=0`,
	}
	for _, q := range checks {
		if tx.QueryRow(q).Scan(&bad) != nil || bad != 0 {
			return ErrInvalid
		}
	}
	if tx.QueryRow("SELECT count(*) FROM human").Scan(&n) != nil || n > 1 {
		return ErrInvalid
	}
	humanCount := n
	if n == 1 {
		var id, user, name, phc string
		var enc []byte
		if tx.QueryRow("SELECT id,username,name,password,seed FROM human").Scan(&id, &user, &name, &phc, &enc) != nil {
			return ErrInvalid
		}
		b, e := hex.DecodeString(id)
		if e != nil || len(b) != 16 || hex.EncodeToString(b) != id || !identifier(user) || !label(name, 128) {
			return ErrInvalid
		}
		if _, _, e = parsePHC(phc); e != nil {
			return ErrInvalid
		}
		seed, e := s.decryptSeed(enc)
		if e != nil {
			return ErrInvalid
		}
		clear(seed)
	}
	if tx.QueryRow("SELECT count(*) FROM recovery_codes").Scan(&n) != nil || n != 10*humanCount {
		return ErrInvalid
	}
	rows, e := tx.Query("SELECT verifier FROM recovery_codes")
	if e != nil {
		return ErrInvalid
	}
	for rows.Next() {
		var v string
		if rows.Scan(&v) != nil {
			rows.Close()
			return ErrInvalid
		}
		if _, _, e = parsePHC(v); e != nil {
			rows.Close()
			return ErrInvalid
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrInvalid
	}
	if tx.QueryRow("SELECT count(*) FROM human_grant").Scan(&n) != nil || n > 1 {
		return ErrInvalid
	}
	if n == 1 {
		var purpose string
		if tx.QueryRow("SELECT purpose FROM human_grant").Scan(&purpose) != nil || (purpose == "setup" && humanCount != 0) || (purpose == "recover" && humanCount != 1) {
			return ErrInvalid
		}
	}
	if tx.QueryRow("SELECT count(*) FROM human_rate").Scan(&n) != nil || n > 1024 {
		return ErrInvalid
	}
	return nil
}

// CreateHumanGrant is local root/operator authority, not an HTTP capability.
func (s *Store) CreateHumanGrant(recovery bool, now time.Time) (string, error) {
	if !validNow(now) {
		return "", ErrInvalid
	}
	token, _, e := secret("sdnh")
	if e != nil {
		return "", e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != 3 {
		return "", ErrUnavailable
	}
	d := s.digest(token)
	purpose := "setup"
	if recovery {
		purpose = "recover"
	}
	e = s.write(func(tx *sql.Tx) error {
		var n, g int
		if tx.QueryRow("SELECT count(*) FROM human").Scan(&n) != nil || tx.QueryRow("SELECT count(*) FROM human_grant").Scan(&g) != nil {
			return ErrUnavailable
		}
		if g != 0 || (!recovery && n != 0) || (recovery && n != 1) || s.collides(tx, d) {
			return ErrDenied
		}
		if _, e := tx.Exec("INSERT INTO human_grant VALUES(1,?,?,?)", d[:], purpose, now.Unix()+600); e != nil {
			return ErrUnavailable
		}
		return audit(tx, now, "human_grant", "")
	})
	if e != nil {
		return "", e
	}
	return token, nil
}
func (s *Store) CancelHumanGrant(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != 3 || !validNow(now) {
		return ErrInvalid
	}
	return s.write(func(tx *sql.Tx) error {
		if _, e := tx.Exec("DELETE FROM human_grant"); e != nil {
			return ErrUnavailable
		}
		return audit(tx, now, "human_grant_cancelled", "")
	})
}
func (s *Store) grantSQL(q queryer, grant, purpose string, now time.Time) error {
	if len(grant) != 102 || !strings.HasPrefix(grant, "sdnh_") {
		return ErrDenied
	}
	var digest []byte
	var p string
	var expiry int64
	e := q.QueryRow("SELECT digest,purpose,expires FROM human_grant WHERE singleton=1").Scan(&digest, &p, &expiry)
	if e == sql.ErrNoRows {
		return ErrDenied
	}
	if e != nil {
		return ErrUnavailable
	}
	d := s.digest(grant)
	if p != purpose || now.Unix() >= expiry || now.Unix() < expiry-600 || !hmac.Equal(d[:], digest) {
		return ErrDenied
	}
	return nil
}

// Rate limits are durable across process restart. Account bucket is constant,
// including unknown names; source is the caller's socket peer, never a header.
func (s *Store) rateAttempt(source string, now time.Time) error {
	if len(source) < 1 || len(source) > 128 || !validNow(now) {
		return ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != 3 {
		return ErrUnavailable
	}
	denied := false
	e := s.write(func(tx *sql.Tx) error {
		if _, e := tx.Exec("DELETE FROM human_rate WHERE updated<?", now.Unix()-86400); e != nil {
			return ErrUnavailable
		}
		for _, key := range []string{"human-account", "human-source:" + source} {
			d := s.digest(key)
			var failures int
			var until int64
			e := tx.QueryRow("SELECT failures,until_at FROM human_rate WHERE bucket=?", d[:]).Scan(&failures, &until)
			if e != nil && e != sql.ErrNoRows {
				return ErrUnavailable
			}
			if e == nil && now.Unix() < until {
				denied = true
				continue
			}
			if e == sql.ErrNoRows {
				var n int
				if tx.QueryRow("SELECT count(*) FROM human_rate").Scan(&n) != nil {
					return ErrUnavailable
				}
				if n >= 1024 {
					denied = true
					continue
				}
			}
			failures++
			if failures > 20 {
				failures = 20
			}
			delay := int64(0)
			if failures > 5 {
				shift := failures - 5
				if shift > 9 {
					shift = 9
				}
				delay = 1 << shift
			}
			if _, e := tx.Exec("INSERT INTO human_rate VALUES(?,?,?,?) ON CONFLICT(bucket) DO UPDATE SET failures=excluded.failures,until_at=excluded.until_at,updated=excluded.updated", d[:], failures, now.Unix()+delay, now.Unix()); e != nil {
				return ErrUnavailable
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	if denied {
		return ErrDenied
	}
	return nil
}
func (s *Store) clearRateSQL(tx *sql.Tx, source string) error {
	for _, key := range []string{"human-account", "human-source:" + source} {
		d := s.digest(key)
		if _, e := tx.Exec("DELETE FROM human_rate WHERE bucket=?", d[:]); e != nil {
			return ErrUnavailable
		}
	}
	return nil
}
