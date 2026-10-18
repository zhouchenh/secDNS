package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const applicationID = 1396982098
const maxCredentials = 128
const maxAudit = 2048

var schema = map[string]string{
	"realm":       `CREATE TABLE realm (singleton INTEGER PRIMARY KEY CHECK(singleton=1), realm TEXT NOT NULL, node TEXT NOT NULL, name TEXT NOT NULL, key_check BLOB NOT NULL CHECK(length(key_check)=32), setup TEXT NOT NULL CHECK(setup='pending'))`,
	"credentials": `CREATE TABLE credentials (id TEXT PRIMARY KEY, digest BLOB NOT NULL UNIQUE CHECK(length(digest)=32), name TEXT NOT NULL, purpose TEXT NOT NULL, scopes TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL, revoked INTEGER NOT NULL)`,
	"bootstrap":   `CREATE TABLE bootstrap (singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest BLOB NOT NULL UNIQUE CHECK(length(digest)=32), scopes TEXT NOT NULL, expires INTEGER NOT NULL, credential_expires INTEGER NOT NULL)`,
	"audit":       `CREATE TABLE audit (sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL, action TEXT NOT NULL, credential_id TEXT NOT NULL)`,
}

type Store struct {
	mu       sync.Mutex
	db       *sql.DB
	key      []byte
	identity Identity
	legacy   [][32]byte
	version  int
	faulted  bool
	commit   func(*sql.Tx) error // private fault seam; production always tx.Commit
}

func (*Store) String() string   { return "adminauth.Store[redacted]" }
func (*Store) GoString() string { return "adminauth.Store[redacted]" }

// Create creates a new, exclusively owned private database. Existing files,
// including empty files, are never adopted. Legacy credentials are collision
// inputs only; they are never persisted or accepted by this store.
func Create(path, keyPath string, id Identity, legacy []string) (*Store, error) {
	return open(path, keyPath, id, legacy, true, false)
}

// Open requires an existing exact schema and matching immutable identity/key.
// It does not create, recover identity, or reset pending setup implicitly.
func Open(path, keyPath string, id Identity, legacy []string) (*Store, error) {
	return open(path, keyPath, id, legacy, false, false)
}
func open(path, keyPath string, id Identity, legacy []string, create, migrate bool) (*Store, error) {
	return openWithCommit(path, keyPath, id, legacy, create, migrate, func(tx *sql.Tx) error { return tx.Commit() })
}

// The commit callback is private and permits deterministic uncertainty tests.
func openWithCommit(path, keyPath string, id Identity, legacy []string, create, migrate bool, commit func(*sql.Tx) error) (_ *Store, err error) {
	if !id.valid() || path == keyPath || len(legacy) > 128 {
		return nil, ErrInvalid
	}
	if err = privatePath(path, !create); err != nil {
		return nil, err
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, e := os.Lstat(path + suffix); e == nil {
			if create || privatePath(path+suffix, true) != nil {
				return nil, ErrInvalid
			}
		} else if !os.IsNotExist(e) {
			return nil, ErrInvalid
		}
	}
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	s := &Store{key: key, identity: id, commit: commit}
	defer func() {
		if err != nil {
			clear(key)
			if s.db != nil {
				_ = s.db.Close()
			}
		}
	}()
	for _, v := range legacy {
		if len(v) < 1 || len(v) > 4096 {
			return nil, ErrInvalid
		}
		s.legacy = append(s.legacy, s.digest(v))
	}
	if create {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, ErrExists
		}
		if e = f.Close(); e != nil {
			return nil, ErrUnavailable
		}
	}
	uriPath := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	q.Set("mode", "rw")
	q.Set("_txlock", "exclusive")
	uri.RawQuery = q.Encode()
	s.db, err = sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	s.db.SetMaxOpenConns(1)
	s.db.SetMaxIdleConns(1)
	for _, pragma := range []string{"PRAGMA busy_timeout=0", "PRAGMA synchronous=FULL", "PRAGMA locking_mode=EXCLUSIVE"} {
		if _, e := s.db.Exec(pragma); e != nil {
			return nil, ErrUnavailable
		}
	}
	var journal string
	if s.db.QueryRow("PRAGMA journal_mode").Scan(&journal) != nil || journal != "delete" {
		return nil, ErrInvalid
	}
	tx, e := s.db.Begin()
	if e != nil {
		return nil, ErrUnavailable
	}
	defer tx.Rollback()
	if create {
		for _, stmt := range schema {
			if _, e = tx.Exec(stmt); e != nil {
				return nil, ErrUnavailable
			}
		}
		if _, e = tx.Exec(fmt.Sprintf("PRAGMA application_id=%d", applicationID)); e != nil {
			return nil, ErrUnavailable
		}
		if _, e = tx.Exec("PRAGMA user_version=2"); e != nil {
			return nil, ErrUnavailable
		}
		check := s.digest("realm-key-check:" + id.RealmID + ":" + id.NodeID)
		if _, e = tx.Exec("INSERT INTO realm VALUES(1,?,?,?,?, 'pending')", id.RealmID, id.NodeID, id.DisplayName, check[:]); e != nil {
			return nil, ErrUnavailable
		}
	}
	expectedVersion := 2
	if !create && !migrate {
		var actual int
		if tx.QueryRow("PRAGMA user_version").Scan(&actual) == nil && actual == 3 {
			expectedVersion = 3
		}
	}
	if migrate {
		expectedVersion = 1
	}
	if e = s.validateVersion(tx, expectedVersion); e != nil {
		return nil, e
	}
	if migrate {
		if _, e = tx.Exec("PRAGMA user_version=2"); e != nil {
			return nil, ErrUnavailable
		}
	}
	if e = s.commit(tx); e != nil {
		return nil, ErrUnavailable
	}
	s.version = expectedVersion
	if migrate {
		s.version = 2
	}
	return s, nil
}

func (s *Store) digest(value string) [32]byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte("secdns-adminauth-v1\x00"))
	h.Write([]byte(value))
	var b [32]byte
	copy(b[:], h.Sum(nil))
	return b
}
func secret(prefix string) (string, string, error) {
	b := make([]byte, 48)
	defer clear(b)
	if _, e := rand.Read(b); e != nil {
		return "", "", ErrUnavailable
	}
	id := hex.EncodeToString(b[:16])
	return prefix + "_" + id + "_" + hex.EncodeToString(b[16:]), id, nil
}
func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
func instant(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}
func validNow(t time.Time) bool { return t.Unix() > 0 && t.Year() <= 9999 }
func (s *Store) healthy() bool  { return s.db != nil && !s.faulted }
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	e := s.db.Close()
	s.db = nil
	clear(s.key)
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) Identity() Identity { return s.identity }

func (s *Store) write(fn func(*sql.Tx) error) error {
	if !s.healthy() {
		return ErrUnavailable
	}
	tx, e := s.db.Begin()
	if e != nil {
		return ErrUnavailable
	}
	if e = fn(tx); e != nil {
		if rb := tx.Rollback(); rb != nil {
			s.faulted = true
			return ErrUnavailable
		}
		return e
	}
	if e = s.commit(tx); e != nil {
		s.faulted = true
		_ = tx.Rollback()
		return ErrUnavailable
	}
	return nil
}
func audit(tx *sql.Tx, now time.Time, action, id string) error {
	if _, e := tx.Exec("INSERT INTO audit(at,action,credential_id) VALUES(?,?,?)", now.Unix(), action, id); e != nil {
		return ErrUnavailable
	}
	_, e := tx.Exec("DELETE FROM audit WHERE sequence <= (SELECT max(sequence) FROM audit)-?", maxAudit)
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) collides(tx *sql.Tx, d [32]byte) bool {
	for _, v := range s.legacy {
		if hmac.Equal(v[:], d[:]) {
			return true
		}
	}
	var n int
	e := tx.QueryRow("SELECT (SELECT count(*) FROM credentials WHERE digest=?)+(SELECT count(*) FROM bootstrap WHERE digest=?)", d[:], d[:]).Scan(&n)
	if e != nil || n != 0 {
		return true
	}
	if s.version == 3 {
		if s.db == nil {
			return true
		}
		if tx.QueryRow("SELECT count(*) FROM human_grant WHERE digest=?", d[:]).Scan(&n) != nil || n != 0 {
			return true
		}
	}
	return false
}
func encodeScopes(sc []Scope) string { b, _ := json.Marshal(sc); return string(b) }
func decodeScopes(raw string) ([]Scope, error) {
	var sc []Scope
	if len(raw) > 256 || json.Unmarshal([]byte(raw), &sc) != nil {
		return nil, ErrInvalid
	}
	out, e := scopes(sc)
	if e != nil || encodeScopes(out) != raw {
		return nil, ErrInvalid
	}
	return out, nil
}

// CreateBootstrap is local operator authority, never a remotely callable login
// or issuance endpoint. It refuses to replace an outstanding grant. The grant is
// valid for ten minutes and can atomically issue one scoped agent credential.
func (s *Store) CreateBootstrap(env BootstrapEnvelope, now time.Time) (string, error) {
	sc, e := scopes(env.Scopes)
	if e != nil || !validNow(now) || (!env.CredentialExpiresAt.IsZero() && (!validNow(env.CredentialExpiresAt) || unix(env.CredentialExpiresAt) <= now.Unix())) {
		return "", ErrInvalid
	}
	token, _, e := secret("sdnb")
	if e != nil {
		return "", e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.digest(token)
	e = s.write(func(tx *sql.Tx) error {
		var n int
		if tx.QueryRow("SELECT count(*) FROM bootstrap").Scan(&n) != nil {
			return ErrUnavailable
		}
		if n != 0 || s.collides(tx, d) {
			return ErrDenied
		}
		if _, e := tx.Exec("INSERT INTO bootstrap VALUES(1,?,?,?,?)", d[:], encodeScopes(sc), now.Unix()+600, unix(env.CredentialExpiresAt)); e != nil {
			return ErrUnavailable
		}
		return audit(tx, now, "bootstrap_created", "")
	})
	if e != nil {
		return "", e
	}
	return token, nil
}

// CancelBootstrapLocal explicitly revokes an outstanding grant, including an
// expired one. It never creates a replacement or resets human/record state.
func (s *Store) CancelBootstrapLocal(now time.Time) error {
	if !validNow(now) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(func(tx *sql.Tx) error {
		res, e := tx.Exec("DELETE FROM bootstrap WHERE singleton=1")
		if e != nil {
			return ErrUnavailable
		}
		n, e := res.RowsAffected()
		if e != nil {
			return ErrUnavailable
		}
		if n != 1 {
			return ErrDenied
		}
		return audit(tx, now, "bootstrap_cancelled", "")
	})
}

func (s *Store) BootstrapIssueAgent(grant string, request CredentialRequest, now time.Time) (string, Credential, error) {
	sc, e := scopes(request.Scopes)
	if e != nil || request.Validate(now) != nil {
		return "", Credential{}, ErrInvalid
	}
	if len(grant) != 102 || !strings.HasPrefix(grant, "sdnb_") {
		return "", Credential{}, ErrDenied
	}
	token, id, e := secret("sdna")
	if e != nil {
		return "", Credential{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	gd, d := s.digest(grant), s.digest(token)
	c := Credential{ID: id, Name: request.Name, Purpose: request.Purpose, Scopes: sc, CreatedAt: instant(now.Unix()), ExpiresAt: instant(unix(request.ExpiresAt))}
	e = s.write(func(tx *sql.Tx) error {
		var stored []byte
		var raw string
		var expires, cap int64
		if e := tx.QueryRow("SELECT digest,scopes,expires,credential_expires FROM bootstrap WHERE singleton=1").Scan(&stored, &raw, &expires, &cap); e == sql.ErrNoRows {
			return ErrDenied
		} else if e != nil {
			return ErrUnavailable
		}
		allowed, e := decodeScopes(raw)
		if e != nil {
			return ErrUnavailable
		}
		if !hmac.Equal(gd[:], stored) || now.Unix() >= expires || !subset(sc, allowed) || (cap != 0 && (unix(request.ExpiresAt) == 0 || unix(request.ExpiresAt) > cap)) {
			return ErrDenied
		}
		var count int
		if tx.QueryRow("SELECT count(*) FROM credentials").Scan(&count) != nil {
			return ErrUnavailable
		}
		if count >= maxCredentials || s.collides(tx, d) {
			return ErrDenied
		}
		if _, e := tx.Exec("INSERT INTO credentials VALUES(?,?,?,?,?,?,?,?,?)", id, d[:], c.Name, c.Purpose, encodeScopes(sc), unix(c.CreatedAt), unix(c.ExpiresAt), 0, 0); e != nil {
			return ErrUnavailable
		}
		if _, e := tx.Exec("DELETE FROM bootstrap WHERE singleton=1"); e != nil {
			return ErrUnavailable
		}
		return audit(tx, now, "agent_issued", id)
	})
	if e != nil {
		return "", Credential{}, e
	}
	return token, c, nil
}

// Verify authenticates an agent only for this exact realm/node. Returned Actor
// conveys no credential-issuance or security-management capability.
func (s *Store) Verify(token, realm, node string, now time.Time) (Actor, error) {
	if len(token) != 102 || !strings.HasPrefix(token, "sdna_") || realm != s.identity.RealmID || node != s.identity.NodeID || !validNow(now) {
		return Actor{}, ErrDenied
	}
	id := token[5:37]
	if token[37] != '_' {
		return Actor{}, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.digest(token)
	var a Actor
	e := s.write(func(tx *sql.Tx) error {
		var stored []byte
		var raw, name string
		var created, expires, revoked int64
		e := tx.QueryRow("SELECT digest,name,scopes,created,expires,revoked FROM credentials WHERE id=?", id).Scan(&stored, &name, &raw, &created, &expires, &revoked)
		if e == sql.ErrNoRows {
			return ErrDenied
		}
		if e != nil {
			return ErrUnavailable
		}
		if !hmac.Equal(d[:], stored) || now.Unix() < created || revoked != 0 || (expires != 0 && now.Unix() >= expires) {
			return ErrDenied
		}
		sc, e := decodeScopes(raw)
		if e != nil {
			return ErrUnavailable
		}
		if _, e = tx.Exec("UPDATE credentials SET used=max(used,?) WHERE id=?", now.Unix(), id); e != nil {
			return ErrUnavailable
		}
		a = Actor{id: id, realm: realm, node: node, name: name, permissions: sc}
		return nil
	})
	if e != nil {
		return Actor{}, e
	}
	return a, nil
}

// RevokeLocal is an explicitly local operator primitive. HTTP adapters must not
// expose it based on possession of an Actor or an arbitrary 'reauthenticated'
// boolean. Human reauthentication capabilities are a later integration slice.
func (s *Store) RevokeLocal(id string, now time.Time) error {
	if len(id) != 32 || !validNow(now) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(func(tx *sql.Tx) error {
		res, e := tx.Exec("UPDATE credentials SET revoked=? WHERE id=? AND revoked=0", now.Unix(), id)
		if e != nil {
			return ErrUnavailable
		}
		n, e := res.RowsAffected()
		if e != nil {
			return ErrUnavailable
		}
		if n == 0 {
			return ErrDenied
		}
		return audit(tx, now, "agent_revoked", id)
	})
}

// MigrateSchema1 explicitly upgrades only a strictly valid schema-1 store.
// Runtime Open never migrates. Take an offline private backup before invocation.
func MigrateSchema1(path, keyPath string, id Identity, legacy []string) error {
	s, e := open(path, keyPath, id, legacy, false, true)
	if e != nil {
		return e
	}
	return s.Close()
}
