package recordstore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	_ "modernc.org/sqlite"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
)

var ErrInvalidRecord = errors.New("invalid persistent record")

const applicationID = 1396985427
const tableSQL = "CREATE TABLE records (name TEXT NOT NULL, type INTEGER NOT NULL, values_json TEXT NOT NULL, ttl INTEGER NOT NULL, expires_at TEXT NOT NULL, PRIMARY KEY(name,type))"

func validateRecord(r Record) error {
	if r.Name == "" || r.Name != canonicalName(r.Name) || len(r.Values) == 0 {
		return ErrInvalidRecord
	}
	if !ValidName(r.Name) {
		return ErrInvalidRecord
	}
	if !r.ExpiresAt.IsZero() && (r.ExpiresAt.UTC().Year() < 1 || r.ExpiresAt.UTC().Year() > 9999) {
		return ErrInvalidRecord
	}
	switch r.Type {
	case dns.TypeA, dns.TypeAAAA:
		for _, v := range r.Values {
			ip := net.ParseIP(v)
			if ip == nil || (r.Type == dns.TypeA) != (ip.To4() != nil) {
				return ErrInvalidRecord
			}
		}
	case dns.TypeCNAME:
		if len(r.Values) != 1 || r.Values[0] == "" || strings.TrimSpace(r.Values[0]) != r.Values[0] {
			return ErrInvalidRecord
		}
		if !ValidName(r.Values[0]) {
			return ErrInvalidRecord
		}
	case dns.TypeTXT:
		for _, v := range r.Values {
			if len(v) > 255 {
				return ErrInvalidRecord
			}
		}
	default:
		return ErrInvalidRecord
	}
	return nil
}

// OpenSQLite opens one exclusively owned local database. The existing parent
// directory must be private on Unix; Windows ACLs remain the operator's responsibility.
func OpenSQLite(path string) (_ *Store, err error) {
	if err = ValidatePaths(map[string]string{DefaultName: path}); err != nil {
		return nil, err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() {
		return nil, errors.New("database parent must be an existing directory")
	}
	if runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
		return nil, errors.New("database parent must be private")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		var f *os.File
		f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("database must be a private regular file")
	}
	uriPath := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	q.Set("_txlock", "exclusive")
	q.Add("_pragma", "busy_timeout(1000)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "locking_mode(EXCLUSIVE)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()
	// Acquiring an exclusive transaction, then retaining EXCLUSIVE locking mode,
	// prevents a second process from opening a separate stale in-memory cache.
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var integrity string
	if err = tx.QueryRow("PRAGMA quick_check").Scan(&integrity); err != nil {
		return nil, err
	}
	if integrity != "ok" {
		return nil, errors.New("record database integrity check failed")
	}
	var version, id, count int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if err = tx.QueryRow("PRAGMA application_id").Scan(&id); err != nil {
		return nil, err
	}
	if err = tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&count); err != nil {
		return nil, err
	}
	if version == 0 && id == 0 && count == 0 {
		if _, err = tx.Exec(tableSQL); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(fmt.Sprintf("PRAGMA application_id=%d", applicationID)); err != nil {
			return nil, err
		}
		if _, err = tx.Exec("PRAGMA user_version=1"); err != nil {
			return nil, err
		}
	} else if version != 1 || id != applicationID || count != 1 {
		return nil, errors.New("unsupported record database schema")
	}
	var schema string
	if err = tx.QueryRow("SELECT sql FROM sqlite_master WHERE name='records' AND type='table'").Scan(&schema); err != nil {
		return nil, err
	}
	if schema != tableSQL {
		return nil, errors.New("unexpected record database schema")
	}
	rows, err := tx.Query("SELECT name,type,values_json,ttl,expires_at FROM records")
	if err != nil {
		return nil, err
	}
	s := New()
	var expired []key
	for rows.Next() {
		var r Record
		var typ, ttl int64
		var values, expiry string
		if err = rows.Scan(&r.Name, &typ, &values, &ttl, &expiry); err != nil {
			rows.Close()
			return nil, err
		}
		if typ < 0 || typ > 65535 || ttl < 0 || ttl > 4294967295 {
			rows.Close()
			return nil, ErrInvalidRecord
		}
		r.Type = uint16(typ)
		r.TTL = uint32(ttl)
		if err = json.Unmarshal([]byte(values), &r.Values); err != nil {
			rows.Close()
			return nil, ErrInvalidRecord
		}
		if expiry != "" {
			r.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiry)
			if err != nil {
				rows.Close()
				return nil, ErrInvalidRecord
			}
		}
		if err = validateRecord(r); err != nil {
			rows.Close()
			return nil, err
		}
		if !r.expired(s.now()) {
			s.records[key{r.Name, r.Type}] = r
		} else {
			expired = append(expired, key{r.Name, r.Type})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for k := range s.records {
		if k.rrtype == dns.TypeCNAME {
			for other := range s.records {
				if other.name == k.name && other.rrtype != dns.TypeCNAME {
					return nil, ErrInvalidRecord
				}
			}
		}
	}
	for _, k := range expired {
		if _, err = tx.Exec("DELETE FROM records WHERE name=? AND type=?", k.name, k.rrtype); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	s.db = db
	return s, nil
}
func (s *Store) persistSet(r Record) error {
	values, err := json.Marshal(r.Values)
	if err != nil {
		return err
	}
	expiry := ""
	if !r.ExpiresAt.IsZero() {
		expiry = r.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec("INSERT INTO records(name,type,values_json,ttl,expires_at) VALUES(?,?,?,?,?) ON CONFLICT(name,type) DO UPDATE SET values_json=excluded.values_json,ttl=excluded.ttl,expires_at=excluded.expires_at", r.Name, r.Type, string(values), r.TTL, expiry)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) persistDelete(k key) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM records WHERE name=? AND type=?", k.name, k.rrtype); err != nil {
		return err
	}
	return tx.Commit()
}

// ValidName accepts DNS presentation names (including underscore labels), but
// rejects literal whitespace/control characters and malformed label structure.
func ValidName(name string) bool {
	if name == "" || len(name) > 255 || strings.IndexFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	_, ok := dns.IsDomainName(name)
	return ok
}

// normalizeValidated operates on an owned Values slice; callers validate and
// publish the resulting representation under the mutation lock.
func normalizeValidated(r Record) (Record, error) {
	switch r.Type {
	case dns.TypeA, dns.TypeAAAA:
		for i, v := range r.Values {
			ip := net.ParseIP(strings.TrimSpace(v))
			if ip == nil || (r.Type == dns.TypeA) != (ip.To4() != nil) {
				return r, ErrInvalidRecord
			}
			r.Values[i] = ip.String()
		}
	case dns.TypeCNAME:
		if len(r.Values) != 1 {
			return r, ErrInvalidRecord
		}
		target := strings.TrimSpace(r.Values[0])
		if target == "" {
			return r, ErrInvalidRecord
		}
		r.Values[0] = canonicalName(target)
	}
	return r, nil
}
