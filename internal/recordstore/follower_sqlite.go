package recordstore

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

const followerApplicationID = 0x53444631
const followerEnrollmentSQL = "CREATE TABLE follower_enrollment (id INTEGER PRIMARY KEY CHECK(id=1), cluster_id TEXT NOT NULL, kind TEXT NOT NULL, ruleset_id TEXT NOT NULL, lineage_id TEXT NOT NULL, authority_epoch TEXT NOT NULL, has_snapshot INTEGER NOT NULL CHECK(has_snapshot IN (0,1)))"
const followerStateSQL = "CREATE TABLE follower_state (id INTEGER PRIMARY KEY CHECK(id=1), revision TEXT NOT NULL, content_sha256 TEXT NOT NULL, envelope BLOB NOT NULL)"

// CreateFollowerSQLite requires an absent final path. Failed creation leaves any
// owned partial file for inspection; it never deletes or replaces another file.
func CreateFollowerSQLite(path string, e FollowerEnrollment) (*FollowerStore, error) {
	return openFollower(path, e, true)
}

// OpenFollowerSQLite requires an existing initialized follower database. Missing,
// empty and unrelated files are never initialized or converted.
func OpenFollowerSQLite(path string, e FollowerEnrollment) (*FollowerStore, error) {
	return openFollower(path, e, false)
}
func followerConnection(path string, create bool) (*sql.DB, error) {
	if !sqlitePlatformSupported {
		return nil, ErrSQLiteUnsupported
	}
	if ValidatePaths(map[string]string{DefaultName: path}) != nil {
		return nil, ErrFollowerInput
	}
	parent, e := os.Lstat(filepath.Dir(path))
	if e != nil || !parent.IsDir() || runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
		return nil, ErrFollowerStorage
	}
	if create {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			if os.IsExist(e) {
				return nil, ErrFollowerExists
			}
			return nil, ErrFollowerStorage
		}
		if f.Close() != nil {
			return nil, ErrFollowerStorage
		}
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, ErrFollowerStorage
	}
	if !create && info.Size() == 0 {
		return nil, ErrFollowerSchema
	}
	uriPath := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	q.Set("mode", "rw")
	q.Set("_txlock", "exclusive")
	for _, pragma := range []string{"busy_timeout(1000)", "synchronous(FULL)", "locking_mode(EXCLUSIVE)", "foreign_keys(ON)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, ErrFollowerStorage
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}
func openFollower(path string, enrollment FollowerEnrollment, create bool) (_ *FollowerStore, err error) {
	s, err := NewFollowerMemory(enrollment)
	if err != nil {
		return nil, err
	}
	db, err := followerConnection(path, create)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()
	tx, e := db.Begin()
	if e != nil {
		return nil, ErrFollowerStorage
	}
	defer tx.Rollback()
	if create {
		var objects, id, version int
		if tx.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&objects) != nil || tx.QueryRow("PRAGMA application_id").Scan(&id) != nil || tx.QueryRow("PRAGMA user_version").Scan(&version) != nil || objects != 0 || id != 0 || version != 0 {
			return nil, ErrFollowerSchema
		}
		for _, statement := range []string{followerEnrollmentSQL, followerStateSQL, fmt.Sprintf("PRAGMA application_id=%d", followerApplicationID), "PRAGMA user_version=1"} {
			if _, e = tx.Exec(statement); e != nil {
				return nil, ErrFollowerStorage
			}
		}
		if _, e = tx.Exec("INSERT INTO follower_enrollment VALUES(1,?,?,?,?,?,0)", enrollment.ClusterID, enrollment.Kind, enrollment.RulesetID, enrollment.LineageID, enrollment.AuthorityEpoch); e != nil {
			return nil, ErrFollowerStorage
		}
	}
	p, e := readFollower(tx, enrollment)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, ErrFollowerStorage
	}
	s.db = db
	s.current.Store(p)
	return s, nil
}
func readFollowerEnrollment(tx *sql.Tx) (FollowerEnrollment, int, error) {
	var count, bad int
	e := tx.QueryRow(`SELECT count(*),coalesce(sum(CASE WHEN typeof(id)!='integer' OR id!=1 OR typeof(cluster_id)!='text' OR length(CAST(cluster_id AS BLOB))>128 OR typeof(kind)!='text' OR length(CAST(kind AS BLOB))>128 OR typeof(ruleset_id)!='text' OR length(CAST(ruleset_id AS BLOB))>128 OR typeof(lineage_id)!='text' OR length(CAST(lineage_id AS BLOB))>128 OR typeof(authority_epoch)!='text' OR length(CAST(authority_epoch AS BLOB))>128 OR typeof(has_snapshot)!='integer' OR has_snapshot NOT IN (0,1) THEN 1 ELSE 0 END),0) FROM follower_enrollment`).Scan(&count, &bad)
	if e != nil || count != 1 || bad != 0 {
		return FollowerEnrollment{}, 0, ErrFollowerSchema
	}
	var enrollment FollowerEnrollment
	var has int
	if tx.QueryRow("SELECT cluster_id,kind,ruleset_id,lineage_id,authority_epoch,has_snapshot FROM follower_enrollment WHERE id=1").Scan(&enrollment.ClusterID, &enrollment.Kind, &enrollment.RulesetID, &enrollment.LineageID, &enrollment.AuthorityEpoch, &has) != nil || !validFollowerEnrollment(enrollment) {
		return FollowerEnrollment{}, 0, ErrFollowerSchema
	}
	return enrollment, has, nil
}
func readFollower(tx *sql.Tx, expected FollowerEnrollment) (*followerPublication, error) {
	var check string
	var id, version, count, size int
	if tx.QueryRow("PRAGMA quick_check").Scan(&check) != nil || check != "ok" {
		return nil, ErrFollowerSchema
	}
	if tx.QueryRow("PRAGMA application_id").Scan(&id) != nil || tx.QueryRow("PRAGMA user_version").Scan(&version) != nil || id != followerApplicationID || version != 1 {
		return nil, ErrFollowerSchema
	}
	// This schema creates no SQLite autoindexes or sequence tables. Every object
	// must be one of its two exact tables; arbitrary sqlite-like names are rejected.
	if tx.QueryRow("SELECT count(*),coalesce(max(length(CAST(name AS BLOB))+length(CAST(type AS BLOB))+coalesce(length(CAST(sql AS BLOB)),0)),0) FROM sqlite_master").Scan(&count, &size) != nil || count != 2 || size > 4096 {
		return nil, ErrFollowerSchema
	}
	rows, e := tx.Query("SELECT name,type,sql FROM sqlite_master")
	if e != nil {
		return nil, ErrFollowerSchema
	}
	schemas := map[string]string{}
	for rows.Next() {
		var n, k, ddl string
		if rows.Scan(&n, &k, &ddl) != nil || k != "table" {
			rows.Close()
			return nil, ErrFollowerSchema
		}
		schemas[n] = ddl
	}
	e = rows.Err()
	rows.Close()
	if e != nil || schemas["follower_enrollment"] != followerEnrollmentSQL || schemas["follower_state"] != followerStateSQL {
		return nil, ErrFollowerSchema
	}
	enrollment, has, e := readFollowerEnrollment(tx)
	if e != nil {
		return nil, e
	}
	if enrollment != expected {
		return nil, ErrFollowerIdentity
	}
	var bad int
	if tx.QueryRow(`SELECT count(*),coalesce(sum(CASE WHEN typeof(id)!='integer' OR id!=1 OR typeof(revision)!='text' OR length(CAST(revision AS BLOB))>20 OR typeof(content_sha256)!='text' OR length(CAST(content_sha256 AS BLOB))!=64 OR typeof(envelope)!='blob' OR length(envelope)>? THEN 1 ELSE 0 END),0) FROM follower_state`, recordset.MaxBytes).Scan(&count, &bad) != nil || count != has || bad != 0 {
		return nil, ErrFollowerSchema
	}
	if has == 0 {
		return &followerPublication{status: followerEmpty}, nil
	}
	var revision, digest string
	var raw []byte
	if tx.QueryRow("SELECT revision,content_sha256,envelope FROM follower_state WHERE id=1").Scan(&revision, &digest, &raw) != nil {
		return nil, ErrFollowerSchema
	}
	rev, ok := canonicalRevision(revision)
	if !ok || !validDigest(digest) {
		return nil, ErrFollowerSchema
	}
	snapshot, e := recordset.Parse(raw)
	if e != nil {
		return nil, ErrFollowerSchema
	}
	meta := snapshot.Metadata()
	wire, e := snapshot.MarshalJSON()
	if e != nil || !bytes.Equal(raw, wire) || meta.Revision != rev || meta.ContentSHA256 != digest || meta.RulesetID != enrollment.RulesetID || meta.LineageID != enrollment.LineageID {
		return nil, ErrFollowerSchema
	}
	return &followerPublication{status: followerReady, snapshot: snapshot, envelope: wire}, nil
}
func (s *FollowerStore) persistFollower(previous, next *followerPublication) error {
	tx, e := s.db.Begin()
	if e != nil {
		return ErrFollowerStorage
	}
	rollback := func() error {
		if tx.Rollback() != nil {
			s.current.Store(&followerPublication{status: followerFaulted})
			return errors.Join(ErrFollowerStorage, ErrFollowerFaulted)
		}
		return ErrFollowerStorage
	}
	enrollment, has, e := readFollowerEnrollment(tx)
	if e != nil || enrollment != s.enrollment || has != boolInt(previous.status == followerReady) {
		return rollback()
	}
	meta := next.snapshot.Metadata()
	if _, e = tx.Exec("INSERT INTO follower_state(id,revision,content_sha256,envelope) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,content_sha256=excluded.content_sha256,envelope=excluded.envelope", strconv.FormatUint(meta.Revision, 10), meta.ContentSHA256, next.envelope); e != nil {
		return rollback()
	}
	result, e := tx.Exec("UPDATE follower_enrollment SET has_snapshot=1 WHERE id=1")
	if e != nil {
		return rollback()
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return rollback()
	}
	if s.hooks.beforeCommit != nil {
		if e = s.hooks.beforeCommit(tx); e != nil {
			return rollback()
		}
	}
	if e = tx.Commit(); e != nil {
		s.current.Store(&followerPublication{status: followerFaulted})
		return errors.Join(ErrFollowerStorage, ErrFollowerFaulted)
	}
	return nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
