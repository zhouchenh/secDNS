package recordstore

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordset"
)

const snapshotTableSQLV2 = "CREATE TABLE snapshot_state (id INTEGER PRIMARY KEY CHECK(id=1), envelope BLOB NOT NULL)"
const receiptTableSQLV2 = "CREATE TABLE operation_receipts (operation_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, committed_revision TEXT NOT NULL, content_sha256 TEXT NOT NULL, committed_at TEXT NOT NULL)"
const snapshotTableSQLV3 = "CREATE TABLE snapshot_state (id INTEGER PRIMARY KEY CHECK(id=1), envelope BLOB NOT NULL, operator_provenance BLOB)"
const receiptTableSQLV3 = "CREATE TABLE operation_receipts (operation_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, committed_revision TEXT NOT NULL, content_sha256 TEXT NOT NULL, committed_at TEXT NOT NULL, operator_provenance BLOB)"

const receiptTableSQLV4 = "CREATE TABLE operation_receipts (operation_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, committed_revision TEXT NOT NULL, content_sha256 TEXT NOT NULL, committed_at TEXT NOT NULL, operator_provenance BLOB, rrset_request BLOB)"

var ErrMigrationIncompatible = errors.New("legacy records cannot form an exact snapshot")

func OpenVersionedSQLite(path string, enrollment Enrollment) (*VersionedStore, error) {
	return openVersionedSQLite(path, enrollment, versionedHooks{})
}
func openVersionedSQLite(path string, enrollment Enrollment, hooks versionedHooks) (_ *VersionedStore, err error) {
	return openVersionedSQLiteMode(path, enrollment, hooks, false)
}

// EnableRRsetMutationsSQLite is explicit offline schema3-to-4 migration.
// The existing exclusive database lock prevents migration of an active store.
// It never creates a store or migrates schemas1/2; keep a private offline backup.
func EnableRRsetMutationsSQLite(path string, enrollment Enrollment) error {
	s, err := openVersionedSQLiteMode(path, enrollment, versionedHooks{}, true)
	if err != nil {
		return err
	}
	return s.Close()
}
func openVersionedSQLiteMode(path string, enrollment Enrollment, hooks versionedHooks, migrateRRsets bool) (_ *VersionedStore, err error) {
	s, err := NewVersionedMemory(enrollment)
	if err != nil {
		return nil, err
	}
	db, err := openExclusiveDatabaseMode(path, migrateRRsets)
	if err != nil {
		if errors.Is(err, ErrSQLiteUnsupported) {
			return nil, ErrSQLiteUnsupported
		}
		return nil, ErrVersionedStorage
	}
	defer func() {
		if err != nil {
			_ = db.Close()
			switch {
			case errors.Is(err, ErrVersionedSchema), errors.Is(err, ErrIdentity), errors.Is(err, ErrMigrationRequired), errors.Is(err, ErrMigrationIncompatible):
			default:
				err = ErrVersionedStorage
			}
		}
	}()
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
		return nil, ErrVersionedSchema
	}
	var version, id int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if err = tx.QueryRow("PRAGMA application_id").Scan(&id); err != nil {
		return nil, err
	}
	schemas, err := readSchema(tx)
	if err != nil {
		return nil, err
	}
	if migrateRRsets && version != 3 {
		return nil, ErrVersionedSchema
	}
	switch {
	case version == 0 && id == 0 && len(schemas) == 0:
		if err = createVersionedSchema(tx, s.current.Load().snapshot); err != nil {
			return nil, err
		}
		s.schemaVersion = 3
	case version == 1 && id == applicationID && len(schemas) == 1 && schemas["records"] == tableSQL:
		if !enrollment.AllowSchema1Migration {
			return nil, ErrMigrationRequired
		}
		records, e := readLegacyExact(tx)
		if e != nil {
			return nil, e
		}
		snapshot, e := recordset.New(enrollment.RulesetID, enrollment.LineageID, 1, records)
		if e != nil {
			return nil, ErrMigrationIncompatible
		}
		if err = createVersionedSchema(tx, snapshot); err != nil {
			return nil, err
		}
		if _, err = tx.Exec("DROP TABLE records"); err != nil {
			return nil, err
		}
		s.current.Store(&versionedGeneration{snapshot: snapshot})
		s.schemaVersion = 3
	case version == 2 && id == applicationID && len(schemas) == 2 && schemas["snapshot_state"] == snapshotTableSQLV2 && schemas["operation_receipts"] == receiptTableSQLV2:
		generation, receipts, e := loadVersioned(tx, enrollment, false, false)
		if e != nil {
			return nil, e
		}
		s.current.Store(generation)
		s.receipts = receipts
		s.schemaVersion = 2
		if enrollment.AllowSchema2Migration {
			if _, err = tx.Exec("ALTER TABLE snapshot_state ADD COLUMN operator_provenance BLOB"); err != nil {
				return nil, err
			}
			if _, err = tx.Exec("ALTER TABLE operation_receipts ADD COLUMN operator_provenance BLOB"); err != nil {
				return nil, err
			}
			if _, err = tx.Exec("PRAGMA user_version=3"); err != nil {
				return nil, err
			}
			s.schemaVersion = 3
		}
	case version == 3 && id == applicationID && len(schemas) == 2 && schemas["snapshot_state"] == snapshotTableSQLV3 && schemas["operation_receipts"] == receiptTableSQLV3:
		generation, receipts, e := loadVersioned(tx, enrollment, true, false)
		if e != nil {
			return nil, e
		}
		s.current.Store(generation)
		s.receipts = receipts
		s.schemaVersion = 3
	case version == 4 && id == applicationID && len(schemas) == 2 && schemas["snapshot_state"] == snapshotTableSQLV3 && schemas["operation_receipts"] == receiptTableSQLV4:
		generation, receipts, e := loadVersioned(tx, enrollment, true, true)
		if e != nil {
			return nil, e
		}
		s.current.Store(generation)
		s.receipts = receipts
		s.schemaVersion = 4
	default:
		return nil, ErrVersionedSchema
	}
	if migrateRRsets {
		if _, err = tx.Exec("ALTER TABLE operation_receipts ADD COLUMN rrset_request BLOB"); err != nil {
			return nil, err
		}
		if _, err = tx.Exec("PRAGMA user_version=4"); err != nil {
			return nil, err
		}
		s.schemaVersion = 4
	}
	if hooks.beforeCommit != nil {
		if err = hooks.beforeCommit(tx); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if hooks.afterCommit != nil {
		hooks.afterCommit()
	}
	s.db = db
	return s, nil
}
func readSchema(tx *sql.Tx) (map[string]string, error) {
	var count, size int
	if err := tx.QueryRow("SELECT count(*),coalesce(max(length(CAST(name AS BLOB))+length(CAST(type AS BLOB))+length(CAST(sql AS BLOB))),0) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").Scan(&count, &size); err != nil {
		return nil, err
	}
	if count > 2 || size > 4096 {
		return nil, ErrVersionedSchema
	}
	rows, err := tx.Query("SELECT name,type,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var name, kind, statement string
		if err := rows.Scan(&name, &kind, &statement); err != nil {
			return nil, ErrVersionedSchema
		}
		if len(m) >= 3 || kind != "table" {
			return nil, ErrVersionedSchema
		}
		m[name] = statement
	}
	return m, rows.Err()
}
func createVersionedSchema(tx *sql.Tx, snapshot *recordset.Snapshot) error {
	for _, statement := range []string{snapshotTableSQLV3, receiptTableSQLV3, fmt.Sprintf("PRAGMA application_id=%d", applicationID), "PRAGMA user_version=3"} {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	wire, _ := snapshot.MarshalJSON()
	_, err := tx.Exec("INSERT INTO snapshot_state(id,envelope) VALUES(1,?)", wire)
	return err
}
func canonicalRevision(raw string) (uint64, bool) {
	n, e := strconv.ParseUint(raw, 10, 64)
	return n, e == nil && n > 0 && strconv.FormatUint(n, 10) == raw
}
func validDigest(raw string) bool {
	if len(raw) != 64 || strings.ToLower(raw) != raw {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}
func decodeStoredOperatorSuppliedProvenance(present int, raw []byte) (recordset.OperatorSuppliedProvenance, bool, error) {
	if present == 0 {
		if raw != nil {
			return recordset.OperatorSuppliedProvenance{}, false, ErrVersionedSchema
		}
		return recordset.OperatorSuppliedProvenance{}, false, nil
	}
	if present != 1 || len(raw) == 0 || len(raw) > recordset.MaxOperatorSuppliedProvenanceBytes {
		return recordset.OperatorSuppliedProvenance{}, false, ErrVersionedSchema
	}
	p, err := recordset.ParseOperatorSuppliedProvenance(raw)
	if err != nil {
		return recordset.OperatorSuppliedProvenance{}, false, ErrVersionedSchema
	}
	canonical, _ := p.MarshalJSON()
	if !bytes.Equal(raw, canonical) {
		return recordset.OperatorSuppliedProvenance{}, false, ErrVersionedSchema
	}
	return p, true, nil
}

func loadVersioned(tx *sql.Tx, e Enrollment, withProvenance, withRRsets bool) (*versionedGeneration, map[string]Receipt, error) {
	var count, size, provenanceSize int
	if withProvenance {
		if err := tx.QueryRow("SELECT count(*),coalesce(max(length(CAST(envelope AS BLOB))),0),coalesce(max(length(CAST(operator_provenance AS BLOB))),0) FROM snapshot_state").Scan(&count, &size, &provenanceSize); err != nil {
			return nil, nil, err
		}
	} else if err := tx.QueryRow("SELECT count(*),coalesce(max(length(CAST(envelope AS BLOB))),0) FROM snapshot_state").Scan(&count, &size); err != nil {
		return nil, nil, err
	}
	if count != 1 || size < 1 || size > recordset.MaxBytes || provenanceSize > recordset.MaxOperatorSuppliedProvenanceBytes {
		return nil, nil, ErrVersionedSchema
	}
	var wrong int
	snapshotTypes := "SELECT count(*) FROM snapshot_state WHERE typeof(id)!='integer' OR typeof(envelope)!='blob'"
	if withProvenance {
		snapshotTypes += " OR (operator_provenance IS NOT NULL AND typeof(operator_provenance)!='blob')"
	}
	if err := tx.QueryRow(snapshotTypes).Scan(&wrong); err != nil {
		return nil, nil, err
	}
	if wrong != 0 {
		return nil, nil, ErrVersionedSchema
	}
	var wire, provenanceRaw []byte
	var provenancePresent int
	if withProvenance {
		if err := tx.QueryRow("SELECT envelope,operator_provenance IS NOT NULL,operator_provenance FROM snapshot_state WHERE id=1").Scan(&wire, &provenancePresent, &provenanceRaw); err != nil {
			return nil, nil, ErrVersionedSchema
		}
	} else if err := tx.QueryRow("SELECT envelope FROM snapshot_state WHERE id=1").Scan(&wire); err != nil {
		return nil, nil, ErrVersionedSchema
	}
	snapshot, err := recordset.Parse(wire)
	if err != nil {
		return nil, nil, ErrVersionedSchema
	}
	canonical, _ := snapshot.MarshalJSON()
	if !bytes.Equal(wire, canonical) {
		return nil, nil, ErrVersionedSchema
	}
	meta := snapshot.Metadata()
	if meta.RulesetID != e.RulesetID || meta.LineageID != e.LineageID {
		return nil, nil, ErrIdentity
	}
	generation := &versionedGeneration{snapshot: snapshot}
	if withProvenance {
		generation.operatorSuppliedProvenance, generation.hasOperatorSuppliedProvenance, err = decodeStoredOperatorSuppliedProvenance(provenancePresent, provenanceRaw)
		if err != nil || generation.hasOperatorSuppliedProvenance && generation.operatorSuppliedProvenance.ContentSHA256() != meta.ContentSHA256 {
			return nil, nil, ErrVersionedSchema
		}
	}
	if meta.Revision == 1 && generation.hasOperatorSuppliedProvenance {
		return nil, nil, ErrVersionedSchema
	}
	if withRRsets {
		var total int64
		if err = tx.QueryRow("SELECT coalesce(sum(length(CAST(rrset_request AS BLOB))),0) FROM operation_receipts").Scan(&total); err != nil {
			return nil, nil, err
		}
		if total > MaxRRsetReceiptBytes {
			return nil, nil, ErrVersionedSchema
		}
	}
	var maxLength int
	receiptBounds := "SELECT count(*),coalesce(max(length(CAST(operation_id AS BLOB))+length(CAST(request_sha256 AS BLOB))+length(CAST(committed_revision AS BLOB))+length(CAST(content_sha256 AS BLOB))+length(CAST(committed_at AS BLOB))),0) FROM operation_receipts"
	if withProvenance {
		receiptBounds = "SELECT count(*),coalesce(max(length(CAST(operation_id AS BLOB))+length(CAST(request_sha256 AS BLOB))+length(CAST(committed_revision AS BLOB))+length(CAST(content_sha256 AS BLOB))+length(CAST(committed_at AS BLOB))+coalesce(length(CAST(operator_provenance AS BLOB)),0)),0) FROM operation_receipts"
	}
	if withRRsets {
		receiptBounds = strings.Replace(receiptBounds, "),0) FROM", "+coalesce(length(CAST(rrset_request AS BLOB)),0)),0) FROM", 1)
	}
	if err = tx.QueryRow(receiptBounds).Scan(&count, &maxLength); err != nil {
		return nil, nil, err
	}
	maxReceiptLength := 310
	if withProvenance {
		maxReceiptLength += recordset.MaxOperatorSuppliedProvenanceBytes
	}
	if withRRsets {
		maxReceiptLength += maxRRsetReceiptMetadataBytes
	}
	if count > MaxOperationReceipts || maxLength > maxReceiptLength || meta.Revision != uint64(count)+1 {
		return nil, nil, ErrVersionedSchema
	}
	receiptTypes := "SELECT count(*) FROM operation_receipts WHERE typeof(operation_id)!='text' OR typeof(request_sha256)!='text' OR typeof(committed_revision)!='text' OR typeof(content_sha256)!='text' OR typeof(committed_at)!='text'"
	if withProvenance {
		receiptTypes += " OR (operator_provenance IS NOT NULL AND typeof(operator_provenance)!='blob')"
	}
	if withRRsets {
		receiptTypes += " OR (rrset_request IS NOT NULL AND typeof(rrset_request)!='blob')"
	}
	if err = tx.QueryRow(receiptTypes).Scan(&wrong); err != nil {
		return nil, nil, err
	}
	if wrong != 0 {
		return nil, nil, ErrVersionedSchema
	}
	receiptQuery := "SELECT operation_id,request_sha256,committed_revision,content_sha256,committed_at FROM operation_receipts"
	if withProvenance {
		receiptQuery = "SELECT operation_id,request_sha256,committed_revision,content_sha256,committed_at,operator_provenance IS NOT NULL,operator_provenance FROM operation_receipts"
	}
	if withRRsets {
		receiptQuery = strings.Replace(receiptQuery, " FROM operation_receipts", ",rrset_request IS NOT NULL,rrset_request FROM operation_receipts", 1)
	}
	rows, err := tx.Query(receiptQuery)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	receipts := map[string]Receipt{}
	revisions := map[uint64]bool{}
	latestSeen := meta.Revision == 1
	for rows.Next() {
		var r Receipt
		var revision, at string
		var raw []byte
		var present, requestPresent int
		var requestRaw []byte
		if withRRsets {
			err = rows.Scan(&r.OperationID, &r.RequestSHA256, &revision, &r.ContentSHA256, &at, &present, &raw, &requestPresent, &requestRaw)
		} else if withProvenance {
			err = rows.Scan(&r.OperationID, &r.RequestSHA256, &revision, &r.ContentSHA256, &at, &present, &raw)
		} else {
			err = rows.Scan(&r.OperationID, &r.RequestSHA256, &revision, &r.ContentSHA256, &at)
		}
		if err != nil {
			return nil, nil, ErrVersionedSchema
		}
		n, ok := canonicalRevision(revision)
		if !ok || n < 2 || n > meta.Revision || revisions[n] || !validOperationID(r.OperationID) || !validDigest(r.RequestSHA256) || !validDigest(r.ContentSHA256) {
			return nil, nil, ErrVersionedSchema
		}
		r.Revision = n
		r.CommittedAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil || r.CommittedAt.IsZero() || r.CommittedAt.Year() < 1 || r.CommittedAt.Year() > 9999 || r.CommittedAt.UTC().Format(time.RFC3339Nano) != at {
			return nil, nil, ErrVersionedSchema
		}
		if withProvenance {
			r.operatorSuppliedProvenance, r.hasOperatorSuppliedProvenance, err = decodeStoredOperatorSuppliedProvenance(present, raw)
			if err != nil || r.hasOperatorSuppliedProvenance && r.operatorSuppliedProvenance.ContentSHA256() != r.ContentSHA256 {
				return nil, nil, ErrVersionedSchema
			}
		}
		expected := Expected{RulesetID: e.RulesetID, LineageID: e.LineageID, Revision: n - 1}
		digest := requestDigest(expected, r.ContentSHA256)
		if r.hasOperatorSuppliedProvenance {
			digest = requestDigestWithOperatorSuppliedProvenance(expected, r.ContentSHA256, r.operatorSuppliedProvenance)
		}
		if requestPresent != 0 {
			if r.hasOperatorSuppliedProvenance || len(requestRaw) > maxRRsetReceiptMetadataBytes {
				return nil, nil, ErrVersionedSchema
			}
			mutation, e := decodeRRsetReceiptMetadata(requestRaw, r.ContentSHA256)
			if e != nil {
				return nil, nil, ErrVersionedSchema
			}
			if mutation.OperationID != r.OperationID || mutation.RulesetID != expected.RulesetID || mutation.LineageID != expected.LineageID || mutation.Revision != expected.Revision {
				return nil, nil, ErrVersionedSchema
			}
			digest = rrsetRequestDigest(mutation)
			r.rrsetRequest = string(requestRaw)
		}
		if r.RequestSHA256 != digest {
			return nil, nil, ErrVersionedSchema
		}
		if n == meta.Revision {
			if r.ContentSHA256 != meta.ContentSHA256 || r.hasOperatorSuppliedProvenance != generation.hasOperatorSuppliedProvenance || r.hasOperatorSuppliedProvenance && r.operatorSuppliedProvenance != generation.operatorSuppliedProvenance {
				return nil, nil, ErrVersionedSchema
			}
			latestSeen = true
		}
		revisions[n] = true
		receipts[r.OperationID] = r
	}
	if err = rows.Err(); err != nil {
		return nil, nil, err
	}
	if !latestSeen {
		return nil, nil, ErrVersionedSchema
	}
	return generation, receipts, nil
}
func readLegacyExact(tx *sql.Tx) ([]recordset.Record, error) {
	var count, size int
	if err := tx.QueryRow("SELECT count(*),coalesce(sum(length(CAST(name AS BLOB))+length(CAST(values_json AS BLOB))+length(CAST(expires_at AS BLOB))),0) FROM records").Scan(&count, &size); err != nil {
		return nil, err
	}
	if count > recordset.MaxRecords || size > recordset.MaxBytes {
		return nil, ErrMigrationIncompatible
	}
	var wrong int
	if err := tx.QueryRow("SELECT count(*) FROM records WHERE typeof(name)!='text' OR typeof(type)!='integer' OR typeof(values_json)!='text' OR typeof(ttl)!='integer' OR typeof(expires_at)!='text'").Scan(&wrong); err != nil {
		return nil, err
	}
	if wrong != 0 {
		return nil, ErrMigrationIncompatible
	}
	rows, err := tx.Query("SELECT name,type,values_json,ttl,expires_at FROM records")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]recordset.Record, 0, count)
	type migrationRecord struct {
		Name       string          `json:"name"`
		Type       string          `json:"type"`
		Values     json.RawMessage `json:"values"`
		TTLSeconds uint32          `json:"ttl_seconds"`
		ExpiresAt  string          `json:"expires_at"`
	}
	for rows.Next() {
		var r recordset.Record
		var typ, ttl int64
		var values string
		if err = rows.Scan(&r.Name, &typ, &values, &ttl, &r.ExpiresAt); err != nil {
			return nil, ErrMigrationIncompatible
		}
		if typ < 0 || typ > 65535 || ttl < 0 || ttl > 4294967295 {
			return nil, ErrMigrationIncompatible
		}
		r.Type = dns.TypeToString[uint16(typ)]
		r.TTLSeconds = uint32(ttl)
		// Decode string elements individually: JSON null must not silently become an
		// empty TXT chunk. Raw values are also checked through the strict snapshot
		// parser below so invalid UTF-8/surrogate escapes cannot be normalized away.
		var raw []json.RawMessage
		if err = json.Unmarshal([]byte(values), &raw); err != nil || len(raw) == 0 {
			return nil, ErrMigrationIncompatible
		}
		for _, v := range raw {
			if len(v) < 2 || v[0] != '"' {
				return nil, ErrMigrationIncompatible
			}
			var text string
			if err = json.Unmarshal(v, &text); err != nil {
				return nil, ErrMigrationIncompatible
			}
			r.Values = append(r.Values, text)
		}
		// Use the existing strict wire parser on the original values bytes. A
		// temporary one-record envelope detects lossy JSON string decoding
		// without introducing a second Unicode escape implementation.
		single, e := recordset.New("migration", "validation", 1, []recordset.Record{r})
		if e != nil {
			return nil, ErrMigrationIncompatible
		}
		rawWire, e := json.Marshal(struct {
			recordset.Metadata
			Records []migrationRecord `json:"records"`
		}{
			Metadata: single.Metadata(),
			Records: []migrationRecord{{
				Name: r.Name, Type: r.Type, Values: json.RawMessage(values),
				TTLSeconds: r.TTLSeconds, ExpiresAt: r.ExpiresAt,
			}},
		})
		if e != nil {
			return nil, ErrMigrationIncompatible
		}
		if _, e = recordset.Parse(rawWire); e != nil {
			return nil, ErrMigrationIncompatible
		}
		records = append(records, r)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}
func (s *VersionedStore) persistReplacement(generation *versionedGeneration, r Receipt) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	wire, _ := generation.snapshot.MarshalJSON()
	var provenance any
	if generation.hasOperatorSuppliedProvenance {
		provenance, err = generation.operatorSuppliedProvenance.MarshalJSON()
		if err != nil {
			return ErrVersionedSchema
		}
	}
	var result sql.Result
	switch s.schemaVersion {
	case 2:
		if generation.hasOperatorSuppliedProvenance {
			return ErrOperatorProvenanceUnavailable
		}
		result, err = tx.Exec("UPDATE snapshot_state SET envelope=? WHERE id=1", wire)
	case 3, 4:
		result, err = tx.Exec("UPDATE snapshot_state SET envelope=?,operator_provenance=? WHERE id=1", wire, provenance)
	default:
		return ErrVersionedSchema
	}
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrVersionedSchema
	}
	switch s.schemaVersion {
	case 2:
		_, err = tx.Exec("INSERT INTO operation_receipts(operation_id,request_sha256,committed_revision,content_sha256,committed_at) VALUES(?,?,?,?,?)", r.OperationID, r.RequestSHA256, strconv.FormatUint(r.Revision, 10), r.ContentSHA256, r.CommittedAt.UTC().Format(time.RFC3339Nano))
	case 3:
		_, err = tx.Exec("INSERT INTO operation_receipts(operation_id,request_sha256,committed_revision,content_sha256,committed_at,operator_provenance) VALUES(?,?,?,?,?,?)", r.OperationID, r.RequestSHA256, strconv.FormatUint(r.Revision, 10), r.ContentSHA256, r.CommittedAt.UTC().Format(time.RFC3339Nano), provenance)
	case 4:
		var request any
		if r.rrsetRequest != "" {
			request = []byte(r.rrsetRequest)
		}
		_, err = tx.Exec("INSERT INTO operation_receipts(operation_id,request_sha256,committed_revision,content_sha256,committed_at,operator_provenance,rrset_request) VALUES(?,?,?,?,?,?,?)", r.OperationID, r.RequestSHA256, strconv.FormatUint(r.Revision, 10), r.ContentSHA256, r.CommittedAt.UTC().Format(time.RFC3339Nano), provenance, request)
	}
	if err != nil {
		return err
	}
	if s.hooks.beforeCommit != nil {
		if err = s.hooks.beforeCommit(tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}
