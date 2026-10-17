package snapshotauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

var (
	headerFields  = []string{"alg", "typ", "kid"}
	payloadFields = []string{
		"schema", "cluster_id", "kind", "ruleset_id", "lineage_id", "authority_epoch",
		"trust_generation", "revision", "content_sha256", "issued_at", "expires_at", "snapshot",
	}
)

// Verify authenticates one Compact JWS under the verifier's captured trust and
// the caller's explicit clock. It does not retain or apply the generation.
func (v *Verifier) Verify(compact []byte, clock Clock) (VerifiedGeneration, error) {
	fail := VerifiedGeneration{}
	if v == nil {
		return fail, ErrTrust
	}
	headerRaw, payloadRaw, signature, signingInput, err := compactParts(compact)
	if err != nil {
		return fail, err
	}
	header, parseErr := strictObject(headerRaw, headerFields)
	if parseErr != nil {
		return fail, classifyJSON(parseErr)
	}
	algorithm, ok := jsonString(header["alg"])
	if !ok || algorithm != Algorithm {
		return fail, ErrProfile
	}
	typeName, ok := jsonString(header["typ"])
	if !ok || typeName != ProtectedType {
		return fail, ErrProfile
	}
	keyID, ok := jsonString(header["kid"])
	if !ok || !validID(keyID) {
		return fail, ErrProfile
	}

	now, ok := trustedTime(clock.Now, false)
	if clock.Status != ClockTrusted || !ok {
		return fail, ErrTime
	}
	if now.Before(v.trustNotBefore) || !now.Before(v.trustNotAfter) {
		return fail, ErrTime
	}
	key, found := v.key(keyID)
	if !found {
		return fail, ErrTrust
	}
	if now.Before(key.notBefore) || !now.Before(key.notAfter) {
		return fail, ErrTime
	}
	if !ed25519.Verify(key.publicKey, signingInput, signature) {
		return fail, ErrSignature
	}

	payload, parseErr := strictObject(payloadRaw, payloadFields)
	if parseErr != nil {
		return fail, classifyJSON(parseErr)
	}
	schema, ok := jsonString(payload["schema"])
	if !ok || schema != Schema {
		return fail, ErrProfile
	}
	enrollment, ok := payloadEnrollment(payload)
	if !ok {
		return fail, ErrProfile
	}
	if enrollment != v.enrollment {
		return fail, ErrEnrollment
	}
	trustGeneration, ok := canonicalUint(payload["trust_generation"])
	if !ok {
		return fail, ErrProfile
	}
	if trustGeneration != v.trustGeneration {
		return fail, ErrTrust
	}
	revision, ok := canonicalUint(payload["revision"])
	if !ok {
		return fail, ErrProfile
	}
	digest, ok := jsonString(payload["content_sha256"])
	if !ok || !validDigest(digest) {
		return fail, ErrProfile
	}
	issuedText, okIssued := jsonString(payload["issued_at"])
	expiresText, okExpires := jsonString(payload["expires_at"])
	issuedAt, validIssued := canonicalTimestamp(issuedText)
	expiresAt, validExpires := canonicalTimestamp(expiresText)
	if !okIssued || !okExpires || !validIssued || !validExpires || !issuedAt.Before(expiresAt) {
		return fail, ErrTime
	}
	if !withinDuration(issuedAt, expiresAt, v.policy.MaxAttestationLifetime) || issuedAt.After(now.Add(v.policy.FutureIssuanceSkew)) || !now.Before(expiresAt) {
		return fail, ErrTime
	}
	if issuedAt.Before(v.trustNotBefore) || expiresAt.After(v.trustNotAfter) || issuedAt.Before(key.notBefore) || expiresAt.After(key.notAfter) {
		return fail, ErrTime
	}

	snapshotRaw := payload["snapshot"]
	if len(snapshotRaw) > recordset.MaxBytes {
		return fail, ErrLimit
	}
	snapshot, err := recordset.Parse(snapshotRaw)
	if err != nil {
		if errors.Is(err, recordset.ErrLimit) {
			return fail, ErrLimit
		}
		return fail, ErrSnapshot
	}
	canonical, err := snapshot.MarshalJSON()
	if err != nil || !bytes.Equal(snapshotRaw, canonical) {
		return fail, ErrSnapshot
	}
	metadata := snapshot.Metadata()
	if metadata.RulesetID != enrollment.RulesetID || metadata.LineageID != enrollment.LineageID || metadata.Revision != revision || metadata.ContentSHA256 != digest {
		return fail, ErrSnapshot
	}

	return VerifiedGeneration{
		enrollment: enrollment, metadata: metadata, envelope: append([]byte(nil), canonical...),
		keyID: keyID, trustGeneration: trustGeneration, verifiedAt: now,
		issuedAt: issuedAt, expiresAt: expiresAt,
	}, nil
}

func (v *Verifier) key(id string) (trustedKey, bool) {
	for _, key := range v.keys {
		if key.id == id {
			return key, true
		}
	}
	return trustedKey{}, false
}

func classifyJSON(err error) error {
	if err == errJSONProfile {
		return ErrProfile
	}
	return ErrMalformed
}

func jsonString(raw json.RawMessage) (string, bool) {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func canonicalUint(raw json.RawMessage) (uint64, bool) {
	text, ok := jsonString(raw)
	if !ok || len(text) == 0 || text[0] == '0' {
		return 0, false
	}
	value, err := strconv.ParseUint(text, 10, 64)
	return value, err == nil && value > 0 && strconv.FormatUint(value, 10) == text
}

func payloadEnrollment(fields map[string]json.RawMessage) (recordstore.FollowerEnrollment, bool) {
	values := make([]string, 5)
	for index, name := range []string{"cluster_id", "kind", "ruleset_id", "lineage_id", "authority_epoch"} {
		value, ok := jsonString(fields[name])
		if !ok || !validID(value) {
			return recordstore.FollowerEnrollment{}, false
		}
		values[index] = value
	}
	enrollment := recordstore.FollowerEnrollment{
		ClusterID: values[0], Kind: values[1], RulesetID: values[2], LineageID: values[3], AuthorityEpoch: values[4],
	}
	return enrollment, enrollment.Kind == recordstore.FollowerExactRecords
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return false
	}
	return hex.EncodeToString(decoded) == value
}

func canonicalTimestamp(value string) (time.Time, bool) {
	const layout = "2006-01-02T15:04:05Z"
	parsed, err := time.Parse(layout, value)
	if err != nil || parsed.IsZero() || parsed.Year() < 1 || parsed.Year() > 9999 || parsed.Format(layout) != value {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}
