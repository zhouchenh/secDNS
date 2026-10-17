package snapshotauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
)

func TestVerifyValidCopiesAndConcurrentUse(t *testing.T) {
	fixture := newFixture(t)
	// Constructor ownership must not depend on caller-held key buffers or slices.
	fixture.config.Trust.Keys[0].PublicKey[0] ^= 0xff
	fixture.config.Trust.Keys = nil

	verified, err := fixture.verifier.Verify(fixture.compact, Clock{Now: fixture.now, Status: ClockTrusted})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Enrollment() != fixtureEnrollment() || verified.Metadata().Revision != math.MaxUint64 || verified.KeyID() != "key-primary" || verified.TrustGeneration() != 7 {
		t.Fatal("verified metadata mismatch")
	}
	if verified.VerifiedAt() != fixture.now || verified.IssuedAt() != fixture.now.Add(-time.Minute) || verified.ExpiresAt() != fixture.now.Add(time.Hour) {
		t.Fatal("verified time mismatch")
	}
	if !bytes.Equal(verified.EnvelopeJSON(), fixture.snapshot) {
		t.Fatal("canonical envelope mismatch")
	}
	first := verified.EnvelopeJSON()
	first[0] ^= 0xff
	if bytes.Equal(first, verified.EnvelopeJSON()) || !bytes.Equal(verified.EnvelopeJSON(), fixture.snapshot) {
		t.Fatal("returned envelope aliases verifier state")
	}

	var wait sync.WaitGroup
	errors := make(chan error, 32)
	for worker := 0; worker < 32; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for attempt := 0; attempt < 50; attempt++ {
				result, verifyErr := fixture.verifier.Verify(fixture.compact, Clock{Now: fixture.now, Status: ClockTrusted})
				if verifyErr != nil || !bytes.Equal(result.EnvelopeJSON(), fixture.snapshot) {
					if verifyErr == nil {
						verifyErr = ErrSnapshot
					}
					errors <- verifyErr
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errors)
	for verifyErr := range errors {
		t.Fatal(verifyErr)
	}
}

func TestNewVerifierRejectsInvalidTrust(t *testing.T) {
	fixture := newFixture(t)
	secondPrivate := testPrivate("secondary")
	secondKey := TrustedKey{
		KeyID: "key-secondary", PublicKey: append(ed25519.PublicKey(nil), secondPrivate.Public().(ed25519.PublicKey)...),
		NotBefore: fixture.config.Trust.NotBefore, NotAfter: fixture.config.Trust.NotAfter,
	}
	nonUTC := time.FixedZone("non-utc", 3600)
	cases := []struct {
		name string
		edit func(*Config)
		want error
	}{
		{"invalid-expected", func(c *Config) { c.ExpectedEnrollment.ClusterID = "bad/id" }, ErrEnrollment},
		{"trust-mismatch", func(c *Config) { c.Trust.Enrollment.AuthorityEpoch = "other" }, ErrEnrollment},
		{"zero-generation", func(c *Config) { c.Trust.Generation = 0 }, ErrTrust},
		{"empty-keys", func(c *Config) { c.Trust.Keys = nil }, ErrTrust},
		{"too-many-keys", func(c *Config) {
			c.Trust.Keys = append(c.Trust.Keys, secondKey, TrustedKey{KeyID: "third", PublicKey: testPrivate("third").Public().(ed25519.PublicKey), NotBefore: c.Trust.NotBefore, NotAfter: c.Trust.NotAfter})
		}, ErrTrust},
		{"duplicate-id", func(c *Config) {
			k := secondKey
			k.KeyID = c.Trust.Keys[0].KeyID
			c.Trust.Keys = append(c.Trust.Keys, k)
		}, ErrTrust},
		{"duplicate-public-key", func(c *Config) { k := c.Trust.Keys[0]; k.KeyID = "different"; c.Trust.Keys = append(c.Trust.Keys, k) }, ErrTrust},
		{"invalid-key-id", func(c *Config) { c.Trust.Keys[0].KeyID = "bad/id" }, ErrTrust},
		{"wrong-key-length", func(c *Config) { c.Trust.Keys[0].PublicKey = c.Trust.Keys[0].PublicKey[:31] }, ErrTrust},
		{"trust-reversed", func(c *Config) { c.Trust.NotAfter = c.Trust.NotBefore }, ErrTime},
		{"trust-fractional", func(c *Config) { c.Trust.NotBefore = c.Trust.NotBefore.Add(time.Nanosecond) }, ErrTime},
		{"trust-not-utc", func(c *Config) { c.Trust.NotBefore = c.Trust.NotBefore.In(nonUTC) }, ErrTime},
		{"trust-over-policy", func(c *Config) { c.Trust.NotAfter = c.Trust.NotAfter.Add(time.Second) }, ErrTime},
		{"trust-duration-overflow", func(c *Config) {
			c.Trust.NotBefore = time.Date(1, 1, 2, 0, 0, 0, 0, time.UTC)
			c.Trust.NotAfter = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
			c.TimePolicy.MaxTrustValidity = time.Duration(math.MaxInt64)
		}, ErrTime},
		{"key-reversed", func(c *Config) { c.Trust.Keys[0].NotAfter = c.Trust.Keys[0].NotBefore }, ErrTime},
		{"key-fractional", func(c *Config) { c.Trust.Keys[0].NotAfter = c.Trust.Keys[0].NotAfter.Add(time.Nanosecond) }, ErrTime},
		{"zero-trust-policy", func(c *Config) { c.TimePolicy.MaxTrustValidity = 0 }, ErrTime},
		{"zero-attestation-policy", func(c *Config) { c.TimePolicy.MaxAttestationLifetime = 0 }, ErrTime},
		{"negative-skew", func(c *Config) { c.TimePolicy.FutureIssuanceSkew = -time.Second }, ErrTime},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			config := cloneConfig(fixture.config)
			test.edit(&config)
			if verifier, err := NewVerifier(config); err != test.want || verifier != nil {
				t.Fatalf("verifier=%v error=%v want=%v", verifier, err, test.want)
			}
		})
	}
}

func TestCompactFramingIsCanonicalAndBounded(t *testing.T) {
	fixture := newFixture(t)
	parts := bytes.Split(fixture.compact, []byte("."))
	if len(parts) != 3 {
		t.Fatal("fixture framing")
	}
	signature, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil {
		t.Fatal(err)
	}
	noncanonical := append([]byte(nil), fixture.compact...)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := bytes.LastIndexByte(noncanonical, '.') + 1 + len(parts[2]) - 1
	index := strings.IndexByte(alphabet, noncanonical[last])
	if index < 0 || index%16 != 0 {
		t.Fatalf("unexpected canonical signature tail %q", noncanonical[last])
	}
	noncanonical[last] = alphabet[index+1]
	invalidAlphabet := append([]byte(nil), fixture.compact...)
	invalidAlphabet[0] = '+'
	emptySignature := append(bytes.Join(parts[:2], []byte(".")), '.')

	cases := []struct {
		name    string
		compact []byte
		want    error
	}{
		{"empty", nil, ErrMalformed},
		{"one-segment", []byte("abc"), ErrMalformed},
		{"empty-header", append([]byte("."), fixture.compact...), ErrMalformed},
		{"empty-payload", []byte("e30..e30"), ErrMalformed},
		{"empty-signature", emptySignature, ErrMalformed},
		{"extra-segment", append(append([]byte(nil), fixture.compact...), []byte(".extra")...), ErrMalformed},
		{"wrapper-space", append([]byte(" "), fixture.compact...), ErrMalformed},
		{"padding", replaceOnce(t, fixture.compact, parts[0], append(append([]byte(nil), parts[0]...), '=')), ErrMalformed},
		{"standard-base64-character", invalidAlphabet, ErrMalformed},
		{"nonzero-unused-bits", noncanonical, ErrMalformed},
		{"short-signature", compactWithSignature(fixture.header, marshalPayload(t, fixture.payload), signature[:63]), ErrMalformed},
		{"oversized-header", compactWithSignature(bytes.Repeat([]byte("a"), MaxHeaderBytes+1), []byte("x"), make([]byte, 64)), ErrLimit},
		{"oversized-payload", compactWithSignature([]byte("{}"), bytes.Repeat([]byte("x"), MaxPayloadBytes+1), make([]byte, 64)), ErrLimit},
		{"oversized-compact", bytes.Repeat([]byte("a"), MaxCompactBytes+1), ErrLimit},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			requireError(t, fixture.verifier, test.compact, Clock{Now: fixture.now, Status: ClockTrusted}, test.want)
		})
	}
}

func TestEmbeddedSnapshotLimitsPropagate(t *testing.T) {
	fixture := newFixture(t)
	validPayload := marshalPayload(t, fixture.payload)
	clock := Clock{Now: fixture.now, Status: ClockTrusted}

	tooLargeSnapshot := append([]byte{'['}, bytes.Repeat([]byte{' '}, recordset.MaxBytes-1)...)
	tooLargeSnapshot = append(tooLargeSnapshot, ']')
	if len(tooLargeSnapshot) != recordset.MaxBytes+1 {
		t.Fatal("oversized snapshot fixture length")
	}
	tooLargePayload := replaceOnce(t, validPayload, fixture.snapshot, tooLargeSnapshot)
	requireError(t, fixture.verifier, signPayload(t, fixture.private, fixture.header, tooLargePayload), clock, ErrLimit)

	records := bytes.Repeat([]byte(`{},`), recordset.MaxRecords)
	records = append(records, []byte(`{}`)...)
	tooManyRecords := []byte(`{"schema":"secdns.exact-record-set.v1","ruleset_id":"rules-test","lineage_id":"lineage-test","revision":"1","content_sha256":"` + strings.Repeat("0", 64) + `","records":[` + string(records) + `]}`)
	if len(tooManyRecords) > recordset.MaxBytes {
		t.Fatal("record-count fixture unexpectedly exceeds byte limit")
	}
	recordLimitPayload := replaceOnce(t, validPayload, fixture.snapshot, tooManyRecords)
	requireError(t, fixture.verifier, signPayload(t, fixture.private, fixture.header, recordLimitPayload), clock, ErrLimit)
}

func TestHeaderProfileAndAlgorithmConfusion(t *testing.T) {
	fixture := newFixture(t)
	payload := marshalPayload(t, fixture.payload)
	cases := []struct {
		name   string
		header []byte
		want   error
	}{
		{"none", []byte(`{"alg":"none","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary"}`), ErrProfile},
		{"hs256", []byte(`{"alg":"HS256","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary"}`), ErrProfile},
		{"eddsa", []byte(`{"alg":"EdDSA","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary"}`), ErrProfile},
		{"ed448", []byte(`{"alg":"Ed448","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary"}`), ErrProfile},
		{"wrong-type", []byte(`{"alg":"Ed25519","typ":"JWT","kid":"key-primary"}`), ErrProfile},
		{"embedded-jwk", []byte(`{"alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary","jwk":{}}`), ErrProfile},
		{"duplicate", []byte(`{"alg":"Ed25519","alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary"}`), ErrProfile},
		{"escape-equivalent-duplicate", []byte(`{"alg":"Ed25519","\u0061lg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary"}`), ErrProfile},
		{"case-variant", []byte(`{"Alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary"}`), ErrProfile},
		{"null-key", []byte(`{"alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":null}`), ErrProfile},
		{"invalid-key-id", []byte(`{"alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"remote/key"}`), ErrProfile},
		{"array-root", []byte(`[]`), ErrMalformed},
		{"trailing-value", []byte(`{"alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary"}{}`), ErrMalformed},
		{"invalid-surrogate", []byte(`{"alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"\ud800"}`), ErrMalformed},
		{"invalid-utf8", append([]byte(`{"alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"`), 0xff, '"', '}'), ErrMalformed},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			requireError(t, fixture.verifier, signPayload(t, fixture.private, test.header, payload), Clock{Now: fixture.now, Status: ClockTrusted}, test.want)
		})
	}
}

func TestSignatureAndPinnedKeySelection(t *testing.T) {
	fixture := newFixture(t)
	clock := Clock{Now: fixture.now, Status: ClockTrusted}
	tampered := append([]byte(nil), fixture.compact...)
	firstDot := bytes.IndexByte(tampered, '.')
	tampered[firstDot+1] = map[byte]byte{'e': 'f'}[tampered[firstDot+1]]
	if tampered[firstDot+1] == 0 {
		tampered[firstDot+1] = 'A'
	}
	requireError(t, fixture.verifier, tampered, clock, ErrSignature)

	otherPrivate := testPrivate("wrong-signature")
	requireError(t, fixture.verifier, signPayload(t, otherPrivate, fixture.header, marshalPayload(t, fixture.payload)), clock, ErrSignature)

	unknownHeader := []byte(`{"alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"unknown-key"}`)
	requireError(t, fixture.verifier, signPayload(t, fixture.private, unknownHeader, marshalPayload(t, fixture.payload)), clock, ErrTrust)

	config := cloneConfig(fixture.config)
	config.Trust.Keys[0].NotBefore = fixture.now.Add(time.Second)
	verifier, err := NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, verifier, fixture.compact, clock, ErrTime)

	config = cloneConfig(fixture.config)
	otherPublic := append(ed25519.PublicKey(nil), otherPrivate.Public().(ed25519.PublicKey)...)
	config.Trust.Keys[0].PublicKey = otherPublic
	verifier, err = NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, verifier, fixture.compact, clock, ErrSignature)
}

func TestPayloadBindingAndStrictJSON(t *testing.T) {
	fixture := newFixture(t)
	clock := Clock{Now: fixture.now, Status: ClockTrusted}
	validPayload := marshalPayload(t, fixture.payload)
	validSnapshot := fixture.snapshot
	differentRuleset := snapshotBytes(t, "other-rules", fixture.payload.LineageID, math.MaxUint64, fixtureRecords("192.0.2.10"))
	differentLineage := snapshotBytes(t, fixture.payload.RulesetID, "other-lineage", math.MaxUint64, fixtureRecords("192.0.2.10"))

	tests := []struct {
		name    string
		payload []byte
		want    error
	}{
		{"unknown-field", append(append([]byte(nil), validPayload[:len(validPayload)-1]...), []byte(`,"extra":"x"}`)...), ErrProfile},
		{"duplicate-field", append(append([]byte(nil), validPayload[:len(validPayload)-1]...), []byte(`,"cluster_id":"cluster-test"}`)...), ErrProfile},
		{"escape-equivalent-duplicate", append(append([]byte(nil), validPayload[:len(validPayload)-1]...), []byte(`,"\u0063luster_id":"cluster-test"}`)...), ErrProfile},
		{"case-variant", append(append([]byte(nil), validPayload[:len(validPayload)-1]...), []byte(`,"Cluster_id":"cluster-test"}`)...), ErrProfile},
		{"null", replaceOnce(t, validPayload, []byte(`"cluster_id":"cluster-test"`), []byte(`"cluster_id":null`)), ErrProfile},
		{"trailing", append(append([]byte(nil), validPayload...), []byte(` {}`)...), ErrMalformed},
		{"array-root", []byte(`[]`), ErrMalformed},
		{"invalid-surrogate", replaceOnce(t, validPayload, []byte(`"cluster_id":"cluster-test"`), []byte(`"cluster_id":"\ud800"`)), ErrMalformed},
		{"invalid-utf8", replaceOnce(t, validPayload, []byte("cluster-test"), []byte{'c', 'l', 0xff}), ErrMalformed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireError(t, fixture.verifier, signPayload(t, fixture.private, fixture.header, test.payload), clock, test.want)
		})
	}

	semantic := []struct {
		name string
		edit func(*signedPayload)
		want error
	}{
		{"wrong-schema", func(p *signedPayload) { p.Schema = "other" }, ErrProfile},
		{"invalid-cluster", func(p *signedPayload) { p.ClusterID = "bad/id" }, ErrProfile},
		{"wrong-kind", func(p *signedPayload) { p.Kind = "other" }, ErrProfile},
		{"wrong-cluster", func(p *signedPayload) { p.ClusterID = "other" }, ErrEnrollment},
		{"wrong-ruleset", func(p *signedPayload) { p.RulesetID = "other" }, ErrEnrollment},
		{"wrong-lineage", func(p *signedPayload) { p.LineageID = "other" }, ErrEnrollment},
		{"wrong-epoch", func(p *signedPayload) { p.AuthorityEpoch = "other" }, ErrEnrollment},
		{"lower-trust-generation", func(p *signedPayload) { p.TrustGeneration = "6" }, ErrTrust},
		{"higher-trust-generation", func(p *signedPayload) { p.TrustGeneration = "8" }, ErrTrust},
		{"noncanonical-trust-generation", func(p *signedPayload) { p.TrustGeneration = "07" }, ErrProfile},
		{"zero-revision", func(p *signedPayload) { p.Revision = "0" }, ErrProfile},
		{"noncanonical-revision", func(p *signedPayload) { p.Revision = "01" }, ErrProfile},
		{"outer-revision-mismatch", func(p *signedPayload) { p.Revision = "1" }, ErrSnapshot},
		{"uppercase-digest", func(p *signedPayload) { p.ContentSHA256 = strings.ToUpper(p.ContentSHA256) }, ErrProfile},
		{"outer-digest-mismatch", func(p *signedPayload) { p.ContentSHA256 = strings.Repeat("0", 64) }, ErrSnapshot},
		{"inner-ruleset-mismatch", func(p *signedPayload) { p.Snapshot = differentRuleset }, ErrSnapshot},
		{"inner-lineage-mismatch", func(p *signedPayload) { p.Snapshot = differentLineage }, ErrSnapshot},
		{"snapshot-null", func(p *signedPayload) { p.Snapshot = json.RawMessage("null") }, ErrProfile},
	}
	for _, test := range semantic {
		t.Run(test.name, func(t *testing.T) {
			payload := fixture.payload
			payload.Snapshot = append(json.RawMessage(nil), fixture.payload.Snapshot...)
			test.edit(&payload)
			requireError(t, fixture.verifier, signPayload(t, fixture.private, fixture.header, marshalPayload(t, payload)), clock, test.want)
		})
	}

	noncanonicalSnapshot := append([]byte("{ "), validSnapshot[1:]...)
	noncanonicalPayload := replaceOnce(t, validPayload, validSnapshot, noncanonicalSnapshot)
	requireError(t, fixture.verifier, signPayload(t, fixture.private, fixture.header, noncanonicalPayload), clock, ErrSnapshot)

	duplicateSnapshot := append(append([]byte(nil), validSnapshot[:len(validSnapshot)-1]...), []byte(`,"schema":"secdns.exact-record-set.v1"}`)...)
	duplicatePayload := replaceOnce(t, validPayload, validSnapshot, duplicateSnapshot)
	requireError(t, fixture.verifier, signPayload(t, fixture.private, fixture.header, duplicatePayload), clock, ErrSnapshot)

	var reordered map[string]json.RawMessage
	if err := json.Unmarshal(validPayload, &reordered); err != nil {
		t.Fatal(err)
	}
	reorderedPayload, err := json.Marshal(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reorderedPayload, validPayload) {
		t.Fatal("outer payload was not reordered")
	}
	if _, err = fixture.verifier.Verify(signPayload(t, fixture.private, fixture.header, reorderedPayload), clock); err != nil {
		t.Fatal("valid reordered outer fields rejected", err)
	}
}

func TestTimePolicyAndContainment(t *testing.T) {
	fixture := newFixture(t)
	baseClock := Clock{Now: fixture.now, Status: ClockTrusted}
	verifyPayload := func(t *testing.T, verifier *Verifier, payload signedPayload, clock Clock, want error) {
		t.Helper()
		requireError(t, verifier, signPayload(t, fixture.private, fixture.header, marshalPayload(t, payload)), clock, want)
	}

	unknown := baseClock
	unknown.Status = ClockUnknown
	requireError(t, fixture.verifier, fixture.compact, unknown, ErrTime)
	invalidStatus := baseClock
	invalidStatus.Status = ClockStatus(2)
	requireError(t, fixture.verifier, fixture.compact, invalidStatus, ErrTime)
	nonUTC := baseClock
	nonUTC.Now = fixture.now.In(time.FixedZone("offset", 3600))
	requireError(t, fixture.verifier, fixture.compact, nonUTC, ErrTime)
	stale := baseClock
	stale.Now = fixture.config.Trust.NotAfter
	requireError(t, fixture.verifier, fixture.compact, stale, ErrTime)

	cases := []struct {
		name string
		edit func(*signedPayload)
		want error
	}{
		{"now-at-expiry", func(p *signedPayload) { p.ExpiresAt = fixture.now.Format("2006-01-02T15:04:05Z") }, ErrTime},
		{"future-skew-plus-one", func(p *signedPayload) {
			p.IssuedAt = fixture.now.Add(31 * time.Second).Format("2006-01-02T15:04:05Z")
			p.ExpiresAt = fixture.now.Add(time.Hour).Format("2006-01-02T15:04:05Z")
		}, ErrTime},
		{"zero-lifetime", func(p *signedPayload) { p.IssuedAt = p.ExpiresAt }, ErrTime},
		{"over-max-lifetime", func(p *signedPayload) {
			p.IssuedAt = fixture.config.Trust.NotBefore.Format("2006-01-02T15:04:05Z")
			p.ExpiresAt = fixture.config.Trust.NotAfter.Add(time.Second).Format("2006-01-02T15:04:05Z")
		}, ErrTime},
		{"before-trust", func(p *signedPayload) {
			p.IssuedAt = fixture.config.Trust.NotBefore.Add(-time.Second).Format("2006-01-02T15:04:05Z")
		}, ErrTime},
		{"after-trust", func(p *signedPayload) {
			p.ExpiresAt = fixture.config.Trust.NotAfter.Add(time.Second).Format("2006-01-02T15:04:05Z")
		}, ErrTime},
		{"fractional-issued", func(p *signedPayload) { p.IssuedAt = "2026-10-18T11:59:00.0Z" }, ErrTime},
		{"offset-expiry", func(p *signedPayload) { p.ExpiresAt = "2026-10-18T13:00:00+00:00" }, ErrTime},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			payload := fixture.payload
			test.edit(&payload)
			verifyPayload(t, fixture.verifier, payload, baseClock, test.want)
		})
	}

	boundary := fixture.payload
	boundary.IssuedAt = fixture.now.Add(30 * time.Second).Format("2006-01-02T15:04:05Z")
	boundary.ExpiresAt = fixture.config.Trust.NotAfter.Format("2006-01-02T15:04:05Z")
	if _, err := fixture.verifier.Verify(signPayload(t, fixture.private, fixture.header, marshalPayload(t, boundary)), baseClock); err != nil {
		t.Fatal("inclusive skew or half-open containment boundary rejected", err)
	}

	config := cloneConfig(fixture.config)
	config.Trust.Keys[0].NotBefore = fixture.now.Add(-30 * time.Minute)
	config.Trust.Keys[0].NotAfter = fixture.now.Add(30 * time.Minute)
	verifier, err := NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	payload := fixture.payload
	payload.IssuedAt = fixture.now.Add(-31 * time.Minute).Format("2006-01-02T15:04:05Z")
	payload.ExpiresAt = fixture.now.Add(20 * time.Minute).Format("2006-01-02T15:04:05Z")
	verifyPayload(t, verifier, payload, baseClock, ErrTime)
	payload.IssuedAt = fixture.now.Add(-20 * time.Minute).Format("2006-01-02T15:04:05Z")
	payload.ExpiresAt = fixture.now.Add(31 * time.Minute).Format("2006-01-02T15:04:05Z")
	verifyPayload(t, verifier, payload, baseClock, ErrTime)
}

func TestIndependentTrustSnapshotsDoNotLeakAuthorization(t *testing.T) {
	fixture := newFixture(t)
	otherPrivate := testPrivate("isolated")
	config := cloneConfig(fixture.config)
	config.Trust.Keys[0].PublicKey = append(ed25519.PublicKey(nil), otherPrivate.Public().(ed25519.PublicKey)...)
	otherVerifier, err := NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	otherCompact := signPayload(t, otherPrivate, fixture.header, marshalPayload(t, fixture.payload))
	clock := Clock{Now: fixture.now, Status: ClockTrusted}
	if _, err = otherVerifier.Verify(otherCompact, clock); err != nil {
		t.Fatal(err)
	}
	requireError(t, otherVerifier, fixture.compact, clock, ErrSignature)
	requireError(t, fixture.verifier, otherCompact, clock, ErrSignature)
}

func TestVerifiedResultIsNotAContinuingAuthorization(t *testing.T) {
	fixture := newFixture(t)
	verified, err := fixture.verifier.Verify(fixture.compact, Clock{Now: fixture.now, Status: ClockTrusted})
	if err != nil {
		t.Fatal(err)
	}

	// A copied result remains ordinary data. It is not invalidated in place and
	// cannot substitute for a fresh Verify at a future apply boundary.
	if len(verified.EnvelopeJSON()) == 0 {
		t.Fatal("verified fixture did not return an envelope")
	}
	requireError(t, fixture.verifier, fixture.compact, Clock{Now: verified.ExpiresAt(), Status: ClockTrusted}, ErrTime)

	replacement := cloneConfig(fixture.config)
	replacement.Trust.Keys[0].KeyID = "replacement-key"
	replacement.Trust.Keys[0].PublicKey = append(ed25519.PublicKey(nil), testPrivate("replacement").Public().(ed25519.PublicKey)...)
	revokedVerifier, err := NewVerifier(replacement)
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, revokedVerifier, fixture.compact, Clock{Now: fixture.now, Status: ClockTrusted}, ErrTrust)
}

func TestNilVerifierRejects(t *testing.T) {
	var verifier *Verifier
	requireError(t, verifier, []byte("a.b.c"), Clock{Now: time.Now().UTC(), Status: ClockTrusted}, ErrTrust)
}

func FuzzVerifyNeverPanics(f *testing.F) {
	fixture := newFixture(f)
	f.Add(fixture.compact)
	f.Add([]byte("a.b.c"))
	f.Add([]byte{})
	clock := Clock{Now: fixture.now, Status: ClockTrusted}
	f.Fuzz(func(t *testing.T, compact []byte) {
		verified, err := fixture.verifier.Verify(compact, clock)
		if err == nil {
			if !bytes.Equal(verified.EnvelopeJSON(), fixture.snapshot) {
				t.Fatal("unexpected successful payload")
			}
		} else if verified.EnvelopeJSON() != nil {
			t.Fatal("failed verification returned payload")
		}
	})
}
