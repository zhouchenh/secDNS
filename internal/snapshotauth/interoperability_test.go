package snapshotauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

const (
	nodeVectorsSHA256    = "0426518d090e07d46fa9b897118510142a16b15e253b3e5abf38cce1656ab966"
	nodeGeneratorSHA256  = "abd8fe10ceb7d21b9f1a8a843e0006f172243396775ac05ca467e751db12e6aa"
	nodeProvenanceSHA256 = "616b90782d7f2251b6733b44f2fd4761879adb0fa3af6737f1377f7b9fee95dd"
	nodeOracleSHA256     = "61e974c2e75bc4fde8ce011640ef3794d1f32546b7202b8081aa35ff8603e928"
	nodeVerificationSHA  = "d09f5b9a6cd7ec4abdefae740ff2a1a6741ec1d2ba3ff7bf959329ec20fba6ed"
	nodeCanonicalSHA256  = "870722abb68881f53b5b53d974cee29a36a7ecddbea27573ca0b64c77d08d533"
)

type nodeEnrollment struct {
	ClusterID      string `json:"cluster_id"`
	Kind           string `json:"kind"`
	RulesetID      string `json:"ruleset_id"`
	LineageID      string `json:"lineage_id"`
	AuthorityEpoch string `json:"authority_epoch"`
}

func (e nodeEnrollment) production() recordstore.FollowerEnrollment {
	return recordstore.FollowerEnrollment{
		ClusterID: e.ClusterID, Kind: e.Kind, RulesetID: e.RulesetID,
		LineageID: e.LineageID, AuthorityEpoch: e.AuthorityEpoch,
	}
}

type nodeKey struct {
	KeyID        string `json:"kid"`
	PublicKeyHex string `json:"public_key_hex"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
}

type nodeTrust struct {
	Enrollment nodeEnrollment `json:"enrollment"`
	Generation string         `json:"generation"`
	NotBefore  string         `json:"not_before"`
	NotAfter   string         `json:"not_after"`
	Keys       []nodeKey      `json:"keys"`
}

type nodeClock struct {
	Status string `json:"status"`
	Now    string `json:"now"`
}

type nodePolicy struct {
	MaxTrustWindowSeconds      int64 `json:"max_trust_window_seconds"`
	MaxAttestationLifetimeSecs int64 `json:"max_attestation_lifetime_seconds"`
	AllowedFutureSkewSeconds   int64 `json:"allowed_future_skew_seconds"`
}

type nodeContext struct {
	ExpectedEnrollment nodeEnrollment `json:"expected_enrollment"`
	Trust              nodeTrust      `json:"trust"`
	Clock              nodeClock      `json:"clock"`
	Policy             nodePolicy     `json:"policy"`
}

type nodeContextOverride struct {
	Trust *nodeTrust `json:"trust"`
	Clock *nodeClock `json:"clock"`
}

type nodeVector struct {
	ID                    string               `json:"id"`
	Expect                string               `json:"expect"`
	Reason                string               `json:"reason"`
	HeaderBytesBase64     string               `json:"header_bytes_base64"`
	PayloadBytesBase64    string               `json:"payload_bytes_base64"`
	SigningInputASCII     string               `json:"signing_input_ascii"`
	SignatureHex          string               `json:"signature_hex"`
	Compact               string               `json:"compact"`
	NodeRawSignatureValid bool                 `json:"node_raw_signature_valid"`
	CompactSHA256         string               `json:"compact_sha256"`
	Context               *nodeContextOverride `json:"context"`
}

type nodeCorpus struct {
	Format        string       `json:"format"`
	KeyProvenance string       `json:"key_provenance"`
	PublicKeyHex  string       `json:"public_key_hex"`
	Context       nodeContext  `json:"context"`
	Vectors       []nodeVector `json:"vectors"`
}

func TestIndependentNodeInteroperabilityCorpus(t *testing.T) {
	directory := filepath.Join("testdata", "node")
	assertFileSHA256(t, filepath.Join(directory, "vectors.json"), nodeVectorsSHA256)
	assertFileSHA256(t, filepath.Join(directory, "generate.cjs"), nodeGeneratorSHA256)
	assertFileSHA256(t, filepath.Join(directory, "provenance.json"), nodeProvenanceSHA256)
	assertFileSHA256(t, filepath.Join(directory, "ORACLE.md"), nodeOracleSHA256)
	assertFileSHA256(t, filepath.Join(directory, "verification.json"), nodeVerificationSHA)
	assertFileSHA256(t, filepath.Join(directory, "canonical-snapshot.json"), nodeCanonicalSHA256)

	raw := readTestFile(t, filepath.Join(directory, "vectors.json"))
	var corpus nodeCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Format == "" || corpus.KeyProvenance != "PUBLIC RFC8032 section7.1 test1; never deploy published seed" {
		t.Fatal("missing independent fixture provenance")
	}
	publicKey := decodeHex(t, corpus.PublicKeyHex)
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d", len(publicKey))
	}
	if len(corpus.Vectors) != 64 {
		t.Fatalf("vector count = %d", len(corpus.Vectors))
	}

	canonical := readTestFile(t, filepath.Join(directory, "canonical-snapshot.json"))
	snapshot, err := recordset.Parse(canonical)
	if err != nil {
		t.Fatal("independent canonical snapshot does not parse", err)
	}
	remarshaled, err := snapshot.MarshalJSON()
	if err != nil || !bytes.Equal(remarshaled, canonical) {
		t.Fatal("independent snapshot is not byte-canonical", err)
	}

	seen := make(map[string]struct{}, len(corpus.Vectors))
	accepts := 0
	for _, vector := range corpus.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			if vector.ID == "" || vector.Reason == "" {
				t.Fatal("vector identity or rationale is empty")
			}
			if _, duplicate := seen[vector.ID]; duplicate {
				t.Fatal("duplicate vector ID")
			}
			seen[vector.ID] = struct{}{}
			if vector.Expect != "accept" && vector.Expect != "reject" {
				t.Fatalf("unknown expectation %q", vector.Expect)
			}
			if vector.Expect == "accept" {
				accepts++
			}

			compactSum := sha256.Sum256([]byte(vector.Compact))
			if hex.EncodeToString(compactSum[:]) != vector.CompactSHA256 {
				t.Fatal("compact fixture hash mismatch")
			}
			signature := decodeHex(t, vector.SignatureHex)
			goSignatureValid := ed25519.Verify(ed25519.PublicKey(publicKey), []byte(vector.SigningInputASCII), signature)
			// The malformed-wire fixtures intentionally retain diagnostic fields
			// from their valid source even when Compact has been changed. Every
			// Node-valid mathematical signature must independently verify in Go;
			// every accepted fixture must be valid in both implementations.
			if vector.NodeRawSignatureValid && !goSignatureValid || vector.Expect == "accept" && (!vector.NodeRawSignatureValid || !goSignatureValid) {
				t.Fatalf("independent raw signature mismatch: Go=%v Node=%v", goSignatureValid, vector.NodeRawSignatureValid)
			}

			context := corpus.Context
			if vector.Context != nil {
				if vector.Context.Trust != nil {
					context.Trust = *vector.Context.Trust
				}
				if vector.Context.Clock != nil {
					context.Clock = *vector.Context.Clock
				}
			}
			config := nodeConfig(t, context)
			verifier, constructorErr := NewVerifier(config)
			if constructorErr != nil {
				if vector.Expect == "accept" {
					t.Fatal("accepted vector trust construction failed", constructorErr)
				}
				return
			}
			clock := nodeVerificationClock(t, context.Clock)
			verified, verifyErr := verifier.Verify([]byte(vector.Compact), clock)
			if vector.Expect == "reject" {
				if verifyErr == nil {
					t.Fatal("rejected vector verified")
				}
				assertZeroVerifiedGeneration(t, verified)
				return
			}
			if verifyErr != nil {
				t.Fatal("accepted vector rejected", verifyErr)
			}
			payloadRaw := decodeStandardBase64(t, vector.PayloadBytesBase64)
			fields, parseErr := strictObject(payloadRaw, payloadFields)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if !bytes.Equal(verified.EnvelopeJSON(), fields["snapshot"]) {
				t.Fatal("verified output does not preserve exact embedded canonical snapshot")
			}
			if verified.Enrollment() != context.ExpectedEnrollment.production() || verified.TrustGeneration() != config.Trust.Generation {
				t.Fatal("verified binding mismatch")
			}
		})
	}
	if accepts != 8 {
		t.Fatalf("accept count = %d", accepts)
	}

	assertNamedFixtureCoherence(t, directory, corpus.Vectors[0], canonical)
}

func nodeConfig(t testing.TB, context nodeContext) Config {
	t.Helper()
	parseTime := func(value string) time.Time {
		t.Helper()
		parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	generation, err := strconv.ParseUint(context.Trust.Generation, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != context.Trust.Generation {
		t.Fatalf("invalid fixture trust generation %q", context.Trust.Generation)
	}
	keys := make([]TrustedKey, 0, len(context.Trust.Keys))
	for _, key := range context.Trust.Keys {
		keys = append(keys, TrustedKey{
			KeyID: key.KeyID, PublicKey: ed25519.PublicKey(decodeHex(t, key.PublicKeyHex)),
			NotBefore: parseTime(key.NotBefore), NotAfter: parseTime(key.NotAfter),
		})
	}
	return Config{
		ExpectedEnrollment: context.ExpectedEnrollment.production(),
		Trust: TrustSnapshot{
			Enrollment: context.Trust.Enrollment.production(), Generation: generation,
			NotBefore: parseTime(context.Trust.NotBefore), NotAfter: parseTime(context.Trust.NotAfter), Keys: keys,
		},
		TimePolicy: TimePolicy{
			MaxTrustValidity:       time.Duration(context.Policy.MaxTrustWindowSeconds) * time.Second,
			MaxAttestationLifetime: time.Duration(context.Policy.MaxAttestationLifetimeSecs) * time.Second,
			FutureIssuanceSkew:     time.Duration(context.Policy.AllowedFutureSkewSeconds) * time.Second,
		},
	}
}

func nodeVerificationClock(t testing.TB, input nodeClock) Clock {
	t.Helper()
	now, err := time.Parse("2006-01-02T15:04:05Z", input.Now)
	if err != nil {
		t.Fatal(err)
	}
	status := ClockUnknown
	if input.Status == "trusted" {
		status = ClockTrusted
	} else if input.Status != "unknown" {
		t.Fatalf("unknown fixture clock status %q", input.Status)
	}
	return Clock{Now: now, Status: status}
}

func assertNamedFixtureCoherence(t testing.TB, directory string, vector nodeVector, canonical []byte) {
	t.Helper()
	if vector.ID != "valid-high-revision" {
		t.Fatalf("first vector = %q", vector.ID)
	}
	comparisons := []struct {
		name string
		got  []byte
	}{
		{"valid-high-revision.jws", []byte(vector.Compact)},
		{"valid-high-revision.header.json", decodeStandardBase64(t, vector.HeaderBytesBase64)},
		{"valid-high-revision.payload.json", decodeStandardBase64(t, vector.PayloadBytesBase64)},
		{"valid-high-revision.signing-input.txt", []byte(vector.SigningInputASCII)},
	}
	for _, comparison := range comparisons {
		if want := readTestFile(t, filepath.Join(directory, comparison.name)); !bytes.Equal(comparison.got, want) {
			t.Fatalf("%s differs from vector corpus", comparison.name)
		}
	}
	parsedFields, err := strictObject(comparisons[2].got, payloadFields)
	if err != nil || !bytes.Equal(parsedFields["snapshot"], canonical) {
		t.Fatal("named payload does not embed named canonical snapshot", err)
	}
}

func assertZeroVerifiedGeneration(t testing.TB, value VerifiedGeneration) {
	t.Helper()
	if value.Enrollment() != (recordstore.FollowerEnrollment{}) || value.Metadata() != (recordset.Metadata{}) ||
		value.EnvelopeJSON() != nil || value.KeyID() != "" || value.TrustGeneration() != 0 ||
		!value.VerifiedAt().IsZero() || !value.IssuedAt().IsZero() || !value.ExpiresAt().IsZero() {
		t.Fatal("failure returned a partial verified result")
	}
}

func assertFileSHA256(t testing.TB, path, expected string) {
	t.Helper()
	raw := readTestFile(t, path)
	digest := sha256.Sum256(raw)
	if actual := hex.EncodeToString(digest[:]); actual != expected {
		t.Fatalf("%s SHA-256 = %s, want %s", path, actual, expected)
	}
}

func readTestFile(t testing.TB, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeHex(t testing.TB, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeStandardBase64(t testing.TB, value string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(fmt.Errorf("decode fixture base64: %w", err))
	}
	return raw
}
