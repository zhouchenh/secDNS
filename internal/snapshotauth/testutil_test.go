package snapshotauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

type signedPayload struct {
	Schema          string          `json:"schema"`
	ClusterID       string          `json:"cluster_id"`
	Kind            string          `json:"kind"`
	RulesetID       string          `json:"ruleset_id"`
	LineageID       string          `json:"lineage_id"`
	AuthorityEpoch  string          `json:"authority_epoch"`
	TrustGeneration string          `json:"trust_generation"`
	Revision        string          `json:"revision"`
	ContentSHA256   string          `json:"content_sha256"`
	IssuedAt        string          `json:"issued_at"`
	ExpiresAt       string          `json:"expires_at"`
	Snapshot        json.RawMessage `json:"snapshot"`
}

type fixture struct {
	config   Config
	verifier *Verifier
	private  ed25519.PrivateKey
	header   []byte
	payload  signedPayload
	compact  []byte
	snapshot []byte
	now      time.Time
}

func testPrivate(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("secdns snapshotauth synthetic test key: " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func fixtureEnrollment() recordstore.FollowerEnrollment {
	return recordstore.FollowerEnrollment{
		ClusterID: "cluster-test", Kind: recordstore.FollowerExactRecords,
		RulesetID: "rules-test", LineageID: "lineage-test", AuthorityEpoch: "epoch-test",
	}
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	start := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	now := start.Add(12 * time.Hour)
	private := testPrivate("primary")
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	enrollment := fixtureEnrollment()
	config := Config{
		ExpectedEnrollment: enrollment,
		Trust: TrustSnapshot{
			Enrollment: enrollment, Generation: 7, NotBefore: start, NotAfter: start.Add(24 * time.Hour),
			Keys: []TrustedKey{{KeyID: "key-primary", PublicKey: public, NotBefore: start, NotAfter: start.Add(24 * time.Hour)}},
		},
		TimePolicy: TimePolicy{MaxTrustValidity: 24 * time.Hour, MaxAttestationLifetime: 24 * time.Hour, FutureIssuanceSkew: 30 * time.Second},
	}
	verifier, err := NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := snapshotBytes(t, enrollment.RulesetID, enrollment.LineageID, math.MaxUint64, fixtureRecords("192.0.2.10"))
	payload := payloadFor(t, config, snapshot, now.Add(-time.Minute), now.Add(time.Hour))
	header := []byte(`{"alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-primary"}`)
	return fixture{
		config: config, verifier: verifier, private: private, header: header, payload: payload,
		compact: signPayload(t, private, header, marshalPayload(t, payload)), snapshot: snapshot, now: now,
	}
}

func fixtureRecords(address string) []recordset.Record {
	return []recordset.Record{
		{Name: "address.invalid.", Type: "A", Values: []string{address}, TTLSeconds: 0},
		{Name: "text.invalid.", Type: "TXT", Values: []string{"", "repeat", "repeat", "<>&", "😀"}, TTLSeconds: math.MaxUint32},
	}
}

func snapshotBytes(t testing.TB, ruleset, lineage string, revision uint64, records []recordset.Record) []byte {
	t.Helper()
	snapshot, err := recordset.New(ruleset, lineage, revision, records)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := snapshot.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func payloadFor(t testing.TB, config Config, snapshot []byte, issuedAt, expiresAt time.Time) signedPayload {
	t.Helper()
	parsed, err := recordset.Parse(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	metadata := parsed.Metadata()
	enrollment := config.ExpectedEnrollment
	return signedPayload{
		Schema: Schema, ClusterID: enrollment.ClusterID, Kind: enrollment.Kind,
		RulesetID: enrollment.RulesetID, LineageID: enrollment.LineageID, AuthorityEpoch: enrollment.AuthorityEpoch,
		TrustGeneration: strconv.FormatUint(config.Trust.Generation, 10), Revision: strconv.FormatUint(metadata.Revision, 10),
		ContentSHA256: metadata.ContentSHA256, IssuedAt: issuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		ExpiresAt: expiresAt.UTC().Format("2006-01-02T15:04:05Z"), Snapshot: append(json.RawMessage(nil), snapshot...),
	}
}

func marshalPayload(t testing.TB, payload signedPayload) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signPayload(t testing.TB, private ed25519.PrivateKey, header, payload []byte) []byte {
	t.Helper()
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := []byte(headerSegment + "." + payloadSegment)
	signature := ed25519.Sign(private, signingInput)
	return []byte(string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(signature))
}

func compactWithSignature(header, payload, signature []byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature))
}

func cloneConfig(input Config) Config {
	out := input
	out.Trust.Keys = make([]TrustedKey, len(input.Trust.Keys))
	for index, key := range input.Trust.Keys {
		out.Trust.Keys[index] = key
		out.Trust.Keys[index].PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
	}
	return out
}

func replaceOnce(t testing.TB, input, old, replacement []byte) []byte {
	t.Helper()
	if bytes.Count(input, old) != 1 {
		t.Fatalf("replacement source count = %d", bytes.Count(input, old))
	}
	return bytes.Replace(input, old, replacement, 1)
}

func requireError(t testing.TB, verifier *Verifier, compact []byte, clock Clock, want error) {
	t.Helper()
	result, err := verifier.Verify(compact, clock)
	if err != want {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if result.EnvelopeJSON() != nil || result.KeyID() != "" || result.TrustGeneration() != 0 {
		t.Fatal("failure returned partial verified result")
	}
}
