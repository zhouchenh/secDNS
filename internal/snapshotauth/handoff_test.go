package snapshotauth

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordstore"
)

func TestVerifiedGenerationFollowerHandoffOrdering(t *testing.T) {
	fixture := newFixture(t)
	secondaryPrivate := testPrivate("renewal")
	config := cloneConfig(fixture.config)
	config.Trust.Keys = append(config.Trust.Keys, TrustedKey{
		KeyID: "key-secondary", PublicKey: append(ed25519.PublicKey(nil), secondaryPrivate.Public().(ed25519.PublicKey)...),
		NotBefore: config.Trust.NotBefore, NotAfter: config.Trust.NotAfter,
	})
	verifier, err := NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	clock := Clock{Now: fixture.now, Status: ClockTrusted}
	headerSecondary := []byte(`{"alg":"Ed25519","typ":"application/vnd.secdns.snapshot-generation.v1+jws","kid":"key-secondary"}`)

	verify := func(snapshot []byte, issuedAt, expiresAt time.Time, private ed25519.PrivateKey, header []byte) VerifiedGeneration {
		t.Helper()
		payload := payloadFor(t, config, snapshot, issuedAt, expiresAt)
		verified, verifyErr := verifier.Verify(signPayload(t, private, header, marshalPayload(t, payload)), clock)
		if verifyErr != nil {
			t.Fatal(verifyErr)
		}
		return verified
	}
	accept := func(store *recordstore.FollowerStore, verified VerifiedGeneration, outcome string) {
		t.Helper()
		accepted, acceptErr := store.Accept(verified.Enrollment(), verified.EnvelopeJSON())
		if acceptErr != nil || accepted.Outcome != outcome {
			t.Fatalf("outcome=%q error=%v, want %q", accepted.Outcome, acceptErr, outcome)
		}
	}

	snapshotOne := snapshotBytes(t, config.ExpectedEnrollment.RulesetID, config.ExpectedEnrollment.LineageID, 1, fixtureRecords("192.0.2.10"))
	initial := verify(snapshotOne, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.private, fixture.header)
	renewed := verify(snapshotOne, fixture.now.Add(-30*time.Second), fixture.now.Add(2*time.Hour), secondaryPrivate, headerSecondary)
	if initial.KeyID() == renewed.KeyID() || initial.IssuedAt() == renewed.IssuedAt() {
		t.Fatal("renewal did not change signed attestation metadata")
	}

	databasePath := filepath.Join(t.TempDir(), "follower.db")
	store, err := recordstore.CreateFollowerSQLite(databasePath, config.ExpectedEnrollment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if store != nil {
			_ = store.Close()
		}
	})
	accept(store, initial, "initial")
	accept(store, initial, "unchanged")
	accept(store, renewed, "unchanged")

	snapshotTwoSameContent := snapshotBytes(t, config.ExpectedEnrollment.RulesetID, config.ExpectedEnrollment.LineageID, 2, fixtureRecords("192.0.2.10"))
	higher := verify(snapshotTwoSameContent, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.private, fixture.header)
	if higher.Metadata().ContentSHA256 != initial.Metadata().ContentSHA256 {
		t.Fatal("same content changed digest")
	}
	accept(store, higher, "advanced")
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = recordstore.OpenFollowerSQLite(databasePath, config.ExpectedEnrollment)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := store.Acquire()
	if err != nil || restarted.State().Snapshot.Revision != 2 {
		t.Fatal("durable follower watermark was not restored", err)
	}

	snapshotTwoDifferentContent := snapshotBytes(t, config.ExpectedEnrollment.RulesetID, config.ExpectedEnrollment.LineageID, 2, fixtureRecords("192.0.2.11"))
	equivocation := verify(snapshotTwoDifferentContent, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.private, fixture.header)
	if _, err = store.Accept(equivocation.Enrollment(), equivocation.EnvelopeJSON()); !errors.Is(err, recordstore.ErrFollowerEquivocation) {
		t.Fatal("same-revision changed content was not equivocation", err)
	}
	if _, err = store.Accept(initial.Enrollment(), initial.EnvelopeJSON()); !errors.Is(err, recordstore.ErrFollowerRollback) {
		t.Fatal("lower authenticated revision was not rollback", err)
	}
}
