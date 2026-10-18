package recordstore

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/zhouchenh/secDNS/internal/recordset"
)

func TestAcquireExactViewNeverCreatesOrAdmitsLegacy(t *testing.T) {
	missing := t.Name() + "-missing"
	if _, err := AcquireExactView(missing); !errors.Is(err, ErrExactReadBinding) {
		t.Fatal(err)
	}
	registryMu.Lock()
	_, created := registry[missing]
	registryMu.Unlock()
	if created {
		t.Fatal("missing exact read binding created a legacy store")
	}

	legacyName := t.Name() + "-legacy"
	legacy := GetOrCreate(legacyName)
	t.Cleanup(func() {
		_ = legacy.Close()
		registryMu.Lock()
		delete(registry, legacyName)
		registryMu.Unlock()
	})
	if _, err := AcquireExactView(legacyName); !errors.Is(err, ErrExactReadBinding) {
		t.Fatal("legacy store admitted as exact read binding", err)
	}
}

func TestAcquireExactViewWriterFollowerAndTerminalStates(t *testing.T) {
	writerName := t.Name() + "-writer"
	followerName := t.Name() + "-follower"
	enrollment := FollowerEnrollment{ClusterID: "cluster", Kind: FollowerExactRecords, RulesetID: "rules", LineageID: "lineage", AuthorityEpoch: "epoch"}
	cleanup, err := PrepareBindingsWithFollowers(nil,
		map[string]VersionedConfig{writerName: {Backend: "memory", RulesetID: "rules", LineageID: "lineage"}},
		map[string]FollowerConfig{followerName: {SQLitePath: filepath.Join(t.TempDir(), "follower.db"), Enrollment: enrollment, CreateIfMissing: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = cleanup()
		}
		registryMu.Lock()
		delete(versionedRegistry, writerName)
		delete(followerRegistry, followerName)
		registryMu.Unlock()
	})
	writer := versionedRegistry[writerName]
	if _, err = writer.Replace(Expected{RulesetID: "rules", LineageID: "lineage", Revision: 1}, "writer-op", []recordset.Record{{Name: "writer.invalid.", Type: "A", Values: []string{"192.0.2.1"}, TTLSeconds: 31}}); err != nil {
		t.Fatal(err)
	}
	writerView, err := AcquireExactView(writerName)
	if err != nil {
		t.Fatal(err)
	}
	if record, ok := writerView.Lookup("WRITER.invalid.", "A"); !ok || record.TTLSeconds != 31 {
		t.Fatal("writer generation unavailable", record, ok)
	}

	if _, err = AcquireExactView(followerName); !errors.Is(err, ErrFollowerNotReady) {
		t.Fatal("empty follower did not fail closed", err)
	}
	snapshot, err := recordset.New("rules", "lineage", 1, []recordset.Record{{Name: "follower.invalid.", Type: "A", Values: []string{"192.0.2.2"}, TTLSeconds: 32}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := snapshot.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = followerRegistry[followerName].Accept(enrollment, raw); err != nil {
		t.Fatal(err)
	}
	followerView, err := AcquireExactView(followerName)
	if err != nil {
		t.Fatal(err)
	}
	if record, ok := followerView.Lookup("follower.invalid.", "A"); !ok || record.TTLSeconds != 32 {
		t.Fatal("follower generation unavailable", record, ok)
	}
	followerRegistry[followerName].current.Store(&followerPublication{status: followerFaulted})
	if _, err = AcquireExactView(followerName); !errors.Is(err, ErrFollowerFaulted) {
		t.Fatal("faulted follower treated as empty", err)
	}

	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	cleaned = true
	if _, err = AcquireExactView(writerName); !errors.Is(err, ErrClosed) {
		t.Fatal("closed writer tombstone reopened", err)
	}
	if _, err = AcquireExactView(followerName); !errors.Is(err, ErrClosed) {
		t.Fatal("closed follower tombstone reopened", err)
	}
}
