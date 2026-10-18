package recordstore

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestFollowerBindingModeAndTombstone(t *testing.T) {
	name := t.Name()
	t.Cleanup(func() {
		registryMu.Lock()
		delete(followerRegistry, name)
		registryMu.Unlock()
	})
	config := FollowerConfig{SQLitePath: filepath.Join(t.TempDir(), "follower.db"), Enrollment: followerEnrollment, CreateIfMissing: true}
	cleanup, err := PrepareBindingsWithFollowers(nil, nil, map[string]FollowerConfig{name: config})
	if err != nil {
		t.Fatal(err)
	}
	legacy, versioned := Binding(name)
	follower := FollowerBinding(name)
	if legacy != nil || versioned != nil || follower == nil || GetOrCreate(name) != nil {
		t.Fatal("follower name was not exclusively reserved")
	}
	if _, err = follower.Acquire(); !errors.Is(err, ErrFollowerNotReady) {
		t.Fatal(err)
	}
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	legacy, versioned = Binding(name)
	if legacy != nil || versioned != nil || FollowerBinding(name) != follower || GetOrCreate(name) != nil {
		t.Fatal("closed follower tombstone lost")
	}
	if _, err = follower.Acquire(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestFollowerBindingsStrictOpenAndAtomicFailure(t *testing.T) {
	good, bad := t.Name()+"-a-good", t.Name()+"-z-bad"
	for _, name := range []string{good, bad} {
		name := name
		t.Cleanup(func() {
			registryMu.Lock()
			delete(followerRegistry, name)
			registryMu.Unlock()
		})
	}
	dir := t.TempDir()
	configs := map[string]FollowerConfig{
		good: {SQLitePath: filepath.Join(dir, "good.db"), Enrollment: followerEnrollment, CreateIfMissing: true},
		bad:  {SQLitePath: filepath.Join(dir, "missing", "bad.db"), Enrollment: followerEnrollment, CreateIfMissing: true},
	}
	if _, err := PrepareBindingsWithFollowers(nil, nil, configs); err == nil {
		t.Fatal("failed preparation succeeded")
	}
	if FollowerBinding(good) != nil || FollowerBinding(bad) != nil {
		t.Fatal("failed preparation published a partial binding")
	}
	delete(configs, bad)
	configs[good] = FollowerConfig{SQLitePath: filepath.Join(dir, "good.db"), Enrollment: followerEnrollment}
	cleanup, err := PrepareBindingsWithFollowers(nil, nil, configs)
	if err != nil {
		t.Fatal("strict open of created database failed", err)
	}
	t.Cleanup(func() { _ = cleanup() })
}

func TestFollowerBindingsRejectCrossModeCollision(t *testing.T) {
	config := FollowerConfig{SQLitePath: filepath.Join(t.TempDir(), "follower.db"), Enrollment: followerEnrollment, CreateIfMissing: true}
	if err := ValidateBindingsWithFollowers(nil, map[string]VersionedConfig{"same": {Backend: "memory", RulesetID: "r", LineageID: "l"}}, map[string]FollowerConfig{"same": config}); err == nil {
		t.Fatal("cross-mode name collision accepted")
	}
	if err := ValidateBindingsWithFollowers(map[string]string{"legacy": config.SQLitePath}, nil, map[string]FollowerConfig{"follower": config}); err == nil {
		t.Fatal("cross-mode path collision accepted")
	}
}
