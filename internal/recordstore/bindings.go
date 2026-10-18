package recordstore

import (
	"errors"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"os"
	"sort"
	"strings"
)

// VersionedConfig selects an explicit mode; runtime startup never migrates schema1.
type VersionedConfig struct{ Backend, SQLitePath, RulesetID, LineageID string }

// FollowerConfig selects a durable, immutably enrolled follower database.
// Existing files are always opened strictly; CreateIfMissing only authorizes
// creation when the final path is absent.
type FollowerConfig struct {
	SQLitePath      string
	Enrollment      FollowerEnrollment
	CreateIfMissing bool
}

func ValidateBindings(legacy map[string]string, versioned map[string]VersionedConfig) error {
	return ValidateBindingsWithFollowers(legacy, versioned, nil)
}

// ValidateBindingsWithFollowers performs syntax and path collision validation
// without filesystem I/O.
func ValidateBindingsWithFollowers(legacy map[string]string, versioned map[string]VersionedConfig, followers map[string]FollowerConfig) error {
	paths := map[string]string{}
	for n, p := range legacy {
		paths[n] = p
	}
	for n, c := range versioned {
		if n == "" || strings.TrimSpace(n) != n {
			return ErrVersionedInput
		}
		if _, ok := legacy[n]; ok {
			return ErrVersionedInput
		}
		if _, e := recordset.New(c.RulesetID, c.LineageID, 1, nil); e != nil {
			return ErrVersionedInput
		}
		switch c.Backend {
		case "memory":
			if c.SQLitePath != "" {
				return ErrVersionedInput
			}
		case "sqlite":
			paths[n] = c.SQLitePath
		default:
			return ErrVersionedInput
		}
	}
	for n, c := range followers {
		if n == "" || strings.TrimSpace(n) != n || !validFollowerEnrollment(c.Enrollment) {
			return ErrFollowerInput
		}
		if _, ok := legacy[n]; ok {
			return ErrFollowerInput
		}
		if _, ok := versioned[n]; ok {
			return ErrFollowerInput
		}
		paths[n] = c.SQLitePath
	}
	return ValidatePaths(paths)
}

// PrepareBindings opens all requested stores before atomically publishing modes.
// Failed startup publishes nothing. Cleanup retains closed versioned tombstones.
func PrepareBindings(legacy map[string]string, versioned map[string]VersionedConfig) (func() error, error) {
	return PrepareBindingsWithFollowers(legacy, versioned, nil)
}

// PrepareBindingsWithFollowers opens every requested mode before atomically
// publishing any name. Cleanup retains closed versioned and follower tombstones.
func PrepareBindingsWithFollowers(legacy map[string]string, versioned map[string]VersionedConfig, followers map[string]FollowerConfig) (func() error, error) {
	if e := ValidateBindingsWithFollowers(legacy, versioned, followers); e != nil {
		return nil, e
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	names := make([]string, 0, len(legacy)+len(versioned)+len(followers))
	paths := map[string]string{}
	for n, p := range legacy {
		names = append(names, n)
		paths[n] = p
	}
	for n, c := range versioned {
		names = append(names, n)
		if c.Backend == "sqlite" {
			paths[n] = c.SQLitePath
		}
	}
	for n, c := range followers {
		names = append(names, n)
		paths[n] = c.SQLitePath
	}
	sort.Strings(names)
	var files []os.FileInfo
	for _, n := range names {
		if registry[n] != nil || versionedRegistry[n] != nil || followerRegistry[n] != nil {
			return nil, ErrVersionedInput
		}
		if p, ok := paths[n]; ok {
			info, e := os.Lstat(p)
			if e != nil && !os.IsNotExist(e) {
				return nil, ErrVersionedStorage
			}
			if info != nil {
				if !info.Mode().IsRegular() {
					return nil, ErrVersionedInput
				}
				for _, f := range files {
					if os.SameFile(info, f) {
						return nil, ErrVersionedInput
					}
				}
				files = append(files, info)
			}
		}
	}
	old := map[string]*Store{}
	fresh := map[string]*VersionedStore{}
	following := map[string]*FollowerStore{}
	closeOpened := func() error {
		var e error
		for _, s := range old {
			e = errors.Join(e, s.Close())
		}
		for _, s := range fresh {
			e = errors.Join(e, s.Close())
		}
		for _, s := range following {
			e = errors.Join(e, s.Close())
		}
		return e
	}
	for _, n := range names {
		var e error
		if c, ok := versioned[n]; ok {
			enrollment := Enrollment{RulesetID: c.RulesetID, LineageID: c.LineageID}
			if c.Backend == "memory" {
				fresh[n], e = NewVersionedMemory(enrollment)
			} else {
				fresh[n], e = OpenVersionedSQLite(c.SQLitePath, enrollment)
			}
		} else if c, ok := followers[n]; ok {
			if _, statErr := os.Lstat(c.SQLitePath); statErr == nil {
				following[n], e = OpenFollowerSQLite(c.SQLitePath, c.Enrollment)
			} else if os.IsNotExist(statErr) && c.CreateIfMissing {
				following[n], e = CreateFollowerSQLite(c.SQLitePath, c.Enrollment)
			} else if os.IsNotExist(statErr) {
				e = ErrFollowerStorage
			} else {
				e = ErrFollowerStorage
			}
		} else {
			old[n], e = OpenSQLite(legacy[n])
		}
		if e != nil {
			delete(old, n)
			delete(fresh, n)
			delete(following, n)
			_ = closeOpened()
			return nil, e
		}
	}
	for n, s := range old {
		registry[n] = s
		s.startGC()
	}
	for n, s := range fresh {
		versionedRegistry[n] = s
	}
	for n, s := range following {
		followerRegistry[n] = s
	}
	return func() error {
		registryMu.Lock()
		defer registryMu.Unlock()
		for n, s := range old {
			if registry[n] == s {
				delete(registry, n)
			}
		}
		return closeOpened()
	}, nil
}
