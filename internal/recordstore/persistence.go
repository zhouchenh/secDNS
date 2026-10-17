package recordstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// ValidatePaths performs syntax/collision validation only; it opens no files.
func ValidatePaths(paths map[string]string) error {
	seen := map[string]bool{}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := paths[name]
		if name == "" || strings.TrimSpace(name) != name {
			return errors.New("record store name must be nonempty and trimmed")
		}
		if strings.HasPrefix(path, `\\`) || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "?\x00") {
			return errors.New("record database must use a clean absolute file path")
		}
		key := path
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if seen[key] {
			return errors.New("duplicate record database path")
		}
		seen[key] = true
	}
	return nil
}

// Prepare opens every store before publishing any registry entry. Existing stores
// are never replaced; callers own the returned cleanup, which touches only these entries.
func Prepare(paths map[string]string) (func() error, error) {
	if err := ValidatePaths(paths); err != nil {
		return nil, err
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	var files []os.FileInfo
	for _, name := range names {
		if _, exists := registry[name]; exists {
			return nil, errors.New("record store already initialized")
		}
		if _, exists := versionedRegistry[name]; exists {
			return nil, errors.New("record store already initialized")
		}
		info, err := os.Lstat(paths[name])
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if info != nil {
			if !info.Mode().IsRegular() {
				return nil, errors.New("database must be regular, not symlink")
			}
			for _, other := range files {
				if os.SameFile(info, other) {
					return nil, errors.New("duplicate record database identity")
				}
			}
			files = append(files, info)
		}
	}
	opened := map[string]*Store{}
	for _, name := range names {
		s, err := OpenSQLite(paths[name])
		if err != nil {
			for _, s := range opened {
				_ = s.Close()
			}
			return nil, err
		}
		opened[name] = s
	}
	for _, name := range names {
		registry[name] = opened[name]
		opened[name].startGC()
	}
	return func() error {
		registryMu.Lock()
		defer registryMu.Unlock()
		var result error
		for _, name := range names {
			if registry[name] == opened[name] {
				delete(registry, name)
			}
			result = errors.Join(result, opened[name].Close())
		}
		return result
	}, nil
}
