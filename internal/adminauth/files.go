package adminauth

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Private paths must have a private existing parent. Windows ACL enforcement is
// an operator prerequisite; Unix mode checks do not establish Windows privacy.
func privatePath(path string, exists bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	if runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
		return ErrInvalid
	}
	st, err := os.Lstat(path)
	if !exists {
		if os.IsNotExist(err) {
			return nil
		}
		return ErrExists
	}
	if err != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		return ErrInvalid
	}
	return nil
}

// CreateKey is an explicit local-only operation. It never overwrites a key.
// An interrupted creation is retained for diagnosis, never silently regenerated.
func CreateKey(path string) error {
	if err := privatePath(path, false); err != nil {
		return err
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return ErrUnavailable
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrUnavailable
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrUnavailable
	}
	return nil
}
func readKey(path string) ([]byte, error) {
	if err := privatePath(path, true); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	b := make([]byte, 33)
	n, err := io.ReadFull(f, b)
	if err != io.ErrUnexpectedEOF || n != 32 {
		clear(b)
		return nil, ErrInvalid
	}
	return b[:32], nil
}
