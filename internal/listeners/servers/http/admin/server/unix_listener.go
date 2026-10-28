package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrListenUnix reports an unusable listenUnix path or directory.
var ErrListenUnix = errors.New("listeners/servers/http/admin/server: invalid listenUnix socket path or directory")

type unixPeerKey struct{}

// markUnixPeer tags connections accepted on a unix socket. Request data can
// never set this context value.
func markUnixPeer(ctx context.Context, c net.Conn) context.Context {
	if _, ok := c.(*net.UnixConn); ok {
		return context.WithValue(ctx, unixPeerKey{}, true)
	}
	return ctx
}

func unixPeer(r *http.Request) bool {
	v, _ := r.Context().Value(unixPeerKey{}).(bool)
	return v
}

// ValidListenUnixPath accepts an absolute, clean, bounded path whose final
// element is a plain name.
func ValidListenUnixPath(p string) bool {
	if p == "" || len(p) > 100 || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\n\r") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(p)))
	base := filepath.Base(filepath.FromSlash(p))
	return clean == p && base != "/" && base != "." && base != ".."
}

// listenUnix creates the socket only inside an existing private directory: a
// real directory (not a symlink) without group write or any other-user bits,
// so no other local user can pre-create or replace the socket. A stale socket
// left by this service is removed; any other existing file is refused.
func (h *HTTPAdminServer) listenUnix() (net.Listener, error) {
	p := filepath.FromSlash(h.ListenUnix)
	if !ValidListenUnixPath(h.ListenUnix) {
		return nil, ErrListenUnix
	}
	dir, err := os.Lstat(filepath.Dir(p))
	if err != nil || !dir.IsDir() || (runtime.GOOS != "windows" && dir.Mode().Perm()&0027 != 0) {
		return nil, ErrListenUnix
	}
	if existing, err := os.Lstat(p); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return nil, ErrListenUnix
		}
		if os.Remove(p) != nil {
			return nil, ErrListenUnix
		}
	}
	listener, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(p, 0660); err != nil {
		listener.Close()
		return nil, ErrListenUnix
	}
	return listener, nil
}
