package server

import (
	"errors"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http"
)

var ErrFollowerStatusOnly = errors.New("admin: invalid follower-status-only listener")

// ValidateFollowerStatusOnly never opens or implicitly creates a record store.
func (h *HTTPAdminServer) ValidateFollowerStatusOnly() error {
	if !h.FollowerStatusOnly {
		return nil
	}
	if h.recordGatewayEnabled() || len(h.followerStatusNames) == 0 || h.Store != "" || len(h.SnapshotReaders) > 0 || h.SourcePolicyExplain || h.store != nil || h.versioned != nil {
		return ErrFollowerStatusOnly
	}
	return nil
}
func (h *HTTPAdminServer) prepareRecordBinding() error {
	if h.recordGatewayEnabled() {
		return h.prepareRecordGateway()
	}
	if h.FollowerStatusOnly {
		if err := h.ValidateFollowerStatusOnly(); err != nil {
			return err
		}
		if h.followerStatus == nil {
			return ErrFollowerStatusOnly
		}
		return nil
	}
	h.store, h.versioned = recordstore.Binding(h.Store)
	if recordstore.FollowerBinding(h.Store) != nil || len(h.SnapshotReaders) > 0 && h.versioned == nil {
		return ErrStoreMode
	}
	return nil
}
func (h *HTTPAdminServer) followerOnlyUIRoutes(mux *http.ServeMux, base string) {
	h.followerUIRoutes(mux, base)
	for _, route := range []string{"/ui", "/ui/{$}"} {
		mux.HandleFunc("GET "+base+route, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			http.Redirect(w, r, base+"/ui/followers/", http.StatusSeeOther)
		})
	}
}
