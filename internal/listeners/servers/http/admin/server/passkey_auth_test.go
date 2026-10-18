package server

import (
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"io"
	"net/http/httptest"
	"testing"
)

type passkeyUnreadBody struct{ read bool }

func (b *passkeyUnreadBody) Read([]byte) (int, error) { b.read = true; return 0, io.EOF }
func (*passkeyUnreadBody) Close() error               { return nil }
func TestPasskeyAuthorizationBeforeBody(t *testing.T) {
	h, _ := humanTestServer(t)
	h.agent.passkeys = &adminauth.PasskeyAuth{}
	// Deliberately unusable passkey core: all requests must refuse before reaching it.
	defer func() { h.agent.passkeys = nil }()
	for _, tc := range []struct{ path, origin, bearer string }{{"register/begin", h.agent.origin, ""}, {"login/begin", "https://other.invalid", ""}, {"login/begin", h.agent.origin, "Bearer synthetic"}} {
		body := &passkeyUnreadBody{}
		r := httptest.NewRequest("POST", "/admin/auth/passkeys/"+tc.path, body)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/json")
		if tc.bearer != "" {
			r.Header.Set("Authorization", tc.bearer)
		}
		w := httptest.NewRecorder()
		h.routes().ServeHTTP(w, r)
		if w.Code != 403 || body.read {
			t.Fatalf("code=%d read=%v", w.Code, body.read)
		}
	}
}
