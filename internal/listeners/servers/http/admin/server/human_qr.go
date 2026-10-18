package server

import (
	"encoding/base32"
	"encoding/base64"
	"net/http"
	"net/url"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/zhouchenh/secDNS/internal/adminauth"
)

// enrollmentPNG encodes locally. The seed is never put in a request URL, image
// endpoint, filesystem artifact or third-party service.
func enrollmentPNG(en adminauth.Enrollment, identity adminauth.Identity) (string, error) {
	if len(en.Secret) != 32 {
		return "", adminauth.ErrInvalid
	}
	seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en.Secret)
	if e != nil || len(seed) != 20 || base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed) != en.Secret {
		return "", adminauth.ErrInvalid
	}
	clear(seed)
	if len(identity.RealmID) > 64 || len(identity.NodeID) > 64 || identity.RealmID == "" || identity.NodeID == "" {
		return "", adminauth.ErrInvalid
	}
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/secDNS:" + identity.RealmID + "/" + identity.NodeID}
	q := url.Values{"secret": {en.Secret}, "issuer": {"secDNS"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	u.RawQuery = q.Encode()
	png, e := qrcode.Encode(u.String(), qrcode.Medium, 320)
	if e != nil || len(png) > 8192 {
		return "", adminauth.ErrUnavailable
	}
	return base64.StdEncoding.EncodeToString(png), nil
}
func (h *HTTPAdminServer) writeEnrollment(w http.ResponseWriter, en adminauth.Enrollment) {
	png, e := enrollmentPNG(en, h.agent.store.Identity())
	if e != nil {
		authenticationError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"challenge": en.Challenge, "secret": en.Secret, "expires_at": en.ExpiresAt, "qr_png": png})
}
