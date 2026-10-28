package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/zhouchenh/secDNS/internal/logger"
)

// ErrTrustedSSO reports an unusable trustedSSO configuration or secret file.
// It never carries the path contents or any header value.
var ErrTrustedSSO = errors.New("listeners/servers/http/admin/server: invalid trustedSSO configuration")

// trustedSSOHeaderPrefix is the canonical prefix every trusted single sign-on
// header must use. Any request header with this prefix makes the request an SSO
// assertion that must validate completely; there is no partial trust.
const trustedSSOHeaderPrefix = "X-Secdns-Sso-"

const (
	trustedSSOMinSecret = 32
	trustedSSOMaxSecret = 1024
	trustedSSOMaxValue  = 254
	trustedSSOMaxRoles  = 4096
	trustedSSOMaxUsers  = 8
)

// TrustedSSO lets the local edge (nginx behind an oauth2-proxy role gate) assert
// the already-authenticated owner identity. It is absent and off by default.
// An assertion is accepted only when every one of these holds:
//   - the socket peer is a loopback address listed in trustedProxySources;
//   - exactly one secret header matches the secret file (constant time);
//   - exactly one user header names an allowed user;
//   - exactly one roles header contains the required role;
//   - the complete trusted forwarding tuple is valid;
//   - no other X-Secdns-SSO-* header is present.
//
// A valid assertion only lets the browser exchange it for the owner's normal
// console session (POST <path>/auth/login/sso). Requests without any SSO header
// keep the unchanged password+TOTP/passkey login (break-glass). Requests whose
// SSO headers are present but invalid are refused on every route.
type TrustedSSO struct {
	HeaderSecretFile string
	SecretHeader     string
	UserHeader       string
	RolesHeader      string
	RequiredRole     string
	AllowedUsers     []string
	MapsTo           string

	secretDigest [sha256.Size]byte
	loaded       bool
}

// String never exposes the configured secret digest.
func (*TrustedSSO) String() string   { return "server.TrustedSSO[redacted]" }
func (*TrustedSSO) GoString() string { return "server.TrustedSSO[redacted]" }

var trustedSSOKeys = []string{"headerSecretFile", "secretHeader", "userHeader", "rolesHeader", "requiredRole", "allowedUsers", "mapsTo"}

func trustedSSOValue(original interface{}) (interface{}, bool) {
	config, ok := original.(map[string]interface{})
	if !ok {
		return nil, false
	}
	raw, present := config["trustedSSO"]
	if !present {
		return (*TrustedSSO)(nil), true
	}
	sso, ok := ParseTrustedSSO(raw)
	if !ok {
		return nil, false
	}
	return sso, true
}

// ParseTrustedSSO validates the configuration shape. It performs no I/O; the
// secret file is read by LoadTrustedSSOSecret at configuration load.
func ParseTrustedSSO(raw interface{}) (*TrustedSSO, bool) {
	m, ok := raw.(map[string]interface{})
	if !ok || len(m) != len(trustedSSOKeys) {
		return nil, false
	}
	for _, key := range trustedSSOKeys {
		if _, ok := m[key]; !ok {
			return nil, false
		}
	}
	text := func(key string) string {
		v, _ := m[key].(string)
		return v
	}
	out := &TrustedSSO{
		HeaderSecretFile: text("headerSecretFile"),
		SecretHeader:     http.CanonicalHeaderKey(text("secretHeader")),
		UserHeader:       http.CanonicalHeaderKey(text("userHeader")),
		RolesHeader:      http.CanonicalHeaderKey(text("rolesHeader")),
		RequiredRole:     text("requiredRole"),
		MapsTo:           text("mapsTo"),
	}
	p := out.HeaderSecretFile
	if p == "" || len(p) > 4096 || !strings.HasPrefix(p, "/") || !filepath.IsAbs(filepath.FromSlash(p)) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(p))) != p {
		return nil, false
	}
	headers := map[string]bool{}
	for _, name := range []string{out.SecretHeader, out.UserHeader, out.RolesHeader} {
		if !validTrustedSSOHeaderName(name) || headers[name] {
			return nil, false
		}
		headers[name] = true
	}
	if !validTrustedSSOValue(out.RequiredRole, 128) || out.MapsTo != "owner" {
		return nil, false
	}
	users, ok := m["allowedUsers"].([]interface{})
	if !ok || len(users) == 0 || len(users) > trustedSSOMaxUsers {
		return nil, false
	}
	seen := map[string]bool{}
	for _, value := range users {
		user, ok := value.(string)
		if !ok || !validTrustedSSOValue(user, trustedSSOMaxValue) || seen[user] {
			return nil, false
		}
		seen[user] = true
		out.AllowedUsers = append(out.AllowedUsers, user)
	}
	return out, true
}

func validTrustedSSOHeaderName(name string) bool {
	if len(name) <= len(trustedSSOHeaderPrefix) || len(name) > 64 || !strings.HasPrefix(name, trustedSSOHeaderPrefix) {
		return false
	}
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// validTrustedSSOValue accepts one bounded visible-ASCII token without commas
// or whitespace, so list splitting and padding cannot change its meaning.
func validTrustedSSOValue(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, c := range []byte(value) {
		if c < 0x21 || c > 0x7e || c == ',' {
			return false
		}
	}
	return true
}

// LoadTrustedSSOSecret reads the shared header secret once. The file must be a
// regular, non-symlink file with no group or other permission bits, holding at
// least 32 visible ASCII bytes (one trailing newline is ignored). Only its
// SHA-256 digest is retained.
func (h *HTTPAdminServer) LoadTrustedSSOSecret() error {
	c := h.TrustedSSO
	if c == nil {
		return nil
	}
	c.loaded = false
	path := filepath.FromSlash(c.HeaderSecretFile)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < trustedSSOMinSecret || info.Size() > trustedSSOMaxSecret+2 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return ErrTrustedSSO
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrTrustedSSO
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return ErrTrustedSSO
	}
	raw, err := io.ReadAll(io.LimitReader(f, trustedSSOMaxSecret+3))
	defer clear(raw)
	if err != nil || len(raw) > trustedSSOMaxSecret+2 {
		return ErrTrustedSSO
	}
	secret := raw
	if n := len(secret); n > 0 && secret[n-1] == '\n' {
		secret = secret[:n-1]
		if n := len(secret); n > 0 && secret[n-1] == '\r' {
			secret = secret[:n-1]
		}
	}
	if len(secret) < trustedSSOMinSecret || len(secret) > trustedSSOMaxSecret {
		return ErrTrustedSSO
	}
	for _, b := range secret {
		if b < 0x21 || b > 0x7e {
			return ErrTrustedSSO
		}
	}
	c.secretDigest = sha256.Sum256(secret)
	c.loaded = true
	return nil
}

// ValidateTrustedSSO checks the listener-level preconditions: an auth store with
// an exact HTTPS public origin (checked by the configuration binder) and at
// least one loopback trusted proxy source.
func (h *HTTPAdminServer) ValidateTrustedSSO() error {
	if h.TrustedSSO == nil {
		return nil
	}
	if h.FollowerStatusOnly {
		return ErrTrustedSSO
	}
	for _, source := range h.TrustedProxySources {
		if source.IsLoopback() {
			return nil
		}
	}
	return ErrTrustedSSO
}

type trustedSSOState int

const (
	trustedSSOAbsent trustedSSOState = iota
	trustedSSOValid
	trustedSSOInvalid
)

// trustedSSOCheck classifies a request. The returned reason is a fixed token
// for logs; it never contains a header value.
func (h *HTTPAdminServer) trustedSSOCheck(r *http.Request) (trustedSSOState, string) {
	c := h.TrustedSSO
	if c == nil {
		return trustedSSOAbsent, ""
	}
	present, unexpected := false, false
	for name := range r.Header {
		canonical := http.CanonicalHeaderKey(name)
		if len(canonical) >= len(trustedSSOHeaderPrefix) && strings.EqualFold(canonical[:len(trustedSSOHeaderPrefix)], trustedSSOHeaderPrefix) {
			present = true
			if canonical != c.SecretHeader && canonical != c.UserHeader && canonical != c.RolesHeader || canonical != name {
				unexpected = true
			}
		}
	}
	if !present {
		return trustedSSOAbsent, ""
	}
	if unexpected {
		return trustedSSOInvalid, "unexpected_header"
	}
	if !c.loaded {
		return trustedSSOInvalid, "unavailable"
	}
	socket, ok := socketSource(r)
	if !ok || !socket.IsLoopback() || !h.trustedSocketSource(socket) {
		return trustedSSOInvalid, "peer"
	}
	secrets := r.Header.Values(c.SecretHeader)
	if len(secrets) != 1 {
		return trustedSSOInvalid, "secret"
	}
	presented := sha256.Sum256([]byte(secrets[0]))
	if subtle.ConstantTimeCompare(presented[:], c.secretDigest[:]) != 1 {
		return trustedSSOInvalid, "secret"
	}
	users := r.Header.Values(c.UserHeader)
	if len(users) != 1 || !validTrustedSSOValue(users[0], trustedSSOMaxValue) {
		return trustedSSOInvalid, "user"
	}
	roles := r.Header.Values(c.RolesHeader)
	if len(roles) != 1 || roles[0] == "" || len(roles[0]) > trustedSSOMaxRoles {
		return trustedSSOInvalid, "role"
	}
	hasRole := false
	for _, role := range strings.Split(roles[0], ",") {
		role = strings.TrimSpace(role)
		if role == "" || !validTrustedSSOValue(role, trustedSSOMaxRoles) {
			return trustedSSOInvalid, "role"
		}
		if role == c.RequiredRole {
			hasRole = true
		}
	}
	if !hasRole {
		return trustedSSOInvalid, "role"
	}
	allowed := false
	for _, user := range c.AllowedUsers {
		if user == users[0] {
			allowed = true
		}
	}
	if !allowed {
		return trustedSSOInvalid, "user_not_allowed"
	}
	if h.humanSource(r) == "" {
		return trustedSSOInvalid, "forwarded"
	}
	return trustedSSOValid, ""
}

// trustedSSOLog records outcomes with fixed reason tokens only. Header values,
// the secret and the user name are never logged.
func (h *HTTPAdminServer) trustedSSOLog(accepted bool, reason string) {
	if h.trustedSSOLogger != nil {
		h.trustedSSOLogger(accepted, reason)
		return
	}
	if accepted {
		// Warning is the default visible level; a sign-in without a console password must be visible.
		logger.Warning().Str("method", "sso").Msg("admin auth: owner session issued from trusted single sign-on")
		return
	}
	logger.Warning().Str("method", "sso").Str("reason", reason).Msg("admin auth: trusted single sign-on assertion rejected")
}

// trustedSSOGate refuses every request that carries an invalid SSO assertion.
// Requests without SSO headers pass unchanged; with trustedSSO absent the
// handler is returned as is and SSO-like headers are ignored as before.
func (h *HTTPAdminServer) trustedSSOGate(next http.Handler) http.Handler {
	if h.TrustedSSO == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state, reason := h.trustedSSOCheck(r); state == trustedSSOInvalid {
			h.trustedSSOLog(false, reason)
			agentError(w, http.StatusForbidden, "sso_rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// trustedSSOLogin exchanges a valid assertion for the owner's normal session.
// It runs inside the public human wrapper: exact HTTPS origin, same-origin
// Fetch Metadata, JSON content type, no cookie or Authorization header, a
// valid trusted forwarding tuple and the exact empty JSON body {}.
func (h *HTTPAdminServer) trustedSSOLogin(w http.ResponseWriter, r *http.Request, _ map[string]string, _ string, now time.Time) {
	if state, _ := h.trustedSSOCheck(r); state != trustedSSOValid {
		agentError(w, http.StatusUnauthorized, "sso_required")
		return
	}
	result, e := h.agent.human.TrustedOwnerLogin(now)
	if e != nil {
		h.trustedSSOLog(false, "owner_session")
		authenticationError(w, e)
		return
	}
	h.trustedSSOLog(true, "")
	humanCookie(w, result)
}

// trustedSSOAvailable reports, for /auth/state, whether this request carries a
// valid assertion that can be exchanged for a session.
func (h *HTTPAdminServer) trustedSSOAvailable(r *http.Request) bool {
	if h.TrustedSSO == nil || h.agent == nil || h.agent.origin == "" {
		return false
	}
	state, _ := h.trustedSSOCheck(r)
	return state == trustedSSOValid
}
