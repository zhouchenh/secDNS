package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
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
	trustedSSOMaxToken  = 12 << 10
)

// DefaultTrustedSSORejectClaims is used when rejectClaims is not configured:
// a token carrying Keycloak's impersonator claim (an administrator acting as
// the owner) never becomes an owner session.
var DefaultTrustedSSORejectClaims = []string{"impersonator"}

// TrustedSSO lets the local edge (nginx behind an oauth2-proxy role gate) assert
// the already-authenticated owner identity. It is absent and off by default.
// An assertion is accepted only when every one of these holds:
//   - the peer reached the console's private unix socket (listenUnix), whose
//     directory only the console, root and the edge's group can enter; TCP peers,
//     including loopback, are never trusted for SSO (no port-squatting window);
//   - exactly one secret header matches the secret file (constant time);
//   - exactly one user header names an allowed user (the identity provider's
//     immutable subject); when usernameHeader is configured, exactly one username
//     header must also name an allowed username (secondary match);
//   - exactly one roles header contains the required role;
//   - the complete trusted forwarding tuple is valid;
//   - every configured token header carries exactly one JWT whose payload is a
//     readable JSON object with "sub" equal to the user header and none of the
//     rejectClaims (default "impersonator") present with any value, null or {}
//     included; the edge already verified the signature, so the console only
//     reads the payload over the trusted channel;
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
	// Optional secondary match (both or neither).
	UsernameHeader   string
	AllowedUsernames []string
	// TokenHeaders carry the edge-verified ID/access tokens (1 or 2 headers);
	// RejectClaims are claim names that refuse the assertion when present.
	TokenHeaders []string
	RejectClaims []string

	secretDigest [sha256.Size]byte
	loaded       bool
}

// String never exposes the configured secret digest.
func (*TrustedSSO) String() string   { return "server.TrustedSSO[redacted]" }
func (*TrustedSSO) GoString() string { return "server.TrustedSSO[redacted]" }

var trustedSSOKeys = []string{"headerSecretFile", "secretHeader", "userHeader", "rolesHeader", "requiredRole", "allowedUsers", "mapsTo", "tokenHeaders"}
var trustedSSOOptionalKeys = []string{"usernameHeader", "allowedUsernames"}

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
	if !ok {
		return nil, false
	}
	for _, key := range trustedSSOKeys {
		if _, ok := m[key]; !ok {
			return nil, false
		}
	}
	optional := 0
	for _, key := range trustedSSOOptionalKeys {
		if _, ok := m[key]; ok {
			optional++
		}
	}
	_, hasReject := m["rejectClaims"]
	extra := 0
	if hasReject {
		extra = 1
	}
	if (optional != 0 && optional != len(trustedSSOOptionalKeys)) || len(m) != len(trustedSSOKeys)+optional+extra {
		return nil, false
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
	names := []string{out.SecretHeader, out.UserHeader, out.RolesHeader}
	if optional != 0 {
		out.UsernameHeader = http.CanonicalHeaderKey(text("usernameHeader"))
		names = append(names, out.UsernameHeader)
	}
	tokens, ok := m["tokenHeaders"].([]interface{})
	if !ok || len(tokens) == 0 || len(tokens) > 2 {
		return nil, false
	}
	for _, value := range tokens {
		name, ok := value.(string)
		if !ok {
			return nil, false
		}
		out.TokenHeaders = append(out.TokenHeaders, http.CanonicalHeaderKey(name))
	}
	names = append(names, out.TokenHeaders...)
	headers := map[string]bool{}
	for _, name := range names {
		if !validTrustedSSOHeaderName(name) || headers[name] {
			return nil, false
		}
		headers[name] = true
	}
	if !validTrustedSSOValue(out.RequiredRole, 128) || out.MapsTo != "owner" {
		return nil, false
	}
	if out.AllowedUsers, ok = trustedSSOList(m["allowedUsers"]); !ok {
		return nil, false
	}
	if optional != 0 {
		if out.AllowedUsernames, ok = trustedSSOList(m["allowedUsernames"]); !ok {
			return nil, false
		}
	}
	out.RejectClaims = append([]string(nil), DefaultTrustedSSORejectClaims...)
	if hasReject {
		// An explicit list replaces the default; it can never be empty.
		if out.RejectClaims, ok = trustedSSOList(m["rejectClaims"]); !ok {
			return nil, false
		}
	}
	return out, true
}

// trustedSSOTokenCheck reads one edge-verified JWT payload. It returns a fixed
// reason token, never a claim value.
func trustedSSOTokenCheck(raw, subject string, reject []string) string {
	raw = strings.TrimPrefix(raw, "Bearer ")
	if raw == "" || len(raw) > trustedSSOMaxToken {
		return "token"
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[1] == "" {
		return "token"
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "token"
	}
	defer clear(payload)
	d := json.NewDecoder(bytes.NewReader(payload))
	var claims map[string]json.RawMessage
	if d.Decode(&claims) != nil || claims == nil || d.More() {
		return "token"
	}
	for _, name := range reject {
		if _, present := claims[name]; present {
			return "rejected_claim"
		}
	}
	var sub string
	if s, ok := claims["sub"]; !ok || json.Unmarshal(s, &sub) != nil || sub != subject {
		return "token_subject"
	}
	return ""
}

func trustedSSOList(raw interface{}) ([]string, bool) {
	values, ok := raw.([]interface{})
	if !ok || len(values) == 0 || len(values) > trustedSSOMaxUsers {
		return nil, false
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		v, ok := value.(string)
		if !ok || !validTrustedSSOValue(v, trustedSSOMaxValue) || seen[v] {
			return nil, false
		}
		seen[v] = true
		out = append(out, v)
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
// an exact HTTPS public origin (checked by the configuration binder) and the
// private unix-socket listener. A TCP listener, even on loopback, can be bound
// by any local user while the console restarts, so SSO refuses it.
func (h *HTTPAdminServer) ValidateTrustedSSO() error {
	if h.TrustedSSO == nil {
		return nil
	}
	if h.FollowerStatusOnly || h.ListenUnix == "" {
		return ErrTrustedSSO
	}
	return nil
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
			known := canonical == c.SecretHeader || canonical == c.UserHeader || canonical == c.RolesHeader || (c.UsernameHeader != "" && canonical == c.UsernameHeader)
			for _, token := range c.TokenHeaders {
				known = known || canonical == token
			}
			if !known || canonical != name {
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
	if h.ListenUnix == "" || !unixPeer(r) {
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
	// Only an exact entry equal to requiredRole counts. Other entries (an
	// identity provider may add roles or groups with spaces or non-ASCII names)
	// are ignored rather than refusing the whole assertion.
	hasRole := false
	for _, role := range strings.Split(roles[0], ",") {
		if strings.TrimSpace(role) == c.RequiredRole {
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
	if c.UsernameHeader != "" {
		names := r.Header.Values(c.UsernameHeader)
		if len(names) != 1 || !validTrustedSSOValue(names[0], trustedSSOMaxValue) {
			return trustedSSOInvalid, "username"
		}
		match := false
		for _, name := range c.AllowedUsernames {
			if name == names[0] {
				match = true
			}
		}
		if !match {
			return trustedSSOInvalid, "username_not_allowed"
		}
	}
	// Fail closed: without readable token claims the reject list cannot be checked.
	if len(c.TokenHeaders) == 0 || len(c.RejectClaims) == 0 {
		return trustedSSOInvalid, "token"
	}
	for _, name := range c.TokenHeaders {
		tokens := r.Header.Values(name)
		if len(tokens) != 1 {
			return trustedSSOInvalid, "token"
		}
		if reason := trustedSSOTokenCheck(tokens[0], users[0], c.RejectClaims); reason != "" {
			return trustedSSOInvalid, reason
		}
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
		state, reason := h.trustedSSOCheck(r)
		if state == trustedSSOInvalid {
			h.trustedSSOLog(false, reason)
			agentError(w, http.StatusForbidden, "sso_rejected")
			return
		}
		if state == trustedSSOValid && trustedSSOBreakGlassOnly(h.basePath(), r.Method, r.URL.Path) {
			agentError(w, http.StatusForbidden, "break_glass_only")
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
	result, e := h.agent.human.TrustedOwnerLogin(now, h.trustedSSOAuthTime(r))
	if e != nil {
		h.trustedSSOLog(false, "owner_session")
		authenticationError(w, e)
		return
	}
	h.trustedSSOLog(true, "")
	humanCookie(w, result)
}

// trustedSSOAuthTime returns the ID token's auth_time (the first token header
// carries the ID token), or zero when absent or unreadable. The caller has
// already validated the assertion, including the token payloads.
func (h *HTTPAdminServer) trustedSSOAuthTime(r *http.Request) time.Time {
	c := h.TrustedSSO
	if c == nil || len(c.TokenHeaders) == 0 {
		return time.Time{}
	}
	values := r.Header.Values(c.TokenHeaders[0])
	if len(values) != 1 {
		return time.Time{}
	}
	parts := strings.Split(strings.TrimPrefix(values[0], "Bearer "), ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}
	}
	defer clear(payload)
	var claims struct {
		AuthTime *json.Number `json:"auth_time"`
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	if d.Decode(&claims) != nil || claims.AuthTime == nil {
		return time.Time{}
	}
	seconds, err := claims.AuthTime.Int64()
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}

// trustedSSOBreakGlassOnly lists the routes that render or complete the
// console's own sign-in and credential management. On the single sign-on path
// (a request carrying a valid edge assertion) they are refused: the public site
// never offers password, recovery, authenticator or agent sign-in. They stay
// available on the private socket without SSO headers (break-glass).
func trustedSSOBreakGlassOnly(base, method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	switch strings.TrimPrefix(path, base) {
	case "/auth/setup/begin", "/auth/recovery/local", "/auth/recovery/code", "/auth/login/password", "/auth/login/totp",
		"/auth/agent-session", "/auth/totp/begin", "/auth/totp/confirm", "/auth/reauth/password-totp", "/auth/password",
		"/auth/recovery-codes/regenerate":
		return true
	}
	return strings.HasPrefix(path, base+"/auth/passkeys/")
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
