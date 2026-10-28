package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/zhouchenh/secDNS/internal/adminauth"
)

const sessionCookie = "__Host-secdns_session"

// SSOSignOutURL is where the console UI goes after signing out a session that
// was issued from a trusted single sign-on assertion.
const SSOSignOutURL = "/oauth2/sign_out?rd=%2F"

type agentBinding struct {
	store    *adminauth.Store
	sessions *adminauth.Sessions
	origin   string
	now      func() time.Time
	human    *adminauth.HumanAuth
	passkeys *adminauth.PasskeyAuth
}
type actorKey struct{}

func (h *HTTPAdminServer) BindAgentAuth(store *adminauth.Store, origin string) {
	sessions := adminauth.NewSessions(store)
	h.agent = &agentBinding{store: store, sessions: sessions, origin: origin, now: time.Now, human: adminauth.NewHumanAuth(store, sessions)}
}
func (h *HTTPAdminServer) ClearAgentAuth() {
	if h.agent != nil {
		if h.agent.passkeys != nil {
			h.agent.passkeys.Close()
		}
		h.agent.human.Close()
		h.agent.sessions.Close()
	}
}
func agentError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code})
}
func authenticationError(w http.ResponseWriter, e error) {
	if e == adminauth.ErrUnavailable {
		agentError(w, 503, "auth_unavailable")
		return
	}
	agentError(w, 401, "authentication")
}

// HTTPAdminServer refuses follower bindings; node role is independent of agent scopes.
func actorJSON(a adminauth.Actor) map[string]any {
	return map[string]any{"record_role": "writable_authority", "principal_type": a.Kind(), "principal_id": a.ID(), "display_name": a.DisplayName(), "realm_id": a.RealmID(), "node_id": a.NodeID(), "scopes": a.Scopes()}
}
func sessionJSON(i adminauth.SessionInfo) map[string]any {
	m := actorJSON(i.Actor)
	m["csrf"] = i.CSRF
	if i.Actor.Kind() == "human" {
		m["authenticated_at"] = i.AuthenticatedAt.UTC().Format(time.RFC3339)
		if i.SSO {
			// Fixed, relative, same-origin: the edge ends its own and the identity
			// provider's session; never derived from request data.
			m["sso"] = true
			m["sign_out_url"] = SSOSignOutURL
		}
	}
	m["expires_at"] = i.ExpiresAt.UTC().Format(time.RFC3339)
	m["idle_expires_at"] = i.IdleExpiresAt.UTC().Format(time.RFC3339)
	return m
}
func cookieValue(r *http.Request) (string, bool) {
	var value string
	found := false
	for _, c := range r.Cookies() {
		if c.Name == sessionCookie {
			if found {
				return "", true
			}
			found = true
			value = c.Value
		}
	}
	return value, found
}
func (h *HTTPAdminServer) browserRequest(r *http.Request, mutation bool) bool {
	if h.agent == nil || h.agent.origin == "" || r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		return false
	}
	origin := r.Header.Get("Origin")
	if (mutation && origin != h.agent.origin) || (origin != "" && origin != h.agent.origin) {
		return false
	}
	if mutation {
		typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || (typ != "application/json" && typ != "application/octet-stream") {
			return false
		}
	}
	return true
}

// scoped retains legacy wrappers when auth is absent. With opt-in auth, a
// Bearer+session combination is rejected, never resolved to a stronger actor.
func (h *HTTPAdminServer) authorizeAgent(next, legacy http.HandlerFunc, required []adminauth.Scope) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.AgentAuthConfigured {
			legacy(w, r)
			return
		}
		if h.agent == nil {
			agentError(w, 503, "auth_unavailable")
			return
		}
		cookie, hasCookie := cookieValue(r)
		hasBearer := len(r.Header.Values("Authorization")) > 0
		if hasCookie && hasBearer {
			agentError(w, 403, "ambiguous_credentials")
			return
		}
		var a adminauth.Actor
		if hasBearer {
			if len(r.Header.Values("Authorization")) != 1 {
				agentError(w, 401, "authentication")
				return
			}
			token, ok := bearerToken(r)
			if !ok {
				agentError(w, 401, "authentication")
				return
			}
			if values := r.Header.Values("X-SecDNS-Legacy-Access"); len(values) > 0 {
				if len(values) != 1 || values[0] != "1" || !h.isLegacyToken(token) {
					agentError(w, 401, "authentication")
					return
				}
				legacy(w, r)
				return
			}
			if h.isLegacyToken(token) || !strings.HasPrefix(token, "sdna_") {
				legacy(w, r)
				return
			}
			id := h.agent.store.Identity()
			var e error
			a, e = h.agent.store.Verify(token, id.RealmID, id.NodeID, h.agent.now())
			if e != nil {
				if e == adminauth.ErrUnavailable {
					agentError(w, 503, "auth_unavailable")
				} else {
					agentError(w, 401, "authentication")
				}
				return
			}
		} else if hasCookie {
			mutation := r.Method != "GET" && r.Method != "HEAD"
			if !h.browserRequest(r, mutation) {
				agentError(w, 403, "origin_or_csrf_required")
				return
			}
			i, e := h.agent.sessions.Authenticate(cookie, r.Header.Get("X-SecDNS-CSRF"), mutation, false, h.agent.now())
			if e != nil {
				authenticationError(w, e)
				return
			}
			a = i.Actor
		} else {
			agentError(w, 401, "authentication")
			return
		}
		for _, scope := range required {
			if !a.Allows(scope) {
				agentError(w, 403, "scope_required")
				return
			}
		}
		if hasCookie && r.Method != "GET" && r.Method != "HEAD" {
			if _, e := h.agent.sessions.Authenticate(cookie, r.Header.Get("X-SecDNS-CSRF"), true, true, h.agent.now()); e != nil {
				authenticationError(w, e)
				return
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), actorKey{}, a))
		next(w, r)
	}
}

// isLegacyToken preserves explicitly configured credentials regardless of prefix.
func (h *HTTPAdminServer) isLegacyToken(token string) bool {
	digest := sha256.Sum256([]byte(token))
	expected := sha256.Sum256([]byte(h.Token))
	found := subtle.ConstantTimeCompare(digest[:], expected[:])
	for _, reader := range h.SnapshotReaders {
		expected = sha256.Sum256([]byte(reader.Token))
		found |= subtle.ConstantTimeCompare(digest[:], expected[:])
	}
	return found == 1
}

// withScopes invokes the original handler directly for verified agents and the
// unchanged legacy wrapper for legacy requests.
func (h *HTTPAdminServer) withScopes(next http.HandlerFunc, reader bool, required ...adminauth.Scope) http.HandlerFunc {
	legacy := h.auth(next)
	if reader {
		legacy = h.readAuth(next)
	}
	return h.authorizeAgent(next, legacy, required)
}

func (h *HTTPAdminServer) agentRoutes(mux *http.ServeMux, base string) {
	mux.HandleFunc("GET "+base+"/auth/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		enabled := h.agent != nil
		secure := enabled && h.agent.origin != ""
		out := map[string]any{"agent_access": secure, "human_access": false, "passkey_access": secure && h.agent != nil && h.agent.passkeys != nil}
		if enabled {
			id := h.agent.store.Identity()
			out["public_origin"] = h.agent.origin
			out["realm_name"] = id.DisplayName
			out["node_id"] = id.NodeID
			if secure && h.agent.store.HumanEnabled() {
				ready, e := h.agent.store.HumanReady()
				if e == nil {
					out["human_access"] = true
					out["setup_required"] = !ready
					if h.TrustedSSO != nil && h.AgentAuthConfigured {
						out["sso_login"] = ready && h.trustedSSOAvailable(r)
					}
				}
			}
		}
		writeJSON(w, 200, out)
	})
	if !h.AgentAuthConfigured {
		return
	}
	h.humanRoutes(mux, base)
	h.passkeyRoutes(mux, base)
	mux.HandleFunc("POST "+base+"/auth/agent-session", func(w http.ResponseWriter, r *http.Request) {
		if h.agent == nil {
			agentError(w, 503, "auth_unavailable")
			return
		}
		if h.agent.origin == "" {
			agentError(w, 403, "secure_origin_required")
			return
		}
		if _, present := cookieValue(r); present {
			agentError(w, 403, "ambiguous_credentials")
			return
		}
		if !h.browserRequest(r, true) || len(r.Header.Values("Authorization")) != 1 {
			agentError(w, 403, "origin_required")
			return
		}
		bearer, ok := bearerToken(r)
		if !ok {
			agentError(w, 401, "authentication")
			return
		}
		id := h.agent.store.Identity()
		// Authenticate before checking body metadata, never read the exchange body.
		a, e := h.agent.store.Verify(bearer, id.RealmID, id.NodeID, h.agent.now())
		if e != nil {
			authenticationError(w, e)
			return
		}
		if !a.Allows(adminauth.UIView) {
			agentError(w, 403, "scope_required")
			return
		}
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			agentError(w, 400, "empty_body_required")
			return
		}
		token, csrf, i, e := h.agent.sessions.Exchange(bearer, id.RealmID, id.NodeID, h.agent.now())
		if e != nil {
			authenticationError(w, e)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(adminauth.SessionLifetime.Seconds())})
		w.Header().Set("Cache-Control", "no-store")
		out := sessionJSON(i)
		out["csrf"] = csrf
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("GET "+base+"/auth/session", func(w http.ResponseWriter, r *http.Request) {
		if h.agent == nil || !h.browserRequest(r, false) || len(r.Header.Values("Authorization")) != 0 {
			agentError(w, 403, "origin_required")
			return
		}
		token, _ := cookieValue(r)
		i, e := h.agent.sessions.Authenticate(token, "", false, false, h.agent.now())
		if e != nil {
			http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
			authenticationError(w, e)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, sessionJSON(i))
	})
	for _, action := range []string{"logout", "activity"} {
		mux.HandleFunc("POST "+base+"/auth/"+action, func(w http.ResponseWriter, r *http.Request) {
			if h.agent == nil || !h.browserRequest(r, true) || len(r.Header.Values("Authorization")) != 0 {
				agentError(w, 403, "origin_required")
				return
			}
			token, _ := cookieValue(r)
			csrf := r.Header.Get("X-SecDNS-CSRF")
			if _, e := h.agent.sessions.Authenticate(token, csrf, true, false, h.agent.now()); e != nil {
				authenticationError(w, e)
				return
			}
			if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				agentError(w, 400, "empty_body_required")
				return
			}
			if action == "activity" {
				if _, e := h.agent.sessions.Authenticate(token, csrf, true, true, h.agent.now()); e != nil {
					agentError(w, 401, "authentication")
					return
				}
			}
			if action == "logout" {
				e := h.agent.sessions.Logout(token, csrf, h.agent.now())
				http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
				if e != nil {
					agentError(w, 503, "auth_unavailable")
					return
				}
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, map[string]bool{"ok": true})
		})
	}
}
