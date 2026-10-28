package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/zhouchenh/secDNS/internal/adminauth"
)

// Authentication inputs are bounded, exact JSON objects; duplicate fields and
// unknown fields are refused before calling password or authenticator code.
func humanBody(w http.ResponseWriter, r *http.Request, fields ...string) (map[string]string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, adminauth.ErrInvalid
	}
	out := map[string]string{}
	allowed := map[string]bool{}
	for _, k := range fields {
		allowed[k] = true
	}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		if e != nil || !ok || !allowed[k] {
			return nil, adminauth.ErrInvalid
		}
		if _, exists := out[k]; exists {
			return nil, adminauth.ErrInvalid
		}
		var v string
		if d.Decode(&v) != nil || len(v) > 4096 {
			return nil, adminauth.ErrInvalid
		}
		out[k] = v
	}
	if _, e = d.Token(); e != nil {
		return nil, adminauth.ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, adminauth.ErrInvalid
	}
	if len(out) != len(fields) {
		return nil, adminauth.ErrInvalid
	}
	return out, nil
}
func socketSource(r *http.Request) (netip.Addr, bool) {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return netip.Addr{}, false
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func singleForwardedHeader(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", false
	}
	return values[0], true
}

func forwardedAddress(r *http.Request, name string) (netip.Addr, bool) {
	raw, ok := singleForwardedHeader(r, name)
	if !ok {
		return netip.Addr{}, false
	}
	ip, e := netip.ParseAddr(raw)
	if e != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func (h *HTTPAdminServer) trustedSocketSource(ip netip.Addr) bool {
	for _, trusted := range h.TrustedProxySources {
		if ip == trusted {
			return true
		}
	}
	return false
}

// humanSource uses forwarded identity only for an explicitly configured socket
// peer and only when the complete Facade metadata tuple is singular and
// internally consistent. A malformed tuple from a trusted peer fails closed.
func (h *HTTPAdminServer) humanSource(r *http.Request) string {
	socket, ok := socketSource(r)
	if !ok {
		return ""
	}
	if !h.trustedSocketSource(socket) {
		return socket.String()
	}
	if h.agent == nil || h.agent.origin == "" {
		return ""
	}
	origin, e := url.Parse(h.agent.origin)
	if e != nil || origin.Scheme != "https" || origin.Host == "" || r.Host != origin.Host {
		return ""
	}
	port := origin.Port()
	if port == "" {
		port = "443"
	}
	proto, protoOK := singleForwardedHeader(r, "X-Forwarded-Proto")
	host, hostOK := singleForwardedHeader(r, "X-Forwarded-Host")
	forwardedPort, portOK := singleForwardedHeader(r, "X-Forwarded-Port")
	forwarded, forwardedOK := forwardedAddress(r, "X-Forwarded-For")
	real, realOK := forwardedAddress(r, "X-Real-IP")
	if !protoOK || proto != "https" || !hostOK || host != origin.Host || !portOK || forwardedPort != port || !forwardedOK || !realOK || forwarded != real {
		return ""
	}
	return forwarded.String()
}
func (h *HTTPAdminServer) humanRoutes(mux *http.ServeMux, base string) {
	h.humanSecurityRoutes(mux, base)
	public := func(fields []string, fn func(http.ResponseWriter, *http.Request, map[string]string, string, time.Time)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if h.agent == nil || !h.agent.store.HumanEnabled() {
				agentError(w, 503, "auth_unavailable")
				return
			}
			_, cookie := cookieValue(r)
			if cookie || len(r.Header.Values("Authorization")) != 0 {
				agentError(w, 403, "ambiguous_credentials")
				return
			}
			if !h.browserRequest(r, true) {
				agentError(w, 403, "origin_required")
				return
			}
			source := h.humanSource(r)
			if source == "" {
				agentError(w, 403, "authentication")
				return
			}
			body, e := humanBody(w, r, fields...)
			if e != nil {
				agentError(w, 400, "invalid_auth_request")
				return
			}
			defer clear(body)
			fn(w, r, body, source, h.agent.now())
		}
	}
	mux.HandleFunc("POST "+base+"/auth/setup/begin", public([]string{"grant", "username", "name", "password"}, func(w http.ResponseWriter, r *http.Request, b map[string]string, source string, now time.Time) {
		en, e := h.agent.human.BeginEnrollment(b["grant"], b["username"], b["name"], b["password"], source, false, now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		h.writeEnrollment(w, en)
	}))
	mux.HandleFunc("POST "+base+"/auth/recovery/local", public([]string{"grant", "username", "name", "password"}, func(w http.ResponseWriter, r *http.Request, b map[string]string, source string, now time.Time) {
		en, e := h.agent.human.BeginEnrollment(b["grant"], b["username"], b["name"], b["password"], source, true, now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		h.writeEnrollment(w, en)
	}))
	mux.HandleFunc("POST "+base+"/auth/recovery/code", public([]string{"username", "password", "code"}, func(w http.ResponseWriter, r *http.Request, b map[string]string, source string, now time.Time) {
		en, e := h.agent.human.BeginCodeRecovery(b["username"], b["password"], b["code"], source, now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		h.writeEnrollment(w, en)
	}))
	mux.HandleFunc("POST "+base+"/auth/login/password", public([]string{"username", "password"}, func(w http.ResponseWriter, r *http.Request, b map[string]string, source string, now time.Time) {
		challenge, e := h.agent.human.PasswordLogin(b["username"], b["password"], source, now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"challenge": challenge, "expires_at": now.Add(5 * time.Minute)})
	}))
	if h.TrustedSSO != nil {
		mux.HandleFunc("POST "+base+"/auth/login/sso", public([]string{}, h.trustedSSOLogin))
	}
	mux.HandleFunc("POST "+base+"/auth/login/totp", public([]string{"challenge", "code"}, func(w http.ResponseWriter, r *http.Request, b map[string]string, source string, now time.Time) {
		result, e := h.agent.human.Confirm(b["challenge"], b["code"], source, now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: result.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(adminauth.HumanSessionLifetime.Seconds())})
		out := sessionJSON(result.Session)
		if len(result.RecoveryCodes) > 0 {
			out["recovery_codes"] = result.RecoveryCodes
		}
		writeJSON(w, 200, out)
	}))
}

func humanCookie(w http.ResponseWriter, result adminauth.HumanResult) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: result.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(adminauth.HumanSessionLifetime.Seconds())})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, sessionJSON(result.Session))
}
func (h *HTTPAdminServer) humanSecurityRoutes(mux *http.ServeMux, base string) {
	mux.HandleFunc("GET "+base+"/auth/audit", func(w http.ResponseWriter, r *http.Request) {
		if h.agent == nil || !h.browserRequest(r, false) || len(r.Header.Values("Authorization")) != 0 {
			agentError(w, 403, "origin_required")
			return
		}
		token, _ := cookieValue(r)
		i, e := h.agent.sessions.Authenticate(token, "", false, false, h.agent.now())
		if e != nil || i.Actor.Kind() != "human" {
			agentError(w, 403, "human_authentication_required")
			return
		}
		events, e := h.agent.store.AuditLocal(100)
		if e != nil {
			authenticationError(w, e)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"events": events})
	})
	protected := func(recent bool, fields []string, fn func(http.ResponseWriter, *http.Request, map[string]string, string, string, string, time.Time)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if h.agent == nil || !h.browserRequest(r, true) || len(r.Header.Values("Authorization")) != 0 {
				agentError(w, 403, "origin_required")
				return
			}
			source := h.humanSource(r)
			if source == "" {
				agentError(w, 403, "authentication")
				return
			}
			token, _ := cookieValue(r)
			csrf := r.Header.Get("X-SecDNS-CSRF")
			now := h.agent.now()
			i, e := h.agent.sessions.Authenticate(token, csrf, true, false, now)
			if e != nil || i.Actor.Kind() != "human" {
				agentError(w, 403, "human_authentication_required")
				return
			}
			if recent {
				if _, e = h.agent.human.RecentHuman(token, csrf, now); e != nil {
					agentError(w, 403, "recent_authentication_required")
					return
				}
			}
			b, e := humanBody(w, r, fields...)
			if e != nil {
				agentError(w, 400, "invalid_auth_request")
				return
			}
			defer clear(b)
			fn(w, r, b, token, csrf, source, now)
		}
	}
	mux.HandleFunc("POST "+base+"/auth/totp/begin", protected(true, []string{}, func(w http.ResponseWriter, r *http.Request, b map[string]string, token, csrf, source string, now time.Time) {
		en, e := h.agent.human.BeginReplacement(token, csrf, source, now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h.writeEnrollment(w, en)
	}))
	mux.HandleFunc("POST "+base+"/auth/totp/confirm", protected(true, []string{"challenge", "code"}, func(w http.ResponseWriter, r *http.Request, b map[string]string, token, csrf, source string, now time.Time) {
		result, e := h.agent.human.ConfirmReplacement(token, csrf, b["challenge"], b["code"], source, now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: result.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(adminauth.HumanSessionLifetime.Seconds())})
		out := sessionJSON(result.Session)
		out["recovery_codes"] = result.RecoveryCodes
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, out)
	}))

	mux.HandleFunc("POST "+base+"/auth/reauth/password-totp", protected(false, []string{"password", "code"}, func(w http.ResponseWriter, r *http.Request, b map[string]string, token, csrf, source string, now time.Time) {
		result, e := h.agent.human.Reauthenticate(token, csrf, b["password"], b["code"], source, now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		humanCookie(w, result)
	}))
	mux.HandleFunc("POST "+base+"/auth/password", protected(true, []string{"password"}, func(w http.ResponseWriter, r *http.Request, b map[string]string, token, csrf, source string, now time.Time) {
		result, e := h.agent.human.ChangePassword(token, csrf, b["password"], now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		humanCookie(w, result)
	}))
	mux.HandleFunc("POST "+base+"/auth/recovery-codes/regenerate", protected(true, []string{}, func(w http.ResponseWriter, r *http.Request, b map[string]string, token, csrf, source string, now time.Time) {
		codes, e := h.agent.human.RegenerateRecovery(token, csrf, now)
		if e != nil {
			authenticationError(w, e)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"recovery_codes": codes})
	}))
	mux.HandleFunc("POST "+base+"/auth/sessions/revoke-others", protected(true, []string{}, func(w http.ResponseWriter, r *http.Request, b map[string]string, token, csrf, source string, now time.Time) {
		if e := h.agent.human.RevokeOtherSessions(token, csrf, now); e != nil {
			authenticationError(w, e)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
}
