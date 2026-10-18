package server

import (
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"io"
	"net/http"
)

func (h *HTTPAdminServer) BindPasskeyAuth(rp string) error {
	if h.agent == nil {
		return adminauth.ErrInvalid
	}
	p, e := adminauth.NewPasskeyAuth(h.agent.human, h.agent.origin, rp)
	if e != nil {
		return e
	}
	h.agent.passkeys = p
	return nil
}
func passkeyBody(w http.ResponseWriter, r *http.Request, fields []string) (map[string]json.RawMessage, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, adminauth.ErrInvalid
	}
	allowed := map[string]bool{}
	for _, k := range fields {
		allowed[k] = true
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		if e != nil || !ok || !allowed[k] || out[k] != nil {
			return nil, adminauth.ErrInvalid
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, adminauth.ErrInvalid
		}
		out[k] = v
	}
	if _, e = d.Token(); e != nil || len(out) != len(fields) {
		return nil, adminauth.ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, adminauth.ErrInvalid
	}
	return out, nil
}
func passkeyString(b map[string]json.RawMessage, k string) string {
	var s string
	if json.Unmarshal(b[k], &s) != nil || len(s) > 2048 {
		return ""
	}
	return s
}
func (h *HTTPAdminServer) passkeyRoutes(mux *http.ServeMux, base string) {
	type endpoint struct {
		path              string
		protected, recent bool
		fields            []string
	}
	for _, ep := range []endpoint{
		{"register/begin", true, true, []string{"name"}}, {"register/finish", true, true, []string{"challenge", "response"}},
		{"login/begin", false, false, []string{}}, {"login/finish", false, false, []string{"challenge", "response"}},
		{"reauth/begin", true, false, []string{}}, {"reauth/finish", true, false, []string{"challenge", "response"}},
		{"list", true, true, []string{}}, {"rename", true, true, []string{"id", "name"}}, {"remove", true, true, []string{"id"}},
	} {
		mux.HandleFunc("POST "+base+"/auth/passkeys/"+ep.path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if h.agent == nil || h.agent.passkeys == nil {
				agentError(w, 503, "auth_unavailable")
				return
			}
			if len(r.Header.Values("Authorization")) != 0 || !h.browserRequest(r, true) {
				agentError(w, 403, "origin_required")
				return
			}
			token, cookie := cookieValue(r)
			csrf := r.Header.Get("X-SecDNS-CSRF")
			now := h.agent.now()
			source := humanSource(r)
			if source == "" {
				agentError(w, 403, "authentication")
				return
			}
			if ep.protected {
				i, e := h.agent.sessions.Authenticate(token, csrf, true, false, now)
				if e != nil || i.Actor.Kind() != "human" {
					agentError(w, 403, "human_authentication_required")
					return
				}
				if ep.recent {
					if _, e = h.agent.human.RecentHuman(token, csrf, now); e != nil {
						agentError(w, 403, "recent_authentication_required")
						return
					}
				}
			} else if cookie {
				agentError(w, 403, "ambiguous_credentials")
				return
			}
			b, e := passkeyBody(w, r, ep.fields)
			if e != nil {
				agentError(w, 400, "invalid_auth_request")
				return
			}
			defer clear(b)
			var result any = map[string]bool{"ok": true}
			switch ep.path {
			case "register/begin":
				result, e = h.agent.passkeys.BeginRegistration(token, csrf, passkeyString(b, "name"), source, now)
			case "register/finish":
				e = h.agent.passkeys.FinishRegistration(token, csrf, passkeyString(b, "challenge"), source, b["response"], now)
			case "login/begin", "reauth/begin":
				result, e = h.agent.passkeys.BeginLogin(token, csrf, source, ep.protected, now)
			case "login/finish", "reauth/finish":
				var human adminauth.HumanResult
				human, e = h.agent.passkeys.FinishLogin(token, csrf, passkeyString(b, "challenge"), source, ep.protected, b["response"], now)
				if e == nil {
					humanCookie(w, human)
					return
				}
			case "list":
				var list []adminauth.PasskeyInfo
				list, e = h.agent.human.Passkeys(token, csrf, now)
				result = map[string]any{"passkeys": list}
			case "rename":
				e = h.agent.human.RenamePasskey(token, csrf, passkeyString(b, "id"), passkeyString(b, "name"), now)
			case "remove":
				e = h.agent.human.RemovePasskey(token, csrf, passkeyString(b, "id"), now)
				if e == nil {
					http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
					result = map[string]bool{"signed_out": true}
				}
			}
			if e != nil {
				authenticationError(w, e)
				return
			}
			writeJSON(w, 200, result)
		})
	}
}
