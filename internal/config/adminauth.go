package config

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/core"
	admin "github.com/zhouchenh/secDNS/internal/listeners/servers/http/admin/server"
)

type authBinding struct {
	server     *admin.HTTPAdminServer
	definition adminauth.Definition
	origin     string
	passkeyRP  string
	legacy     []string
}
type authInstance struct {
	core.Instance
	bindings       []authBinding
	followerStatus []followerStatusBinding
}

func (i *authInstance) PrepareAdminAuth() (func() error, error) {
	var stores []*adminauth.Store
	cleanup := func() error {
		var out error
		for _, b := range i.bindings {
			b.server.ClearAgentAuth()
		}
		for _, s := range stores {
			if e := s.Close(); e != nil {
				out = e
			}
		}
		return out
	}
	for _, b := range i.bindings {
		s, e := adminauth.Open(b.definition.Path, b.definition.KeyPath, b.definition.Identity(), b.legacy)
		if e != nil {
			cleanup()
			return nil, adminauth.ErrUnavailable
		}
		stores = append(stores, s)
		b.server.BindAgentAuth(s, b.origin)
		if b.passkeyRP != "" {
			if e := b.server.BindPasskeyAuth(b.passkeyRP); e != nil {
				cleanup()
				return nil, adminauth.ErrUnavailable
			}
		}
	}
	return cleanup, nil
}

func parseAdminBindings(raw interface{}, c *Config) ([]authBinding, error) {
	root, ok := raw.(map[string]interface{})
	if !ok {
		return nil, adminauth.ErrInvalid
	}
	value, present := root["adminAuthStores"]
	defs := map[string]adminauth.Definition{}
	paths := map[string]bool{}
	identities := map[string]bool{}
	if present {
		m, ok := value.(map[string]interface{})
		if !ok || len(m) == 0 || len(m) > 1 {
			return nil, adminauth.ErrInvalid
		}
		for name, v := range m {
			b, e := json.Marshal(v)
			if e != nil {
				return nil, adminauth.ErrInvalid
			}
			var d adminauth.Definition
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if dec.Decode(&d) != nil || d.Validate() != nil || name == "" {
				return nil, adminauth.ErrInvalid
			}
			for _, p := range []string{d.Path, d.KeyPath} {
				k := strings.ToLower(filepath.Clean(p))
				if paths[k] {
					return nil, adminauth.ErrInvalid
				}
				paths[k] = true
			}
			if identities[d.RealmID] {
				return nil, adminauth.ErrInvalid
			}
			identities[d.RealmID] = true
			defs[name] = d
		}
	}
	// Avoid auth paths aliasing configured record databases before any I/O.
	for _, group := range []string{"recordStores", "versionedRecordStores", "followerRecordStores"} {
		if m, ok := root[group].(map[string]interface{}); ok {
			for _, v := range m {
				if p, ok := v.(string); ok && paths[strings.ToLower(filepath.Clean(p))] {
					return nil, adminauth.ErrInvalid
				}
				if cfg, ok := v.(map[string]interface{}); ok {
					if p, ok := cfg["path"].(string); ok && paths[strings.ToLower(filepath.Clean(p))] {
						return nil, adminauth.ErrInvalid
					}
				}
			}
		}
	}
	entries, ok := root["listeners"].([]interface{})
	if !ok {
		return nil, adminauth.ErrInvalid
	}
	var legacy []string
	for _, l := range c.Listeners {
		if h, ok := l.(*admin.HTTPAdminServer); ok {
			legacy = append(legacy, h.Token)
			for _, r := range h.SnapshotReaders {
				legacy = append(legacy, r.Token)
			}
		}
	}
	used := map[string]bool{}
	hosts := map[string]bool{}
	var out []authBinding
	for index, raw := range entries {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, adminauth.ErrInvalid
		}
		var h *admin.HTTPAdminServer
		if index < len(c.Listeners) {
			h, _ = c.Listeners[index].(*admin.HTTPAdminServer)
		}
		name, p := m["authStore"]
		originRaw, op := m["publicOrigin"]
		rpRaw, rpp := m["passkeyRPID"]
		if !p {
			if op || rpp || h != nil && (len(h.TrustedProxySources) != 0 || h.TrustedSSO != nil || h.ListenUnix != "") {
				return nil, adminauth.ErrInvalid
			}
			continue
		}
		if h == nil {
			return nil, adminauth.ErrInvalid
		}
		n, ok := name.(string)
		d, exists := defs[n]
		if !ok || !exists || used[n] {
			return nil, adminauth.ErrInvalid
		}
		origin := ""
		if op {
			origin, ok = originRaw.(string)
			if !ok || origin == "" || adminauth.ValidateOrigin(origin) != nil {
				return nil, adminauth.ErrInvalid
			}
			u, _ := url.Parse(origin)
			if hosts[u.Hostname()] {
				return nil, adminauth.ErrInvalid
			}
			hosts[u.Hostname()] = true
		}
		rp := ""
		if rpp {
			rp, ok = rpRaw.(string)
			if !ok || adminauth.ValidatePasskeyOrigin(origin, rp) != nil {
				return nil, adminauth.ErrInvalid
			}
		}
		if len(h.TrustedProxySources) != 0 && origin == "" {
			return nil, adminauth.ErrInvalid
		}
		// Every unix-socket peer is treated as the edge proxy: that needs the exact origin.
		if h.ListenUnix != "" && (origin == "" || !admin.ValidListenUnixPath(h.ListenUnix)) {
			return nil, adminauth.ErrInvalid
		}
		if h.RecordAuthorityURL != "" && origin == "" {
			return nil, adminauth.ErrInvalid
		}
		// Trusted SSO needs the exact HTTPS origin, a loopback trusted proxy
		// source and a readable private secret before anything is served.
		if h.TrustedSSO != nil && (origin == "" || h.ValidateTrustedSSO() != nil || h.LoadTrustedSSOSecret() != nil) {
			return nil, adminauth.ErrInvalid
		}
		used[n] = true
		h.AgentAuthConfigured = true
		out = append(out, authBinding{h, d, origin, rp, append([]string(nil), legacy...)})
	}
	if len(used) != len(defs) {
		return nil, adminauth.ErrInvalid
	}
	return out, nil
}

// validateAdminAuthSyntax retains legacy parsing outside opt-in auth fields but
// refuses duplicate security bindings before ordinary JSON maps erase them.
func validateAdminAuthSyntax(raw []byte) error {
	root, e := authObject(raw, map[string]bool{"adminAuthStores": true, "listeners": true})
	if e != nil {
		return e
	}
	if defs, ok := root["adminAuthStores"]; ok {
		values, e := authObject(defs, nil)
		if e != nil {
			return e
		}
		for _, value := range values {
			if _, e := authObject(value, nil); e != nil {
				return e
			}
		}
	}
	var listeners []json.RawMessage
	if value, ok := root["listeners"]; ok && json.Unmarshal(value, &listeners) == nil {
		for _, value := range listeners {
			entry, e := authObject(value, map[string]bool{"authStore": true, "publicOrigin": true, "passkeyRPID": true, "config": true})
			if e != nil {
				return e
			}
			if raw, ok := entry["config"]; ok {
				var cfg map[string]json.RawMessage
				if json.Unmarshal(raw, &cfg) == nil {
					if proxyRaw, proxySet := cfg["trustedProxySources"]; proxySet {
						if _, e := authObject(raw, map[string]bool{"trustedProxySources": true}); e != nil {
							return e
						}
						var values []string
						if json.Unmarshal(proxyRaw, &values) != nil || len(values) == 0 || len(values) > 8 {
							return adminauth.ErrInvalid
						}
						seen := map[netip.Addr]bool{}
						for _, raw := range values {
							address, e := netip.ParseAddr(raw)
							if e != nil || raw == "" || strings.TrimSpace(raw) != raw || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
								return adminauth.ErrInvalid
							}
							address = address.Unmap()
							if seen[address] {
								return adminauth.ErrInvalid
							}
							seen[address] = true
						}
					}
					if _, unixSet := cfg["listenUnix"]; unixSet {
						if _, e := authObject(raw, map[string]bool{"listenUnix": true}); e != nil {
							return e
						}
					}
					if ssoRaw, ssoSet := cfg["trustedSSO"]; ssoSet {
						if _, e := authObject(raw, map[string]bool{"trustedSSO": true}); e != nil {
							return e
						}
						fields, e := authObject(ssoRaw, nil)
						if e != nil {
							return e
						}
						var decoded interface{}
						if json.Unmarshal(ssoRaw, &decoded) != nil {
							return adminauth.ErrInvalid
						}
						if _, ok := admin.ParseTrustedSSO(decoded); !ok || len(fields) < 8 || len(fields) > 11 {
							return adminauth.ErrInvalid
						}
					}
					_, urlSet := cfg["recordAuthorityURL"]
					_, tokenSet := cfg["recordAuthorityToken"]
					_, fileSet := cfg["recordAuthorityTokenFile"]
					if urlSet || tokenSet || fileSet {
						if tokenSet == fileSet {
							return adminauth.ErrInvalid
						}
						if _, e := authObject(raw, map[string]bool{"recordAuthorityURL": true, "recordAuthorityToken": true, "recordAuthorityTokenFile": true}); e != nil {
							return e
						}
						credentialKey := "recordAuthorityToken"
						if fileSet {
							credentialKey = "recordAuthorityTokenFile"
						}
						for _, key := range []string{"recordAuthorityURL", credentialKey} {
							var text string
							if json.Unmarshal(cfg[key], &text) != nil || text == "" {
								return adminauth.ErrInvalid
							}
						}
					}
				}
			}
		}
	}
	return nil
}
func authObject(raw []byte, selected map[string]bool) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return nil, adminauth.ErrInvalid
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		token, e = d.Token()
		if e != nil {
			return nil, adminauth.ErrInvalid
		}
		key, ok := token.(string)
		if !ok {
			return nil, adminauth.ErrInvalid
		}
		if _, exists := out[key]; exists && (selected == nil || selected[key]) {
			return nil, adminauth.ErrInvalid
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, adminauth.ErrInvalid
		}
		out[key] = value
	}
	if _, e = d.Token(); e != nil {
		return nil, adminauth.ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, adminauth.ErrInvalid
	}
	return out, nil
}
