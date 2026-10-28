package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhouchenh/secDNS/internal/adminauth"
)

func trustedSSOConfigFixture(t *testing.T) (map[string]any, string) {
	t.Helper()
	raw, _, def := authFixture(t)
	raw["defaultResolver"] = map[string]any{"type": "authoritative", "config": map[string]any{}}
	secret := filepath.Join(t.TempDir(), "sso-header-secret")
	if e := os.WriteFile(secret, []byte(strings.Repeat("s", 64)+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	listener := raw["listeners"].([]any)[0].(map[string]any)
	listener["type"] = "httpAdminServer"
	listener["config"] = map[string]any{
		"listen": "127.0.0.1", "port": 19054, "path": "/admin", "token": "synthetic-local-token", "ui": true,
		"recordAuthorityURL": "http://127.0.0.1:18055/owned-static", "recordAuthorityToken": strings.Repeat("x", 32),
		"trustedProxySources": []any{"127.0.0.1"},
		"trustedSSO": map[string]any{
			"headerSecretFile": filepath.ToSlash(secret),
			"secretHeader":     "X-Secdns-SSO-Secret",
			"userHeader":       "X-Secdns-SSO-User",
			"rolesHeader":      "X-Secdns-SSO-Roles",
			"requiredRole":     "secdns-console:access",
			"allowedUsers":     []any{"owner"},
			"mapsTo":           "owner",
		},
	}
	if e := adminauth.CreateKey(def.KeyPath); e != nil {
		t.Fatal(e)
	}
	s, e := adminauth.Create(def.Path, def.KeyPath, def.Identity(), nil)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	return raw, secret
}

func TestTrustedSSOLoadedConfig(t *testing.T) {
	raw, _ := trustedSSOConfigFixture(t)
	encoded, _ := json.Marshal(raw)
	if e := ValidateConfig(bytes.NewReader(encoded)); e != nil {
		t.Fatal(e)
	}
	instance, e := LoadConfig(bytes.NewReader(encoded))
	if e != nil {
		t.Fatal(e)
	}
	ai, ok := instance.(*authInstance)
	if !ok || len(ai.bindings) != 1 {
		t.Fatal("auth binding lost")
	}
	sso := ai.bindings[0].server.TrustedSSO
	if sso == nil || sso.UserHeader != "X-Secdns-Sso-User" || sso.RequiredRole != "secdns-console:access" || len(sso.AllowedUsers) != 1 || sso.MapsTo != "owner" {
		t.Fatal("descriptor dropped trustedSSO")
	}
	if got := sso.String(); got != "server.TrustedSSO[redacted]" {
		t.Fatalf("trustedSSO printed %q", got)
	}
}

func TestTrustedSSOConfigRefusals(t *testing.T) {
	for _, kind := range []string{
		"no-origin", "no-auth", "no-proxy", "non-loopback-proxy", "missing-key", "extra-key", "bad-prefix", "same-header",
		"relative-path", "unclean-path", "maps-to", "no-users", "duplicate-user", "user-comma", "user-space", "role-comma",
		"too-many-users", "not-object", "null", "secret-missing", "secret-group-readable", "secret-short", "secret-control",
		"secret-symlink", "secret-directory", "duplicate-block", "duplicate-field",
	} {
		t.Run(kind, func(t *testing.T) {
			raw, secret := trustedSSOConfigFixture(t)
			l := raw["listeners"].([]any)[0].(map[string]any)
			c := l["config"].(map[string]any)
			sso := c["trustedSSO"].(map[string]any)
			switch kind {
			case "no-origin":
				delete(l, "publicOrigin")
			case "no-auth":
				delete(l, "authStore")
				delete(l, "publicOrigin")
				delete(raw, "adminAuthStores")
				delete(c, "recordAuthorityURL")
				delete(c, "recordAuthorityToken")
				delete(c, "trustedProxySources")
			case "no-proxy":
				delete(c, "trustedProxySources")
			case "non-loopback-proxy":
				c["trustedProxySources"] = []any{"192.0.2.10"}
			case "missing-key":
				delete(sso, "rolesHeader")
			case "extra-key":
				sso["allowAll"] = true
			case "bad-prefix":
				sso["userHeader"] = "X-Forwarded-User"
			case "same-header":
				sso["rolesHeader"] = "x-secdns-sso-user"
			case "relative-path":
				sso["headerSecretFile"] = "sso-header-secret"
			case "unclean-path":
				sso["headerSecretFile"] = filepath.ToSlash(filepath.Dir(secret)) + "/./sso-header-secret"
			case "maps-to":
				sso["mapsTo"] = "agent"
			case "no-users":
				sso["allowedUsers"] = []any{}
			case "duplicate-user":
				sso["allowedUsers"] = []any{"owner", "owner"}
			case "user-comma":
				sso["allowedUsers"] = []any{"owner,other"}
			case "user-space":
				sso["allowedUsers"] = []any{" owner"}
			case "role-comma":
				sso["requiredRole"] = "a,b"
			case "too-many-users":
				sso["allowedUsers"] = []any{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
			case "not-object":
				c["trustedSSO"] = "on"
			case "null":
				c["trustedSSO"] = nil
			case "secret-missing":
				os.Remove(secret)
			case "secret-group-readable":
				if e := os.Chmod(secret, 0640); e != nil {
					t.Fatal(e)
				}
			case "secret-short":
				os.WriteFile(secret, []byte(strings.Repeat("s", 31)), 0600)
			case "secret-control":
				os.WriteFile(secret, []byte(strings.Repeat("s", 40)+"\x00"+strings.Repeat("s", 10)), 0600)
			case "secret-symlink":
				link := secret + ".link"
				if e := os.Symlink(secret, link); e != nil {
					t.Skip("symlinks unavailable")
				}
				sso["headerSecretFile"] = filepath.ToSlash(link)
			case "secret-directory":
				sso["headerSecretFile"] = filepath.ToSlash(filepath.Dir(secret))
			}
			b, _ := json.Marshal(raw)
			switch kind {
			case "duplicate-block":
				b = bytes.Replace(b, []byte(`"trustedSSO":`), []byte(`"trustedSSO":{},"trustedSSO":`), 1)
			case "duplicate-field":
				b = bytes.Replace(b, []byte(`"mapsTo":"owner"`), []byte(`"mapsTo":"owner","mapsTo":"owner"`), 1)
			}
			if ValidateConfig(bytes.NewReader(b)) == nil {
				t.Fatal("invalid trustedSSO accepted by -test validation")
			}
			if _, e := LoadConfig(bytes.NewReader(b)); e == nil {
				t.Fatal("invalid trustedSSO accepted at load")
			}
		})
	}
}
