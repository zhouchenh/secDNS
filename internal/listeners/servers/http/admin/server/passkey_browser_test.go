package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPasskeyBrowser(t *testing.T) {
	if os.Getenv("ADMINAUTH_BROWSER") != "1" {
		t.Skip("installed local Chromium only")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path, key := filepath.Join(dir, "auth.db"), filepath.Join(dir, "auth.key")
	id := adminauth.Identity{RealmID: "passkey-test", NodeID: "test-node", DisplayName: "Synthetic realm"}
	if e := adminauth.CreateKey(key); e != nil {
		t.Fatal(e)
	}
	s, e := adminauth.Create(path, key, id, nil)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e = adminauth.EnableHumanSchema(path, key, id, nil); e != nil {
		t.Fatal(e)
	}
	s, e = adminauth.Open(path, key, id, nil)
	if e != nil {
		t.Fatal(e)
	}
	ss := adminauth.NewSessions(s)
	ha := adminauth.NewHumanAuth(s, ss)
	now := time.Now()
	grant, e := s.CreateHumanGrant(false, now)
	if e != nil {
		t.Fatal(e)
	}
	en, e := ha.BeginEnrollment(grant, "owner", "Test owner", "A private phrase with spaces 2091!", "127.0.0.1", false, now)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en.Secret)
	if e != nil {
		t.Fatal(e)
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, seed)
	mac.Write(counter)
	sum := mac.Sum(nil)
	code := fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[int(sum[len(sum)-1]&15):])&0x7fffffff)%1000000)
	if _, e = ha.Confirm(en.Challenge, code, "127.0.0.1", now); e != nil {
		t.Fatal(e)
	}
	ha.Close()
	ss.Close()
	s.Close()
	h := &HTTPAdminServer{Path: "/admin", Token: "synthetic-legacy", UI: true, AgentAuthConfigured: true}
	v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "passkey-browser", LineageID: "synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	h.versioned = v
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.routes().ServeHTTP(w, r) }))
	origin := "https://" + strings.Replace(ts.Listener.Addr().String(), "127.0.0.1", "localhost", 1)
	if e = adminauth.EnablePasskeySchema(path, key, id, nil, origin, "localhost"); e != nil {
		t.Fatal(e)
	}
	s, e = adminauth.Open(path, key, id, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	h.BindAgentAuth(s, origin)
	defer h.ClearAgentAuth()
	if e = h.BindPasskeyAuth("localhost"); e != nil {
		t.Fatal(e)
	}
	// A fixed next TOTP interval avoids replay of setup's code without real waits.
	h.agent.now = func() time.Time { return now.Add(30 * time.Second) }
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	defer ts.Close()
	script, e := filepath.Abs("../../../../../../scripts/test-passkey-browser.cjs")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Env = append(os.Environ(), "PASSKEY_TEST_URL="+origin+"/admin/ui/", "PASSKEY_TEST_SEED="+en.Secret, "PASSKEY_TEST_TIME="+fmt.Sprint(now.Add(30*time.Second).Unix()))
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("passkey browser: %v\n%s", e, out)
	} else {
		t.Log(string(out))
	}
}
