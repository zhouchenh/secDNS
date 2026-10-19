package server

import (
	"context"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthenticatedRouteExpiryBrowser(t *testing.T) {
	if os.Getenv("ADMINAUTH_BROWSER") != "1" {
		t.Skip("opt-in actual cookie-session browser")
	}
	h, token := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead, adminauth.RecordsWrite, adminauth.RouterOSPreview})
	h.UI = true
	h.Path = "/admin"
	h.store = recordstore.New()
	defer h.store.Close()
	h.followerStatusNames = []string{"qa"}
	h.followerStatus = func() []followerObservation { return []followerObservation{} }
	ts := httptest.NewUnstartedServer(h.routes())
	h.agent.origin = "https://" + ts.Listener.Addr().String()
	ts.StartTLS()
	defer ts.Close()
	script, _ := filepath.Abs("../../../../../../scripts/test-authenticated-route-expiry-browser.cjs")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Env = append(os.Environ(), "ROUTE_QA_URL="+ts.URL, "ROUTE_QA_TOKEN="+token)
	out, e := cmd.CombinedOutput()
	t.Log(string(out))
	if e != nil {
		t.Fatal(e)
	}
}
