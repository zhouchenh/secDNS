package server

import (
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/snapshotfollower"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFollowerStatusAuthorizationAndOptIn(t *testing.T) {
	for _, scopes := range [][]adminauth.Scope{{adminauth.RecordsRead}, {adminauth.UIView}, {adminauth.RecordsWrite}} {
		h, token := agentTestServer(t, scopes)
		h.SnapshotReaders = []SnapshotReader{{"reader", "reader-token-0123456789abcdef-0001"}}
		h.ConfigureFollowerStatus([]string{"allowed"})
		calls := 0
		if e := h.BindFollowerStatus(map[string]func() snapshotfollower.Status{"allowed": func() snapshotfollower.Status {
			calls++
			return snapshotfollower.Status{ConnectionState: "starting", StoreState: "not_ready"}
		}}); e != nil {
			t.Fatal(e)
		}
		for _, value := range []string{"", h.SnapshotReaders[0].Token, token, h.Token} {
			r := httptest.NewRequest("GET", "/admin/followers", nil)
			r.Body = noRead{t}
			if value != "" {
				r.Header.Set("Authorization", "Bearer "+value)
			}
			w := httptest.NewRecorder()
			before := calls
			h.routes().ServeHTTP(w, r)
			allowed := value == h.Token || value == token && scopes[0] == adminauth.RecordsRead
			if allowed && (w.Code != 200 || calls != before+1) {
				t.Fatalf("allowed %d %s", w.Code, w.Body.String())
			}
			if !allowed && (w.Code < 400 || calls != before) {
				t.Fatal("unauthorized observation", w.Code, calls)
			}
			if allowed && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cached status")
			}
		}
	}
	h := &HTTPAdminServer{Token: "secret"}
	r := httptest.NewRequest("GET", "/admin/followers", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("default exposure", w.Code)
	}
	h.ConfigureFollowerStatus([]string{"missing"})
	w = httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("unbound success", w.Code)
	}
	if h.BindFollowerStatus(map[string]func() snapshotfollower.Status{"other": func() snapshotfollower.Status { return snapshotfollower.Status{} }}) == nil {
		t.Fatal("wrong name accepted")
	}
}
func TestFollowerObservationSemantics(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	s := snapshotfollower.Status{Ready: true, Revision: math.MaxUint64, ConnectionState: "backoff", ErrorCategory: "transport", StoreState: "available"}
	row := observeFollower("replica", s, now)
	if row.LastAccepted != nil || row.LastContact != nil || row.ContactFreshness != "unknown" || row.Revision != "18446744073709551615" || !row.Accepted {
		t.Fatal(row)
	}
	s.LastSuccess = now.Add(-time.Hour)
	s.LastContact = now.Add(-time.Minute)
	row = observeFollower("replica", s, now)
	if row.ContactFreshness != "recent" || row.Error != "transport" || row.StoreState != "available" || !row.LastAccepted.Equal(s.LastSuccess) {
		t.Fatal(row)
	}
	s.LastContact = now.Add(-91 * time.Second)
	if observeFollower("replica", s, now).ContactFreshness != "stale" {
		t.Fatal("old contact not stale")
	}
	raw, _ := json.Marshal(row)
	if strings.Contains(string(raw), "AuthorityURL") || strings.Contains(string(raw), "Token") {
		t.Fatal("private fields")
	}
}

func TestFollowerUIRequiresOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		h := &HTTPAdminServer{}
		if enabled {
			h.ConfigureFollowerStatus([]string{"replica"})
		}
		mux := http.NewServeMux()
		h.editorRoutes(mux, "/admin")
		for _, path := range []string{"/admin/ui/followers/", "/admin/ui/followers/app.js"} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if (w.Code == 200) != enabled {
				t.Fatalf("enabled=%v path=%s status=%d", enabled, path, w.Code)
			}
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/admin/ui/", nil))
		if strings.Contains(w.Body.String(), "Local follower status") != enabled {
			t.Fatal("link opt-in mismatch")
		}
	}
}
