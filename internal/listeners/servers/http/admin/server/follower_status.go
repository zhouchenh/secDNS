package server

import (
	"errors"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/snapshotfollower"
	"net/http"
	"sort"
	"strconv"
	"time"
)

type followerObservation struct {
	Store            string     `json:"store"`
	NodeID           string     `json:"node_id"`
	RulesetID        string     `json:"ruleset_id"`
	LineageID        string     `json:"lineage_id"`
	AuthorityEpoch   string     `json:"authority_epoch"`
	Accepted         bool       `json:"accepted"`
	Revision         string     `json:"revision"`
	ContentSHA256    string     `json:"content_sha256"`
	LastAccepted     *time.Time `json:"last_accepted_at"`
	LastContact      *time.Time `json:"last_contact_at"`
	Connection       string     `json:"connection"`
	Error            string     `json:"error_category"`
	StoreState       string     `json:"store_state"`
	ContactFreshness string     `json:"contact_freshness"`
}

const followerStaleAfter = 90 * time.Second

func (h *HTTPAdminServer) ConfigureFollowerStatus(names []string) {
	h.followerStatusNames = append([]string(nil), names...)
	sort.Strings(h.followerStatusNames)
}
func (h *HTTPAdminServer) BindFollowerStatus(readers map[string]func() snapshotfollower.Status) error {
	if len(readers) != len(h.followerStatusNames) {
		return errors.New("invalid follower status binding")
	}
	copied := make(map[string]func() snapshotfollower.Status, len(readers))
	for _, name := range h.followerStatusNames {
		if readers[name] == nil {
			return errors.New("invalid follower status binding")
		}
		copied[name] = readers[name]
	}
	h.followerStatus = func() []followerObservation {
		result := make([]followerObservation, 0, len(h.followerStatusNames))
		for _, name := range h.followerStatusNames {
			result = append(result, observeFollower(name, copied[name](), time.Now().UTC()))
		}
		return result
	}
	return nil
}
func observeFollower(name string, s snapshotfollower.Status, now time.Time) followerObservation {
	timeOrNil := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		v := t.UTC()
		return &v
	}
	freshness := "unknown"
	if !s.LastContact.IsZero() && !s.LastContact.After(now) {
		freshness = "recent"
		if now.Sub(s.LastContact) > followerStaleAfter {
			freshness = "stale"
		}
	}
	return followerObservation{name, s.NodeID, s.RulesetID, s.LineageID, s.AuthorityEpoch, s.Ready, strconv.FormatUint(s.Revision, 10), s.ContentSHA256, timeOrNil(s.LastSuccess), timeOrNil(s.LastContact), s.ConnectionState, s.ErrorCategory, s.StoreState, freshness}
}
func (h *HTTPAdminServer) followerRoutes(mux *http.ServeMux, base string) {
	if len(h.followerStatusNames) == 0 {
		return
	}
	mux.HandleFunc("GET "+base+"/followers", h.withScopes(func(w http.ResponseWriter, r *http.Request) {
		if h.followerStatus == nil {
			writeJSON(w, 503, map[string]string{"error": "status_unavailable"})
			return
		}
		writeJSON(w, 200, map[string]any{"observed_at": time.Now().UTC(), "scope": "local_follower_workers", "stale_after_seconds": 90, "followers": h.followerStatus()})
	}, false, adminauth.RecordsRead))
}
func (h *HTTPAdminServer) followerUIRoutes(mux *http.ServeMux, base string) {
	for _, asset := range []struct{ name, kind string }{{"index.html", "text/html"}, {"app.js", "text/javascript"}, {"style.css", "text/css"}} {
		data, e := editorAssets.ReadFile("follower_ui/" + asset.name)
		if e != nil {
			panic(e)
		}
		route := asset.name
		if route == "index.html" {
			route = "{$}"
		}
		mux.HandleFunc("GET "+base+"/ui/followers/"+route, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", asset.kind+"; charset=utf-8")
			_, _ = w.Write(data)
		})
	}
}
