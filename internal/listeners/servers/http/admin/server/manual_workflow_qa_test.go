package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestManualWorkflowQA is an explicit, bounded loopback-only hands-on fixture.
// All identities, keys, records and credentials are generated for this test.
func TestManualWorkflowQA(t *testing.T) {
	out := os.Getenv("SECDNS_MANUAL_QA_DIR")
	if out == "" {
		t.Skip("manual synthetic QA opt-in")
	}
	if !filepath.IsAbs(out) {
		t.Fatal("absolute new QA directory required")
	}
	if e := os.Mkdir(out, 0700); e != nil {
		t.Fatal(e)
	}
	secret := func() string {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		return hex.EncodeToString(b)
	}
	upstream := &HTTPAdminServer{Path: "/admin", Token: secret(), UI: true}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	db := filepath.Join(dir, "records.db")
	enrollment := recordstore.Enrollment{RulesetID: "workflow-qa", LineageID: "synthetic"}
	v, e := recordstore.OpenVersionedSQLite(db, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	v.Close()
	if e = recordstore.EnableRRsetMutationsSQLite(db, enrollment); e != nil {
		t.Fatal(e)
	}
	v, e = recordstore.OpenVersionedSQLite(db, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	upstream.versioned = v
	records := []recordset.Record{{Name: "gateway.office.invalid.", Type: "A", Values: []string{"192.0.2.1"}, TTLSeconds: 300}, {Name: "printer.office.invalid.", Type: "A", Values: []string{"192.0.2.20"}, TTLSeconds: 60}, {Name: "files.office.invalid.", Type: "AAAA", Values: []string{"2001:db8::20"}, TTLSeconds: 300}, {Name: "docs.office.invalid.", Type: "CNAME", Values: []string{"files.office.invalid."}, TTLSeconds: 300}, {Name: "note.office.invalid.", Type: "TXT", Values: []string{"Synthetic QA record"}, TTLSeconds: 0}}
	if _, e = v.Replace(recordstore.Expected{RulesetID: enrollment.RulesetID, LineageID: enrollment.LineageID, Revision: 1}, "qa-seed", records); e != nil {
		t.Fatal(e)
	}
	remote := httptest.NewServer(upstream.routes())
	defer remote.Close()
	h, grant := humanTestServer(t)
	h.UI = true
	h.RecordAuthorityURL = remote.URL + "/admin"
	h.RecordAuthorityToken = upstream.Token
	if e = h.prepareRecordBinding(); e != nil {
		t.Fatal(e)
	}
	password := secret()
	now := time.Now()
	owner, e := h.agent.human.BeginEnrollment(grant, "qa-owner", "QA administrator", password, "127.0.0.1", false, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.agent.human.Confirm(owner.Challenge, gatewayOTP(t, owner.Secret, now), "127.0.0.1", now); e != nil {
		t.Fatal(e)
	}
	routes := h.routes()
	// Make the disposable identity unmistakable without changing production UI
	// or exposing the synthetic password/seed in public markup.
	portal := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/auth/human.js" {
			routes.ServeHTTP(w, r)
			return
		}
		recorded := httptest.NewRecorder()
		routes.ServeHTTP(recorded, r)
		for name, values := range recorded.Header() {
			w.Header()[name] = values
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(recorded.Code)
		body := strings.ReplaceAll(recorded.Body.String(), "Enter your username and password to continue.", "Disposable QA account: qa-owner. Use the separate synthetic password, not your real account.")
		body = strings.ReplaceAll(body, "Sign in to secDNS", "Sign in to disposable secDNS QA")
		w.Write([]byte(body))
	}))
	h.agent.origin = "https://" + portal.Listener.Addr().String()
	portal.StartTLS()
	defer portal.Close()
	cert, e := x509.ParseCertificate(portal.TLS.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	follower := statusOnlyServer(t)
	if e = follower.prepareRecordBinding(); e != nil {
		t.Fatal(e)
	}
	fs := httptest.NewServer(follower.routes())
	defer fs.Close()
	write := func(name string, value any) {
		b, e := json.MarshalIndent(value, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("synthetic-credentials.private.json", map[string]string{"username": "qa-owner", "password": password, "totp_secret": owner.Secret, "follower_token": follower.Token})
	write("READY.json", map[string]any{"portal_url": portal.URL + "/admin/ui/", "follower_url": fs.URL + "/owned-static/ui/", "tls_spki_sha256_base64": base64.StdEncoding.EncodeToString(spki[:]), "synthetic_only": true, "records": len(records), "started_at": time.Now().UTC(), "stop_file": "STOP", "expires_after_minutes": 90})
	t.Log("Disposable loopback gateway fixture ready; metadata in explicit QA directory")
	deadline := time.NewTimer(90 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			return
		case <-tick.C:
			if _, e := os.Stat(filepath.Join(out, "STOP")); e == nil {
				return
			}
		}
	}
}
