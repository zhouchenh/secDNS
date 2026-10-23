package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real secDNS routes + real Facade apphost transport. Only the node runner is synthetic.
func TestFacadeRealTLS(t *testing.T) {
	helper := os.Getenv("SECDNS_FACADE_HELPER")
	if helper == "" {
		t.Skip("set SECDNS_FACADE_HELPER to built tools/facade-e2e-helper binary")
	}
	h, grant := humanTestServer(t)
	h.agent.origin = "https://secdns.aircloud.pro"
	h.UI = true
	now := time.Now()
	h.agent.now = func() time.Time { return now }
	dir := t.TempDir()
	h.NodeAdapterExecutable = filepath.Join(dir, "fixture.exe")
	h.NodeAdapterScript = filepath.Join(dir, "fixture.py")
	h.NodeAuditDirectory = dir
	v, e := recordstore.OpenVersionedSQLite(filepath.Join(dir, "records.db"), recordstore.Enrollment{RulesetID: "edge", LineageID: "disposable"})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	h.versioned = v
	h.nodeRunner = func(_ context.Context, action, node, id string) (nodeSnapshot, error) {
		return nodeSnapshot{Schema: 1, Node: node, ObservedAt: now, Reachable: true}, nil
	}
	revision := strings.Repeat("a", 64)
	config := nodeBGPFixture("amd103")
	applies := 0
	h.nodeBGPRunner = func(_ context.Context, action, node, id string, raw []byte) (nodeBGPResult, error) {
		out := nodeBGPResult{Schema: 1, Node: node, Revision: revision, Config: config}
		if action == "bgp-validate" {
			out.Valid = true
		}
		if action == "bgp-apply" {
			applies++
			var body nodeBGPRequest
			json.Unmarshal(raw, &body)
			config = body.Config
			revision = strings.Repeat("b", 64)
			out.BGP = &nodeBGPView{revision, config}
			out.Operation = &nodeBGPOperation{RequestID: id, Action: action, Confirmed: true, Status: "confirmed"}
		}
		return out, nil
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable E2E"}, DNSNames: []string{"secdns.aircloud.pro", "backend.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, certPEM, 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600)
	pair, _ := tls.LoadX509KeyPair(certPath, keyPath)
	routes := h.routes()
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "127.0.0.1" || r.Header.Get("X-Real-IP") != "127.0.0.1" || r.Header.Get("X-Forwarded-Proto") != "https" || r.Header.Get("Forwarded") != "" {
			t.Error("forwarding metadata not sanitized")
		}
		routes.ServeHTTP(w, r)
	}))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	backend.StartTLS()
	defer backend.Close()
	start := func(name string) string {
		cfg := filepath.Join(dir, name+".json")
		raw, _ := json.Marshal([]map[string]any{{"host": "secdns.aircloud.pro", "upstream": backend.URL, "tls_server_name": name, "ca_file": certPath, "allow_cidrs": []string{"127.0.0.1/32"}}})
		os.WriteFile(cfg, raw, 0600)
		cmd := exec.Command(helper, cfg, certPath, keyPath)
		stdout, _ := cmd.StdoutPipe()
		cmd.Stderr = os.Stderr
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		scan := bufio.NewScanner(stdout)
		if !scan.Scan() {
			t.Fatal("helper failed")
		}
		return scan.Text()
	}
	address := start("backend.invalid")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	clientFor := func(addr, sni string) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: sni}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}, Timeout: 10 * time.Second}
	}
	client := clientFor(address, "secdns.aircloud.pro")
	var cookie *http.Cookie
	csrf := ""
	request := func(method, path string, body any, status int, origin string, sendCSRF bool) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(body)
		if body == nil {
			raw = nil
		}
		r, _ := http.NewRequest(method, h.agent.origin+path, strings.NewReader(string(raw)))
		r.Header.Set("Origin", origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Forwarded", "for=192.0.2.99")
		r.Header.Set("X-Forwarded-For", "192.0.2.99")
		r.Header.Set("X-Real-IP", "192.0.2.99")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if sendCSRF {
			r.Header.Set("X-SecDNS-CSRF", csrf)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != status {
			t.Fatalf("%s %s got %d want %d: %s", method, path, resp.StatusCode, status, b)
		}
		for _, c := range resp.Cookies() {
			if c.MaxAge < 0 {
				cookie = nil
			} else {
				if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
					t.Fatal("unsafe cookie")
				}
				cookie = c
			}
		}
		var out map[string]any
		json.Unmarshal(b, &out)
		if s, ok := out["csrf"].(string); ok {
			csrf = s
		}
		return out
	}
	request("GET", "/admin/ui/", nil, 200, h.agent.origin, false)
	request("GET", "/admin/ui/app.js", nil, 200, h.agent.origin, false)
	origin := h.agent.origin
	pass := "Disposable E2E password phrase 8573!"
	request("POST", "/admin/auth/setup/begin", map[string]string{"grant": grant, "username": "owner", "name": "Disposable", "password": pass}, 403, "https://wrong.invalid", false)
	enrollment := request("POST", "/admin/auth/setup/begin", map[string]string{"grant": grant, "username": "owner", "name": "Disposable", "password": pass}, 200, origin, false)
	secret := enrollment["secret"].(string)
	request("POST", "/admin/auth/login/totp", map[string]string{"challenge": enrollment["challenge"].(string), "code": nodeTestOTP(secret, now)}, 200, origin, false)
	request("POST", "/admin/auth/logout", nil, 200, origin, true)
	now = now.Add(30 * time.Second)
	challenge := request("POST", "/admin/auth/login/password", map[string]string{"username": "owner", "password": pass}, 200, origin, false)
	if cookie != nil {
		t.Fatal("password alone issued session")
	}
	request("POST", "/admin/auth/login/totp", map[string]string{"challenge": challenge["challenge"].(string), "code": nodeTestOTP(secret, now)}, 200, origin, false)
	request("GET", "/admin/auth/session", nil, 200, origin, false)
	snapshot := request("GET", "/admin/snapshot", nil, 200, origin, false)
	for i, records := range []any{[]any{map[string]any{"name": "edge.invalid.", "type": "A", "values": []string{"192.0.2.1"}, "ttl_seconds": 60}}, []any{map[string]any{"name": "edge.invalid.", "type": "A", "values": []string{"192.0.2.2"}, "ttl_seconds": 120}}, []any{}} {
		body := map[string]any{"expected": map[string]any{"ruleset_id": snapshot["ruleset_id"], "lineage_id": snapshot["lineage_id"], "revision": snapshot["revision"]}, "operation_id": []string{"create", "update", "delete"}[i], "records": records}
		if i == 0 {
			request("POST", "/admin/snapshot", body, 401, origin, false)
		}
		request("POST", "/admin/snapshot", body, 200, origin, true)
		snapshot = request("GET", "/admin/snapshot", nil, 200, origin, false)
		got, _ := json.Marshal(snapshot["records"])
		want, _ := json.Marshal(records)
		if string(got) != string(want) {
			t.Fatalf("record readback mismatch: %s", got)
		}
	}
	request("GET", "/admin/nodes/amd103", nil, 200, origin, false)
	body := nodeBGPRequest{ExpectedRevision: revision, Config: config}
	request("POST", "/admin/nodes/amd103/bgp/preview", body, 403, origin, false)
	request("POST", "/admin/nodes/amd103/bgp/preview", body, 200, origin, true)
	if applies != 0 {
		t.Fatal("preview applied")
	}
	body.RequestID = "55555555-5555-4555-8555-555555555555"
	request("POST", "/admin/nodes/amd103/bgp/apply", body, 200, origin, true)
	request("POST", "/admin/nodes/amd103/bgp/apply", body, 409, origin, true)
	if applies != 1 {
		t.Fatal("apply replay")
	}
	request("POST", "/admin/auth/logout", nil, 200, origin, true)
	request("GET", "/admin/auth/session", nil, 401, origin, false)
	badClient := clientFor(address, "wrong.invalid")
	if resp, err := badClient.Get(origin + "/admin/auth/state"); err == nil {
		resp.Body.Close()
		t.Fatal("invalid edge TLS name accepted")
	}
	client = clientFor(start("wrong.invalid"), "secdns.aircloud.pro")
	request("GET", "/admin/auth/state", nil, 502, origin, false)
	t.Log("PASS: real TLS Facade proxy, secDNS setup + password/TOTP + logout, Secure cookie, CSRF/origin negatives, forged headers, records create/read/update/delete, node status, BGP preview/apply/replay (synthetic node runner), wrong upstream TLS name")
}
