package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/authoritative"
)

const testToken = "s3cr3t-token"

func newServer(t *testing.T, storeName string) *HTTPAdminServer {
	t.Helper()
	h := &HTTPAdminServer{Token: testToken, Store: storeName}
	h.store = recordstore.GetOrCreate(storeName)
	return h
}

func do(h *HTTPAdminServer, method, target, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.routes().ServeHTTP(rec, req)
	return rec
}

func TestServeFailsClosedWithoutToken(t *testing.T) {
	h := &HTTPAdminServer{Token: "  "} // blank token
	var got error
	h.Serve(nil, func(err error) { got = err })
	if !errors.Is(got, ErrMissingToken) {
		t.Fatalf("a tokenless admin listener must refuse to serve, got %v", got)
	}
}

func TestAuth(t *testing.T) {
	h := newServer(t, "admin-auth")

	if rec := do(h, http.MethodGet, "/admin/records", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer -> want 401, got %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/admin/records", "wrong", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong bearer -> want 403, got %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/admin/records", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("correct bearer -> want 200, got %d", rec.Code)
	}
}

func TestSetGetDeleteRoundTrip(t *testing.T) {
	h := newServer(t, "admin-rt")

	// POST a TXT record (the ACME shape).
	body := `{"name":"_acme-challenge.example.com","type":"TXT","values":["tok"],"ttl_seconds":60}`
	if rec := do(h, http.MethodPost, "/admin/records", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("POST -> want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if got, ok := h.store.Get("_acme-challenge.example.com", dns.TypeTXT); !ok || got.Values[0] != "tok" {
		t.Fatalf("record not stored: %+v ok=%v", got, ok)
	}

	// GET list shows it.
	rec := do(h, http.MethodGet, "/admin/records", testToken, "")
	var listed struct {
		Records []recordJSON `json:"records"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Records) != 1 || listed.Records[0].Type != "TXT" {
		t.Fatalf("unexpected list: %+v", listed.Records)
	}

	// DELETE it.
	rec = do(h, http.MethodDelete, "/admin/records/_acme-challenge.example.com/TXT", testToken, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"deleted":true`) {
		t.Fatalf("DELETE -> want 200 deleted:true, got %d (%s)", rec.Code, rec.Body.String())
	}
	if _, ok := h.store.Get("_acme-challenge.example.com", dns.TypeTXT); ok {
		t.Fatalf("record still present after delete")
	}
	// Deleting again reports false.
	rec = do(h, http.MethodDelete, "/admin/records/_acme-challenge.example.com/TXT", testToken, "")
	if !strings.Contains(rec.Body.String(), `"deleted":false`) {
		t.Fatalf("second DELETE should report deleted:false, got %s", rec.Body.String())
	}
}

func TestSetValidation(t *testing.T) {
	h := newServer(t, "admin-validate")
	cases := []struct {
		name string
		body string
	}{
		{"bad type", `{"name":"x.example.","type":"MX","values":["1 mail."]}`},
		{"bad A ip", `{"name":"x.example.","type":"A","values":["not-an-ip"]}`},
		{"AAAA given v4", `{"name":"x.example.","type":"AAAA","values":["1.2.3.4"]}`},
		{"empty values", `{"name":"x.example.","type":"TXT","values":[]}`},
		{"bad name", `{"name":"a..b.example.","type":"TXT","values":["v"]}`}, // empty interior label
		{"negative expiry", `{"name":"x.example.","type":"TXT","values":["v"],"expires_in_seconds":-5}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if rec := do(h, http.MethodPost, "/admin/records", testToken, c.body); rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSetExpiryComputed(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	req := setRequest{Name: "x.example.", Type: "TXT", Values: []string{"v"}, ExpiresInSeconds: ptr(int64(1800))}
	rec, err := req.toRecord(now)
	if err != nil {
		t.Fatalf("toRecord: %v", err)
	}
	if want := now.Add(1800 * time.Second); !rec.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", rec.ExpiresAt, want)
	}
	if rec.TTL != 60 {
		t.Fatalf("ttl should default to 60, got %d", rec.TTL)
	}

	// No expires_in_seconds -> no expiry.
	req2 := setRequest{Name: "y.example.", Type: "TXT", Values: []string{"v"}}
	rec2, _ := req2.toRecord(now)
	if !rec2.ExpiresAt.IsZero() {
		t.Fatalf("omitted expiry must leave ExpiresAt zero, got %v", rec2.ExpiresAt)
	}
}

func ptr[T any](v T) *T { return &v }

// TestAdminToResolverIntegration is the cross-component proof: a record POSTed through
// the admin API is answered by an authoritative resolver that names the same store —
// the full ACME DNS-01 shape (the LE validator's TXT query resolves to the token).
func TestAdminToResolverIntegration(t *testing.T) {
	const storeName = "admin-integration"
	h := newServer(t, storeName)

	body := `{"name":"_acme-challenge.example.com","type":"TXT","values":["challenge-token"],"ttl_seconds":60,"expires_in_seconds":1800}`
	if rec := do(h, http.MethodPost, "/admin/records", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("POST failed: %d (%s)", rec.Code, rec.Body.String())
	}

	a := &authoritative.Authoritative{Store: storeName}
	q := new(dns.Msg)
	q.SetQuestion("_acme-challenge.example.com.", dns.TypeTXT)
	resp, err := a.Resolve(q, 4)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("want 1 answer from the shared store, got %d", len(resp.Answer))
	}
	if txt, ok := resp.Answer[0].(*dns.TXT); !ok || txt.Txt[0] != "challenge-token" {
		t.Fatalf("unexpected answer: %+v", resp.Answer[0])
	}

	// After deletion through the API, the resolver returns NXDOMAIN.
	if rec := do(h, http.MethodDelete, "/admin/records/_acme-challenge.example.com/TXT", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("DELETE failed: %d", rec.Code)
	}
	resp2, _ := a.Resolve(q, 4)
	if resp2.Rcode != dns.RcodeNameError {
		t.Fatalf("after delete want NXDOMAIN, got rcode=%d", resp2.Rcode)
	}
}
