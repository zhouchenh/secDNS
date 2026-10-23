package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	listenerserver "github.com/zhouchenh/secDNS/pkg/listeners/server"
)

const facadeOrigin = "https://secdns.aircloud.pro"

func forwardedRequest(remote, client string) *http.Request {
	r := httptest.NewRequest("POST", facadeOrigin+"/admin/auth/login/password", nil)
	r.RemoteAddr = remote
	r.Header.Set("X-Forwarded-For", client)
	r.Header.Set("X-Real-IP", client)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "secdns.aircloud.pro")
	r.Header.Set("X-Forwarded-Port", "443")
	return r
}

func trustedProxyServer(source string) *HTTPAdminServer {
	return &HTTPAdminServer{
		TrustedProxySources: []netip.Addr{netip.MustParseAddr(source).Unmap()},
		agent:               &agentBinding{origin: facadeOrigin},
	}
}

func setForwardedTuple(r *http.Request, host, client string) {
	r.Header.Set("X-Forwarded-For", client)
	r.Header.Set("X-Real-IP", client)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Port", "443")
}

func TestHumanSourceIgnoresForwardingFromUntrustedPeer(t *testing.T) {
	h := &HTTPAdminServer{agent: &agentBinding{origin: facadeOrigin}}
	r := forwardedRequest("198.51.100.9:49152", "203.0.113.7")
	if got := h.humanSource(r); got != "198.51.100.9" {
		t.Fatalf("untrusted forwarding changed source: %q", got)
	}

	// IPv4-mapped socket addresses have one stable rate-limit identity.
	r.RemoteAddr = "[::ffff:198.51.100.9]:49152"
	if got := h.humanSource(r); got != "198.51.100.9" {
		t.Fatalf("mapped socket source = %q", got)
	}
}

func TestHumanSourceAcceptsCompleteTrustedFacadeTuple(t *testing.T) {
	for _, test := range []struct {
		name     string
		proxy    string
		remote   string
		client   string
		expected string
	}{
		{"ipv4", "127.0.0.1", "127.0.0.1:49152", "203.0.113.7", "203.0.113.7"},
		{"mapped", "127.0.0.1", "[::ffff:127.0.0.1]:49152", "::ffff:203.0.113.7", "203.0.113.7"},
		{"ipv6", "2001:db8::10", "[2001:db8::10]:49152", "2001:db8::77", "2001:db8::77"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := trustedProxyServer(test.proxy)
			if got := h.humanSource(forwardedRequest(test.remote, test.client)); got != test.expected {
				t.Fatalf("source = %q, want %q", got, test.expected)
			}
		})
	}
}

func TestHumanSourceTrustedProxyFailsClosedOnAmbiguousMetadata(t *testing.T) {
	tests := map[string]func(*http.Request){
		"missing forwarded for": func(r *http.Request) { r.Header.Del("X-Forwarded-For") },
		"forwarded chain":       func(r *http.Request) { r.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.2") },
		"duplicate real ip":     func(r *http.Request) { r.Header.Add("X-Real-IP", "203.0.113.7") },
		"mismatched real ip":    func(r *http.Request) { r.Header.Set("X-Real-IP", "203.0.113.8") },
		"wrong proto":           func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") },
		"wrong forwarded host":  func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "other.invalid") },
		"wrong forwarded port":  func(r *http.Request) { r.Header.Set("X-Forwarded-Port", "8443") },
		"wrong authority":       func(r *http.Request) { r.Host = "other.invalid" },
		"unspecified client": func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "0.0.0.0")
			r.Header.Set("X-Real-IP", "0.0.0.0")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			h := trustedProxyServer("127.0.0.1")
			r := forwardedRequest("127.0.0.1:49152", "203.0.113.7")
			mutate(r)
			if got := h.humanSource(r); got != "" {
				t.Fatalf("ambiguous metadata admitted as %q", got)
			}
		})
	}
}

func TestTrustedProxySourcesDescriptor(t *testing.T) {
	descriptor, ok := listenerserver.GetServerDescriptorByTypeName("httpAdminServer")
	if !ok {
		t.Fatal("listener descriptor missing")
	}
	decode := func(raw string) (*HTTPAdminServer, bool) {
		var config any
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			t.Fatal(err)
		}
		value, successes, failures := descriptor.Describe(config)
		h, typed := value.(*HTTPAdminServer)
		return h, typed && successes > 0 && failures == 0
	}
	h, ok := decode(`{"trustedProxySources":["127.0.0.1","::ffff:192.0.2.10"]}`)
	if !ok || len(h.TrustedProxySources) != 2 || h.TrustedProxySources[1].String() != "192.0.2.10" {
		t.Fatalf("trusted sources lost: %+v, ok=%v", h.TrustedProxySources, ok)
	}
	for _, raw := range []string{
		`{"trustedProxySources":[]}`,
		`{"trustedProxySources":["127.0.0.1","::ffff:127.0.0.1"]}`,
		`{"trustedProxySources":["0.0.0.0"]}`,
		`{"trustedProxySources":["127.0.0.0/8"]}`,
		`{"trustedProxySources":[" 127.0.0.1"]}`,
	} {
		if _, ok := decode(raw); ok {
			t.Fatalf("invalid trusted sources admitted: %s", raw)
		}
	}
}

func TestPublicHumanLoginRefusesMalformedTrustedProxyTupleBeforeBody(t *testing.T) {
	h, _ := humanTestServer(t)
	h.TrustedProxySources = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	r := httptest.NewRequest("POST", "https://example.invalid/admin/auth/login/password", noRead{t})
	r.RemoteAddr = "127.0.0.1:49152"
	r.Header.Set("Origin", h.agent.origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	if w.Code != 403 || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("malformed trusted tuple response = %d %s", w.Code, w.Body.String())
	}
}

func TestPublicHumanLoginDoesNotTrustUnlistedForwarder(t *testing.T) {
	h, _ := humanTestServer(t)
	h.TrustedProxySources = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	r := httptest.NewRequest("POST", "https://example.invalid/admin/auth/login/password", strings.NewReader(`{}`))
	r.RemoteAddr = "198.51.100.9:49152"
	r.Header.Set("Origin", h.agent.origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	setForwardedTuple(r, "example.invalid", "203.0.113.7")
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("unlisted peer did not retain direct-source behavior: %d %s", w.Code, w.Body.String())
	}
}

func TestProtectedTOTPRefusesMalformedTrustedProxyTupleBeforeSecret(t *testing.T) {
	h, session := nodeTestSetup(t)
	h.TrustedProxySources = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	request := func(body httpBody) *http.Request {
		r := httptest.NewRequest("POST", "https://example.invalid/admin/auth/totp/begin", body)
		r.RemoteAddr = "127.0.0.1:49152"
		r.Header.Set("Origin", h.agent.origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-SecDNS-CSRF", session.Session.CSRF)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: session.Token})
		return r
	}
	r := request(noRead{t})
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	if w.Code != 403 || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "otpauth") {
		t.Fatalf("malformed trusted tuple exposed enrollment: %d %s", w.Code, w.Body.String())
	}

	r = request(strings.NewReader(`{}`))
	setForwardedTuple(r, "example.invalid", "127.0.0.1")
	w = httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("complete trusted tuple did not preserve TOTP flow: %d %s", w.Code, w.Body.String())
	}
}

type httpBody interface {
	Read([]byte) (int, error)
}
