package server

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/sourcepolicy"
)

const explainAt = "2026-10-18T00:00:00Z"

type explainResolverSpy struct {
	selector     *sourcepolicy.Selector
	resolveCalls atomic.Int32
}

func (spy *explainResolverSpy) Select(role string, peer netip.Addr, at time.Time) (sourcepolicy.Decision, error) {
	return spy.selector.Select(role, peer, at)
}

// Resolve deliberately exists on the same object handed to the HTTP server.
// The explain handler receives it only through sourcepolicy.Explainer and must
// never use this DNS-resolution surface.
func (spy *explainResolverSpy) Resolve(*dns.Msg, int) (*dns.Msg, error) {
	spy.resolveCalls.Add(1)
	return nil, nil
}

func newExplainServer(t *testing.T) (*HTTPAdminServer, *explainResolverSpy) {
	t.Helper()
	expires := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	selector, err := sourcepolicy.Compile(sourcepolicy.Definition{
		SourceSets: []sourcepolicy.SourceSet{{
			ID: "regional-clients",
			Members: []sourcepolicy.Member{{
				Prefix: netip.MustParsePrefix("192.0.2.0/24"), ExpiresAt: expires,
			}},
		}},
		Rules: []sourcepolicy.Rule{{
			ListenerRole: "normal", SourceSetID: "regional-clients", ResolverPolicyID: "regional",
		}},
		Defaults:          []sourcepolicy.RoleDefault{{ListenerRole: "normal", ResolverPolicyID: "ordinary"}},
		ResolverPolicyIDs: []string{"ordinary", "regional"},
	})
	if err != nil {
		t.Fatal(err)
	}
	spy := &explainResolverSpy{selector: selector}
	h := &HTTPAdminServer{Token: testToken, SourcePolicyExplain: true}
	if !h.BindSourcePolicySelector(spy) {
		t.Fatal("bind selector")
	}
	return h, spy
}

func explainBody(role, clientIP, at string) string {
	raw, _ := json.Marshal(map[string]string{"listener_role": role, "client_ip": clientIP, "at": at})
	return string(raw)
}

func TestSourcePolicyExplainDisabledAndUnbound(t *testing.T) {
	disabled := &HTTPAdminServer{Token: testToken}
	if response := do(disabled, http.MethodPost, "/admin/source-policy/explain", testToken, explainBody("normal", "192.0.2.1", explainAt)); response.Code != http.StatusNotFound {
		t.Fatalf("disabled endpoint = %d, want 404", response.Code)
	}
	if disabled.BindSourcePolicySelector(mustExplainSelector(t)) {
		t.Fatal("disabled server accepted selector binding")
	}

	unbound := &HTTPAdminServer{Token: testToken, SourcePolicyExplain: true}
	response := do(unbound, http.MethodPost, "/admin/source-policy/explain", testToken, explainBody("normal", "192.0.2.1", explainAt))
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"source_policy_explain_unavailable\"}\n" {
		t.Fatalf("unbound endpoint = %d %q", response.Code, response.Body.String())
	}
}

func TestSourcePolicyExplainUsesExistingAuthenticationBeforeReadingBody(t *testing.T) {
	h, _ := newExplainServer(t)
	for _, test := range []struct {
		token string
		want  int
	}{{"", http.StatusUnauthorized}, {"wrong", http.StatusForbidden}} {
		response := do(h, http.MethodPost, "/admin/source-policy/explain", test.token, strings.Repeat("x", maxSourcePolicyExplainBodyBytes+1))
		if response.Code != test.want {
			t.Fatalf("token %q = %d, want %d", test.token, response.Code, test.want)
		}
	}
}

func TestSourcePolicyExplainStrictBoundedRequest(t *testing.T) {
	h, _ := newExplainServer(t)
	cases := []string{
		"",
		"[]",
		`{"listener_role":"normal","client_ip":"192.0.2.1"}`,
		`{"listener_role":"normal","client_ip":"192.0.2.1","at":"2026-10-18T00:00:00Z","extra":true}`,
		`{"listener_role":"normal","listener_role":"normal","client_ip":"192.0.2.1","at":"2026-10-18T00:00:00Z"}`,
		`{"listener_role":"normal","client_ip":42,"at":"2026-10-18T00:00:00Z"}`,
		explainBody("", "192.0.2.1", explainAt),
		explainBody("normal", " 192.0.2.1", explainAt),
		explainBody("normal", "fe80::1%eth0", explainAt),
		explainBody("normal", "192.0.2.1", ""),
		explainBody("normal", "192.0.2.1", "0001-01-01T00:00:00Z"),
		explainBody("normal", "192.0.2.1", "0001-01-01T00:00:00+14:00"),
		explainBody("normal", "192.0.2.1", "9999-12-31T23:59:59-14:00"),
		explainBody("normal", "192.0.2.1", explainAt) + `{}`,
	}
	for index, body := range cases {
		response := do(h, http.MethodPost, "/admin/source-policy/explain", testToken, body)
		if response.Code != http.StatusBadRequest || response.Body.String() != "{\"error\":\"source_policy_explain_invalid_request\"}\n" {
			t.Fatalf("case %d = %d %q", index, response.Code, response.Body.String())
		}
	}

	oversized := `{"listener_role":"normal","client_ip":"` + strings.Repeat("1", maxSourcePolicyExplainBodyBytes) + `","at":"` + explainAt + `"}`
	response := do(h, http.MethodPost, "/admin/source-policy/explain", testToken, oversized)
	if response.Code != http.StatusRequestEntityTooLarge || response.Body.String() != "{\"error\":\"source_policy_explain_too_large\"}\n" {
		t.Fatalf("oversized = %d %q", response.Code, response.Body.String())
	}
}

func TestSourcePolicyExplainUnknownRole(t *testing.T) {
	h, _ := newExplainServer(t)
	response := do(h, http.MethodPost, "/admin/source-policy/explain", testToken, explainBody("missing", "192.0.2.1", explainAt))
	if response.Code != http.StatusBadRequest || response.Body.String() != "{\"error\":\"source_policy_explain_unknown_role\"}\n" {
		t.Fatalf("unknown role = %d %q", response.Code, response.Body.String())
	}
}

func TestSourcePolicyExplainMatchDefaultExpiryAndNoResolverCall(t *testing.T) {
	h, spy := newExplainServer(t)
	tests := []struct {
		name        string
		clientIP    string
		at          string
		resolver    string
		sourceSet   string
		ruleIndex   int
		reason      string
		canonicalIP string
	}{
		{"match", "::ffff:192.0.2.10", explainAt, "regional", "regional-clients", 0, "matched_rule", "192.0.2.10"},
		{"unmatched", "198.51.100.1", explainAt, "ordinary", "", -1, "explicit_default", "198.51.100.1"},
		{"expired", "192.0.2.10", "2026-10-18T01:00:00Z", "ordinary", "", -1, "explicit_default", "192.0.2.10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := do(h, http.MethodPost, "/admin/source-policy/explain", testToken, explainBody("normal", test.clientIP, test.at))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d %s", response.Code, response.Body.String())
			}
			var got sourcePolicyExplainResponse
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Schema != sourcePolicyExplainSchema || got.Evaluation != "diagnostic_preview" || got.PolicyFingerprint != spy.selector.FingerprintHex() || got.ListenerRole != "normal" || got.ClientIP != test.canonicalIP || got.Resolver != test.resolver || got.SourceSet != test.sourceSet || got.RuleIndex != test.ruleIndex || got.Reason != test.reason {
				t.Fatalf("response = %#v", got)
			}
			if strings.Contains(response.Body.String(), "192.0.2.0/24") {
				t.Fatal("response exposed source-set membership")
			}
		})
	}
	if calls := spy.resolveCalls.Load(); calls != 0 {
		t.Fatalf("offline explain called resolver %d times", calls)
	}
	if h.BindSourcePolicySelector(spy) {
		t.Fatal("server accepted selector rebinding")
	}
}

func mustExplainSelector(t *testing.T) *sourcepolicy.Selector {
	t.Helper()
	selector, err := sourcepolicy.Compile(sourcepolicy.Definition{
		Defaults:          []sourcepolicy.RoleDefault{{ListenerRole: "normal", ResolverPolicyID: "ordinary"}},
		ResolverPolicyIDs: []string{"ordinary"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return selector
}
