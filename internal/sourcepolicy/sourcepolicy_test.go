package sourcepolicy

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSelectUsesOrderedRulesDualStackExpiryAndExplicitDefaults(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	selector := mustCompile(t, Definition{
		ResolverPolicyIDs: []string{"ordinary", "regional", "dns64"},
		SourceSets: []SourceSet{
			{ID: "broad-v4", Members: []Member{{Prefix: mustPrefix("192.0.2.0/24"), ExpiresAt: now.Add(time.Hour)}}},
			{ID: "narrow-v4", Members: []Member{{Prefix: mustPrefix("192.0.2.128/25")}}},
			{ID: "v6", Members: []Member{
				{Prefix: mustPrefix("2001:db8::/32"), ExpiresAt: now.Add(time.Minute)},
				{Prefix: mustPrefix("2001:db8:1::/48"), ExpiresAt: now},
			}},
		},
		Rules: []Rule{
			{ListenerRole: "normal", SourceSetID: "broad-v4", ResolverPolicyID: "regional"},
			{ListenerRole: "normal", SourceSetID: "narrow-v4", ResolverPolicyID: "dns64"},
			{ListenerRole: "dns64", SourceSetID: "v6", ResolverPolicyID: "dns64"},
		},
		Defaults: []RoleDefault{
			{ListenerRole: "normal", ResolverPolicyID: "ordinary"},
			{ListenerRole: "dns64", ResolverPolicyID: "ordinary"},
		},
	})

	tests := []struct {
		name         string
		role         string
		peer         netip.Addr
		at           time.Time
		wantResolver string
		wantSet      string
		wantRule     int
		wantDefault  bool
	}{
		{
			name: "earlier broad rule beats later longer prefix", role: "normal",
			peer: netip.MustParseAddr("192.0.2.200"), at: now,
			wantResolver: "regional", wantSet: "broad-v4", wantRule: 0,
		},
		{
			name: "mapped IPv4 peer is normalized", role: "normal",
			peer: netip.MustParseAddr("::ffff:192.0.2.10"), at: now,
			wantResolver: "regional", wantSet: "broad-v4", wantRule: 0,
		},
		{
			name: "IPv6 live before expiry", role: "dns64",
			peer: netip.MustParseAddr("2001:db8:ffff::1"), at: now.Add(time.Minute - time.Nanosecond),
			wantResolver: "dns64", wantSet: "v6", wantRule: 2,
		},
		{
			name: "expiry boundary is inactive", role: "dns64",
			peer: netip.MustParseAddr("2001:db8:ffff::1"), at: now.Add(time.Minute),
			wantResolver: "ordinary", wantRule: -1, wantDefault: true,
		},
		{
			name: "unmatched peer uses role default", role: "normal",
			peer: netip.MustParseAddr("198.51.100.1"), at: now,
			wantResolver: "ordinary", wantRule: -1, wantDefault: true,
		},
		{
			name: "missing peer uses role default", role: "normal",
			peer: netip.Addr{}, at: now,
			wantResolver: "ordinary", wantRule: -1, wantDefault: true,
		},
		{
			name: "zone-qualified peer uses role default", role: "dns64",
			peer: netip.MustParseAddr("fe80::1%eth0"), at: now,
			wantResolver: "ordinary", wantRule: -1, wantDefault: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := selector.Select(test.role, test.peer, test.at)
			if err != nil {
				t.Fatal(err)
			}
			if decision.ResolverPolicyID != test.wantResolver || decision.SourceSetID != test.wantSet || decision.RuleIndex != test.wantRule || decision.UsedDefault != test.wantDefault {
				t.Fatalf("unexpected decision: %+v", decision)
			}
			if decision.CachePartition.PolicyFingerprint != selector.Fingerprint() || decision.CachePartition.ListenerRole != test.role || decision.CachePartition.ResolverPolicyID != test.wantResolver {
				t.Fatalf("unexpected cache partition: %+v", decision.CachePartition)
			}
		})
	}

	if _, err := selector.Select("unknown", netip.MustParseAddr("192.0.2.1"), now); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("unknown role: %v", err)
	}
	if _, err := selector.Select("normal", netip.MustParseAddr("192.0.2.1"), time.Time{}); !errors.Is(err, ErrInvalidTime) {
		t.Fatalf("zero query time: %v", err)
	}
	for _, invalid := range []time.Time{
		time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("plus14", 14*60*60)),
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("minus14", -14*60*60)),
	} {
		if _, err := selector.Select("normal", netip.MustParseAddr("192.0.2.1"), invalid); !errors.Is(err, ErrInvalidTime) {
			t.Fatalf("out-of-range normalized query time %v: %v", invalid, err)
		}
	}
}

func TestOverlappingContributionsRemainLiveIndependently(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	definition := basicDefinition()
	definition.SourceSets[0].Members = []Member{
		{Prefix: mustPrefix("192.0.2.0/24"), ExpiresAt: now},
		{Prefix: mustPrefix("192.0.2.0/24"), ExpiresAt: now.Add(time.Minute)},
		{Prefix: mustPrefix("192.0.2.128/25"), ExpiresAt: now.Add(2 * time.Minute)},
	}
	selector := mustCompile(t, definition)

	decision, err := selector.Select("normal", netip.MustParseAddr("192.0.2.10"), now)
	if err != nil || decision.UsedDefault {
		t.Fatalf("second contribution was erased: %+v, %v", decision, err)
	}
	decision, err = selector.Select("normal", netip.MustParseAddr("192.0.2.200"), now.Add(time.Minute))
	if err != nil || decision.UsedDefault {
		t.Fatalf("overlapping longer prefix was erased: %+v, %v", decision, err)
	}
	decision, err = selector.Select("normal", netip.MustParseAddr("192.0.2.200"), now.Add(2*time.Minute))
	if err != nil || !decision.UsedDefault {
		t.Fatalf("expired contributions remained live: %+v, %v", decision, err)
	}
}

func TestCompileCanonicalFingerprintAndCallerMutationIsolation(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.FixedZone("offset", 8*60*60))
	input := Definition{
		ResolverPolicyIDs: []string{"regional", "ordinary"},
		SourceSets: []SourceSet{
			{ID: "z-set", Members: []Member{{Prefix: netip.PrefixFrom(netip.MustParseAddr("192.0.2.123"), 24), ExpiresAt: now.Add(time.Hour)}}},
			{ID: "a-set", Members: []Member{{Prefix: mustPrefix("2001:db8::/32")}}},
		},
		Rules:    []Rule{{ListenerRole: "normal", SourceSetID: "z-set", ResolverPolicyID: "regional"}},
		Defaults: []RoleDefault{{ListenerRole: "normal", ResolverPolicyID: "ordinary"}},
	}
	selector := mustCompile(t, input)
	fingerprint := selector.Fingerprint()

	permuted := Definition{
		ResolverPolicyIDs: []string{"ordinary", "regional"},
		SourceSets: []SourceSet{
			{ID: "a-set", Members: []Member{{Prefix: mustPrefix("2001:db8::/32")}}},
			{ID: "z-set", Members: []Member{{Prefix: mustPrefix("192.0.2.0/24"), ExpiresAt: now.Add(time.Hour).UTC()}}},
		},
		Rules:    append([]Rule(nil), input.Rules...),
		Defaults: append([]RoleDefault(nil), input.Defaults...),
	}
	if got := mustCompile(t, permuted).Fingerprint(); got != fingerprint {
		t.Fatalf("semantically equivalent definition changed fingerprint: %x != %x", got, fingerprint)
	}

	input.ResolverPolicyIDs[0] = "changed"
	input.SourceSets[0].ID = "changed"
	input.SourceSets[0].Members[0].Prefix = mustPrefix("203.0.113.0/24")
	input.Rules[0].ResolverPolicyID = "changed"
	input.Defaults[0].ResolverPolicyID = "changed"
	decision, err := selector.Select("normal", netip.MustParseAddr("192.0.2.44"), now.UTC())
	if err != nil || decision.ResolverPolicyID != "regional" || decision.SourceSetID != "z-set" {
		t.Fatalf("caller mutation changed selector: %+v, %v", decision, err)
	}
	if selector.Fingerprint() != fingerprint || len(selector.FingerprintHex()) != sha256HexLength {
		t.Fatal("caller mutation changed fingerprint")
	}

	changed := permuted
	changed.Rules = append([]Rule(nil), permuted.Rules...)
	changed.Rules[0].ResolverPolicyID = "ordinary"
	if got := mustCompile(t, changed).Fingerprint(); got == fingerprint {
		t.Fatal("material selection change did not change fingerprint")
	}
}

const sha256HexLength = 64

func TestCachePartitionSeparatesRoleResolverAndPolicyContent(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	definition := basicDefinition()
	definition.Defaults = append(definition.Defaults, RoleDefault{ListenerRole: "dns64", ResolverPolicyID: "ordinary"})
	first := mustCompile(t, definition)
	normal, err := first.Select("normal", netip.MustParseAddr("198.51.100.1"), now)
	if err != nil {
		t.Fatal(err)
	}
	dns64, err := first.Select("dns64", netip.MustParseAddr("198.51.100.1"), now)
	if err != nil {
		t.Fatal(err)
	}
	if normal.CachePartition == dns64.CachePartition {
		t.Fatal("listener roles shared a cache partition")
	}

	changed := basicDefinition()
	changed.SourceSets[0].Members = append(changed.SourceSets[0].Members, Member{Prefix: mustPrefix("198.51.100.0/24")})
	second := mustCompile(t, changed)
	changedDecision, err := second.Select("normal", netip.MustParseAddr("203.0.113.1"), now)
	if err != nil {
		t.Fatal(err)
	}
	if normal.CachePartition == changedDecision.CachePartition {
		t.Fatal("different policy content shared a cache partition")
	}
}

func TestCompileRejectsMalformedOrDanglingDefinitions(t *testing.T) {
	invalidPrefix := basicDefinition()
	invalidPrefix.SourceSets[0].Members[0].Prefix = netip.Prefix{}
	mappedPrefix := basicDefinition()
	mappedPrefix.SourceSets[0].Members[0].Prefix = mustPrefix("::ffff:192.0.2.0/120")
	badTime := basicDefinition()
	badTime.SourceSets[0].Members[0].ExpiresAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)
	lowOffsetTime := basicDefinition()
	lowOffsetTime.SourceSets[0].Members[0].ExpiresAt = time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("plus14", 14*60*60))
	highOffsetTime := basicDefinition()
	highOffsetTime.SourceSets[0].Members[0].ExpiresAt = time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("minus14", -14*60*60))
	duplicateSet := basicDefinition()
	duplicateSet.SourceSets = append(duplicateSet.SourceSets, duplicateSet.SourceSets[0])
	duplicateResolver := basicDefinition()
	duplicateResolver.ResolverPolicyIDs = append(duplicateResolver.ResolverPolicyIDs, "ordinary")
	duplicateDefault := basicDefinition()
	duplicateDefault.Defaults = append(duplicateDefault.Defaults, duplicateDefault.Defaults[0])
	badID := basicDefinition()
	badID.SourceSets[0].ID = strings.Repeat("a", MaxIDBytes+1)
	unknownSet := basicDefinition()
	unknownSet.Rules[0].SourceSetID = "missing"
	unknownResolver := basicDefinition()
	unknownResolver.Rules[0].ResolverPolicyID = "missing"
	unknownDefaultResolver := basicDefinition()
	unknownDefaultResolver.Defaults[0].ResolverPolicyID = "missing"
	missingRoleDefault := basicDefinition()
	missingRoleDefault.Rules[0].ListenerRole = "dns64"

	tests := []struct {
		name       string
		definition Definition
		want       error
	}{
		{"empty", Definition{}, ErrInvalid},
		{"invalid prefix", invalidPrefix, ErrInvalid},
		{"mapped IPv4 prefix", mappedPrefix, ErrInvalid},
		{"invalid expiry", badTime, ErrInvalid},
		{"expiry normalizes below year one", lowOffsetTime, ErrInvalid},
		{"expiry normalizes above year 9999", highOffsetTime, ErrInvalid},
		{"duplicate set", duplicateSet, ErrInvalid},
		{"duplicate resolver", duplicateResolver, ErrInvalid},
		{"duplicate default", duplicateDefault, ErrInvalid},
		{"bad identifier", badID, ErrInvalid},
		{"unknown set", unknownSet, ErrReference},
		{"unknown rule resolver", unknownResolver, ErrReference},
		{"unknown default resolver", unknownDefaultResolver, ErrReference},
		{"missing role default", missingRoleDefault, ErrReference},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Compile(test.definition); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestCompileLimits(t *testing.T) {
	tests := []struct {
		name       string
		definition Definition
	}{
		{"source sets", Definition{SourceSets: make([]SourceSet, MaxSourceSets+1)}},
		{"members", Definition{SourceSets: []SourceSet{{ID: "set", Members: make([]Member, MaxMembers+1)}}, Defaults: []RoleDefault{{ListenerRole: "normal", ResolverPolicyID: "ordinary"}}, ResolverPolicyIDs: []string{"ordinary"}}},
		{"rules", Definition{Rules: make([]Rule, MaxRules+1)}},
		{"roles", Definition{Defaults: make([]RoleDefault, MaxRoles+1)}},
		{"resolvers", Definition{ResolverPolicyIDs: make([]string, MaxResolverPolicies+1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Compile(test.definition); !errors.Is(err, ErrLimit) {
				t.Fatalf("got %v, want %v", err, ErrLimit)
			}
		})
	}
}

func TestSelectorConcurrentReads(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	selector := mustCompile(t, basicDefinition())
	var group sync.WaitGroup
	errorsFound := make(chan string, 32)
	for worker := 0; worker < 32; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for iteration := 0; iteration < 250; iteration++ {
				peer := netip.MustParseAddr("192.0.2.1")
				want := "regional"
				if (worker+iteration)%2 == 0 {
					peer = netip.MustParseAddr("198.51.100.1")
					want = "ordinary"
				}
				decision, err := selector.Select("normal", peer, now)
				if err != nil || decision.ResolverPolicyID != want {
					errorsFound <- "unexpected concurrent decision"
					return
				}
			}
		}(worker)
	}
	group.Wait()
	close(errorsFound)
	for message := range errorsFound {
		t.Error(message)
	}
}

func basicDefinition() Definition {
	return Definition{
		ResolverPolicyIDs: []string{"ordinary", "regional"},
		SourceSets: []SourceSet{{
			ID:      "clients",
			Members: []Member{{Prefix: mustPrefix("192.0.2.0/24")}},
		}},
		Rules:    []Rule{{ListenerRole: "normal", SourceSetID: "clients", ResolverPolicyID: "regional"}},
		Defaults: []RoleDefault{{ListenerRole: "normal", ResolverPolicyID: "ordinary"}},
	}
}

func mustCompile(t testing.TB, definition Definition) *Selector {
	t.Helper()
	selector, err := Compile(definition)
	if err != nil {
		t.Fatal(err)
	}
	return selector
}

func mustPrefix(value string) netip.Prefix {
	return netip.MustParsePrefix(value)
}
