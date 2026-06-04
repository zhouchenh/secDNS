package recursive

import (
	"net"
	"testing"
	"time"
)

func hasV4(ips []net.IP) bool {
	for _, ip := range ips {
		if ip.To4() != nil {
			return true
		}
	}
	return false
}

func hasV6(ips []net.IP) bool {
	for _, ip := range ips {
		if ip.To4() == nil {
			return true
		}
	}
	return false
}

// TestScoreboardPrefersIPv4ByDefault: on a cold board with equal RTTs, IPv4 sorts
// first so a host with broken IPv6 egress does not stall cold queries.
func TestScoreboardPrefersIPv4ByDefault(t *testing.T) {
	roots := []RootServer{
		{Host: "a", Addresses: []net.IP{net.ParseIP("198.41.0.4"), net.ParseIP("2001:503:ba3e::2:30")}},
		{Host: "b", Addresses: []net.IP{net.ParseIP("199.9.14.201"), net.ParseIP("2001:500:200::b")}},
	}
	sb := newScoreboard(roots, 5)
	picked := sb.pickRoots(false)
	if len(picked) == 0 || picked[0].To4() == nil {
		t.Fatalf("expected an IPv4 root first by default, got %v", picked)
	}
	// Determinism: a second identical call returns the same order.
	again := sb.pickRoots(false)
	for i := range picked {
		if !picked[i].Equal(again[i]) {
			t.Fatalf("pickRoots is not deterministic: %v vs %v", picked, again)
		}
	}
}

// TestScoreboardPreferIPv6Honored: when preferIPv6 is set, IPv6 sorts first.
func TestScoreboardPreferIPv6Honored(t *testing.T) {
	roots := []RootServer{
		{Host: "a", Addresses: []net.IP{net.ParseIP("198.41.0.4"), net.ParseIP("2001:503:ba3e::2:30")}},
	}
	sb := newScoreboard(roots, 5)
	picked := sb.pickRoots(true)
	if len(picked) == 0 || picked[0].To4() != nil {
		t.Fatalf("expected an IPv6 root first when preferIPv6, got %v", picked)
	}
}

// TestScoreboardFamilyDiversity: even when one family would fill the whole topN by
// score, the selection still includes at least one server of the other family so a
// dead family cannot starve the working one.
func TestScoreboardFamilyDiversity(t *testing.T) {
	roots := []RootServer{
		{Addresses: []net.IP{net.ParseIP("198.41.0.4")}},
		{Addresses: []net.IP{net.ParseIP("199.9.14.201")}},
		{Addresses: []net.IP{net.ParseIP("192.33.4.12")}},
		{Addresses: []net.IP{net.ParseIP("2001:500:2::c")}},
	}
	sb := newScoreboard(roots, 2) // topN smaller than the IPv4 count
	picked := sb.pickRoots(false)
	if len(picked) != 2 {
		t.Fatalf("expected 2 picks, got %d (%v)", len(picked), picked)
	}
	if !hasV4(picked) || !hasV6(picked) {
		t.Fatalf("expected both address families in the selection, got %v", picked)
	}
}

// TestMarkSuccessRTTInMillis: a proven-fast server (low ms RTT) must outrank an untried
// server. This guards the unit fix: raw-nanosecond RTTs would make tried servers score
// in the millions and always lose to untried (often dead) ones.
func TestMarkSuccessRTTInMillis(t *testing.T) {
	fast := net.ParseIP("198.41.0.4")
	untried := net.ParseIP("199.9.14.201")
	sb := newScoreboard([]RootServer{{Addresses: []net.IP{fast, untried}}}, 5)
	sb.markSuccess(fast, 10*time.Millisecond)
	picked := sb.pickFrom([]net.IP{fast, untried}, false, 2)
	if len(picked) != 2 || !picked[0].Equal(fast) {
		t.Fatalf("expected the proven-fast server first, got %v", picked)
	}
	// A server that just failed must drop below an untried one.
	sb.markFailure(fast)
	sb.markFailure(fast)
	picked = sb.pickFrom([]net.IP{fast, untried}, false, 2)
	if !picked[0].Equal(untried) {
		t.Fatalf("expected the untried server to outrank a just-failed one, got %v", picked)
	}
}
