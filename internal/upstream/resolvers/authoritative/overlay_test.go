package authoritative

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/config/typed"
	_ "github.com/zhouchenh/secDNS/internal/config/typed/resolver"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type overlayFallback struct {
	calls int
	depth int
	reply *dns.Msg
	err   error
}

func (*overlayFallback) Type() descriptor.Type { return nil }
func (*overlayFallback) TypeName() string      { return "overlay-fallback-test" }
func (f *overlayFallback) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	f.calls++
	f.depth = depth
	if f.err != nil || f.reply == nil {
		return f.reply, f.err
	}
	reply := f.reply.Copy()
	reply.Id = query.Id
	if len(reply.Question) == 0 {
		reply.Question = append([]dns.Question(nil), query.Question...)
	}
	return reply, nil
}

func fallbackAddress(name, address string, ttl uint32) *dns.Msg {
	query := query(name, dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(query)
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP(address).To4()}}
	return reply
}

func prepareOverlayWriter(t *testing.T) (string, *recordstore.VersionedStore) {
	t.Helper()
	name := fmt.Sprintf("%s-%d", t.Name(), versionedTestSequence.Add(1))
	cleanup, err := recordstore.PrepareBindings(nil, map[string]recordstore.VersionedConfig{name: {Backend: "memory", RulesetID: "rules", LineageID: "lineage"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup() })
	_, writer := recordstore.Binding(name)
	return name, writer
}

func replaceOverlayRecords(t *testing.T, writer *recordstore.VersionedStore, revision uint64, operation string, records []recordset.Record) {
	t.Helper()
	if _, err := writer.Replace(recordstore.Expected{RulesetID: "rules", LineageID: "lineage", Revision: revision}, operation, records); err != nil {
		t.Fatal(err)
	}
}

func TestExactStoreOverlayDynamicWriterMembershipAndLocalNegatives(t *testing.T) {
	name, writer := prepareOverlayWriter(t)
	fallback := &overlayFallback{reply: fallbackAddress("new-owner.invalid.", "198.51.100.10", 300)}
	overlay := &ExactStoreOverlay{Store: name, CompleteCNAME: true, NegativeTTL: 45, Fallback: fallback}

	response, err := overlay.Resolve(query("new-owner.invalid.", dns.TypeA), 8)
	if err != nil || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "198.51.100.10" || fallback.calls != 1 || fallback.depth != 7 {
		t.Fatal("initial miss did not use selected fallback exactly once", response, err, fallback.calls, fallback.depth)
	}

	replaceOverlayRecords(t, writer, 1, "add-owner", []recordset.Record{{Name: "new-owner.invalid.", Type: "A", Values: []string{"192.0.2.44"}, TTLSeconds: 44}})
	response, err = overlay.Resolve(query("NEW-OWNER.invalid.", dns.TypeA), 8)
	if err != nil || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "192.0.2.44" || response.Answer[0].Header().Ttl != 44 || fallback.calls != 1 {
		t.Fatal("published owner did not bypass fallback", response, err, fallback.calls)
	}
	for _, typ := range []uint16{dns.TypeAAAA, dns.TypeMX} {
		response, err = overlay.Resolve(query("new-owner.invalid.", typ), 8)
		if err != nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 0 || len(response.Ns) != 1 || response.Ns[0].(*dns.SOA).Minttl != 45 || fallback.calls != 1 {
			t.Fatal("existing owner did not produce local NODATA", typ, response, err, fallback.calls)
		}
	}
	response, err = overlay.Resolve(query("child.new-owner.invalid.", dns.TypeA), 8)
	if err != nil || len(response.Answer) != 1 || fallback.calls != 2 {
		t.Fatal("subdomain was not an exact miss", response, err, fallback.calls)
	}

	replaceOverlayRecords(t, writer, 2, "remove-owner", nil)
	response, err = overlay.Resolve(query("new-owner.invalid.", dns.TypeA), 8)
	if err != nil || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "198.51.100.10" || fallback.calls != 3 {
		t.Fatal("removed owner did not return to fallback", response, err, fallback.calls)
	}
}

func TestExactStoreOverlayCNAMEAndLocalFailuresNeverFallThrough(t *testing.T) {
	name, writer := prepareOverlayWriter(t)
	fallback := &overlayFallback{reply: fallbackAddress("absent.invalid.", "198.51.100.20", 60)}
	overlay := &ExactStoreOverlay{Store: name, CompleteCNAME: true, Fallback: fallback}
	replaceOverlayRecords(t, writer, 1, "chain", []recordset.Record{
		{Name: "alias.invalid.", Type: "CNAME", Values: []string{"target.invalid."}, TTLSeconds: 31},
		{Name: "target.invalid.", Type: "A", Values: []string{"192.0.2.31"}, TTLSeconds: 32},
		{Name: "external.invalid.", Type: "CNAME", Values: []string{"outside.invalid."}, TTLSeconds: 33},
	})
	response, err := overlay.Resolve(query("alias.invalid.", dns.TypeA), 8)
	if err != nil || len(response.Answer) != 2 || response.Answer[0].Header().Ttl != 31 || response.Answer[1].Header().Ttl != 32 || fallback.calls != 0 {
		t.Fatal("local chain changed", response, err, fallback.calls)
	}
	response, err = overlay.Resolve(query("external.invalid.", dns.TypeA), 8)
	if err != nil || len(response.Answer) != 1 || fallback.calls != 0 {
		t.Fatal("external target should remain chain-only", response, err, fallback.calls)
	}
	response, err = overlay.Resolve(query("alias.invalid.", dns.TypeA), 0)
	if err != nil || response.Rcode != dns.RcodeServerFailure || fallback.calls != 0 {
		t.Fatal("local depth exhaustion escaped to fallback", response, err, fallback.calls)
	}

	replaceOverlayRecords(t, writer, 2, "cycle", []recordset.Record{{Name: "loop.invalid.", Type: "CNAME", Values: []string{"LOOP.invalid."}, TTLSeconds: 34}})
	response, err = overlay.Resolve(query("loop.invalid.", dns.TypeA), 8)
	if err != nil || response.Rcode != dns.RcodeServerFailure || len(response.Answer) != 0 || fallback.calls != 0 {
		t.Fatal("local chain failure escaped to fallback", response, err, fallback.calls)
	}
}

func TestExactStoreOverlayFallbackAndBindingFailuresAreTerminal(t *testing.T) {
	name, _ := prepareOverlayWriter(t)
	for _, test := range []struct {
		name  string
		stub  *overlayFallback
		rcode int
	}{
		{"nil", &overlayFallback{}, dns.RcodeServerFailure},
		{"error", &overlayFallback{err: errors.New("synthetic")}, dns.RcodeServerFailure},
		{"nxdomain", &overlayFallback{reply: func() *dns.Msg {
			m := new(dns.Msg)
			m.SetRcode(query("missing.invalid.", dns.TypeA), dns.RcodeNameError)
			return m
		}()}, dns.RcodeNameError},
	} {
		t.Run(test.name, func(t *testing.T) {
			overlay := &ExactStoreOverlay{Store: name, Fallback: test.stub}
			response, err := overlay.Resolve(query("missing.invalid.", dns.TypeA), 0)
			if err != nil || response.Rcode != test.rcode || test.stub.calls != 1 || test.stub.depth != -1 {
				t.Fatal(response, err, test.stub.calls, test.stub.depth)
			}
		})
	}
	legacyName := fmt.Sprintf("%s-legacy-%d", t.Name(), versionedTestSequence.Add(1))
	legacy := recordstore.GetOrCreate(legacyName)
	t.Cleanup(func() { _ = legacy.Close() })
	for _, store := range []string{"missing-exact-binding", "", legacyName} {
		fallback := &overlayFallback{reply: fallbackAddress("missing.invalid.", "198.51.100.30", 60)}
		response, err := (&ExactStoreOverlay{Store: store, Fallback: fallback}).Resolve(query("missing.invalid.", dns.TypeA), 8)
		if err != nil || response.Rcode != dns.RcodeServerFailure || fallback.calls != 0 {
			t.Fatal("bad binding fell through", store, response, err, fallback.calls)
		}
	}
	if _, err := (&ExactStoreOverlay{}).Resolve(nil, 1); !errors.Is(err, resolverpkg.ErrNilQuery) {
		t.Fatal(err)
	}
	if _, err := (&ExactStoreOverlay{}).Resolve(new(dns.Msg), 1); !errors.Is(err, resolverpkg.ErrNotSupportedQuestion) {
		t.Fatal(err)
	}
	if _, err := (&ExactStoreOverlay{}).Resolve(query("x.invalid.", dns.TypeA), -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatal(err)
	}
}

func TestExactStoreOverlayExpiredOnlyOwnerFallsThrough(t *testing.T) {
	name, writer := prepareOverlayWriter(t)
	replaceOverlayRecords(t, writer, 1, "expired", []recordset.Record{{
		Name: "expired.invalid.", Type: "A", Values: []string{"192.0.2.60"}, TTLSeconds: 60,
		ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
	}})
	fallback := &overlayFallback{reply: fallbackAddress("expired.invalid.", "198.51.100.60", 61)}
	response, err := (&ExactStoreOverlay{Store: name, Fallback: fallback}).Resolve(query("expired.invalid.", dns.TypeA), 8)
	if err != nil || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "198.51.100.60" || fallback.calls != 1 {
		t.Fatal("expired-only owner did not fall through", response, err, fallback.calls)
	}
}

func TestExactStoreOverlayUsesOnePinnedGenerationAndExpiryInstant(t *testing.T) {
	writer, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "rules", LineageID: "lineage"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	deadline := time.Now().Add(250 * time.Millisecond)
	replaceOverlayRecords(t, writer, 1, "old", []recordset.Record{
		{Name: "alias.invalid.", Type: "CNAME", Values: []string{"old.invalid."}, TTLSeconds: 41},
		{Name: "old.invalid.", Type: "A", Values: []string{"192.0.2.41"}, TTLSeconds: 42, ExpiresAt: deadline.Format(time.RFC3339Nano)},
	})
	held, err := writer.Acquire()
	if err != nil || !held.CapturedAt().Before(deadline) {
		t.Fatal(err, held.CapturedAt(), deadline)
	}
	replaceOverlayRecords(t, writer, 2, "new", []recordset.Record{
		{Name: "alias.invalid.", Type: "CNAME", Values: []string{"new.invalid."}, TTLSeconds: 51},
		{Name: "new.invalid.", Type: "A", Values: []string{"192.0.2.51"}, TTLSeconds: 52},
	})
	time.Sleep(time.Until(deadline) + time.Millisecond)
	overlay := &ExactStoreOverlay{CompleteCNAME: true, Fallback: &overlayFallback{reply: fallbackAddress("alias.invalid.", "198.51.100.40", 60)}}
	response := overlay.resolveView(query("alias.invalid.", dns.TypeA), 8, held)
	if len(response.Answer) != 2 || response.Answer[0].(*dns.CNAME).Target != "old.invalid." || response.Answer[1].(*dns.A).A.String() != "192.0.2.41" {
		t.Fatal("held view mixed publication or expiry instant", response)
	}
	fresh, err := writer.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	response = overlay.resolveView(query("alias.invalid.", dns.TypeA), 8, fresh)
	if len(response.Answer) != 2 || response.Answer[0].(*dns.CNAME).Target != "new.invalid." || response.Answer[1].(*dns.A).A.String() != "192.0.2.51" {
		t.Fatal("fresh view did not see new publication", response)
	}
}

func TestExactStoreOverlayFollowerTransitions(t *testing.T) {
	name := fmt.Sprintf("%s-%d", t.Name(), versionedTestSequence.Add(1))
	enrollment := recordstore.FollowerEnrollment{ClusterID: "cluster", Kind: recordstore.FollowerExactRecords, RulesetID: "rules", LineageID: "lineage", AuthorityEpoch: "epoch"}
	cleanup, err := recordstore.PrepareBindingsWithFollowers(nil, nil, map[string]recordstore.FollowerConfig{name: {SQLitePath: filepath.Join(t.TempDir(), "follower.db"), Enrollment: enrollment, CreateIfMissing: true}})
	if err != nil {
		t.Fatal(err)
	}
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = cleanup()
		}
	})
	fallback := &overlayFallback{reply: fallbackAddress("owned.invalid.", "198.51.100.50", 60)}
	overlay := &ExactStoreOverlay{Store: name, CompleteCNAME: true, Fallback: fallback}
	response, err := overlay.Resolve(query("owned.invalid.", dns.TypeA), 8)
	if err != nil || response.Rcode != dns.RcodeServerFailure || fallback.calls != 0 {
		t.Fatal("uninitialized follower treated as empty", response, err, fallback.calls)
	}
	snapshot, err := recordset.New("rules", "lineage", 1, []recordset.Record{{Name: "owned.invalid.", Type: "A", Values: []string{"192.0.2.50"}, TTLSeconds: 50}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := snapshot.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recordstore.FollowerBinding(name).Accept(enrollment, raw); err != nil {
		t.Fatal(err)
	}
	response, err = overlay.Resolve(query("owned.invalid.", dns.TypeA), 8)
	if err != nil || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "192.0.2.50" || fallback.calls != 0 {
		t.Fatal("accepted follower owner unavailable", response, err, fallback.calls)
	}
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	cleaned = true
	response, err = overlay.Resolve(query("owned.invalid.", dns.TypeA), 8)
	if err != nil || response.Rcode != dns.RcodeServerFailure || fallback.calls != 0 {
		t.Fatal("closed follower fell through", response, err, fallback.calls)
	}
}

func TestExactStoreOverlayDescriptor(t *testing.T) {
	describable, ok := resolverpkg.GetResolverDescriptorByTypeName("exactStoreOverlay")
	if !ok {
		t.Fatal("overlay resolver not registered")
	}
	fallbackConfig := typed.Value{Type: "authoritative", Value: map[string]interface{}{}}
	object, successes, failures := describable.Describe(map[string]interface{}{"store": "owned", "completeCNAME": true, "negativeTTL": float64(90), "fallback": fallbackConfig})
	if successes < 1 || failures != 0 {
		t.Fatal(successes, failures)
	}
	overlay := object.(*ExactStoreOverlay)
	if overlay.Store != "owned" || !overlay.CompleteCNAME || overlay.NegativeTTL != 90 || overlay.Fallback == nil || overlay.Fallback.TypeName() != "authoritative" {
		t.Fatal(overlay)
	}
	for _, bad := range []map[string]interface{}{
		{"fallback": fallbackConfig},
		{"store": " owned", "fallback": fallbackConfig},
		{"store": "owned"},
	} {
		if _, successes, failures := describable.Describe(bad); successes > 0 && failures == 0 {
			t.Fatal("bad overlay descriptor admitted", bad)
		}
	}
}
