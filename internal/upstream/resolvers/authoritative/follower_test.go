package authoritative

import (
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

func TestFollowerAuthoritativeAtomicTransition(t *testing.T) {
	name := t.Name()
	enrollment := recordstore.FollowerEnrollment{ClusterID: "cluster", Kind: recordstore.FollowerExactRecords, RulesetID: "rules", LineageID: "lineage", AuthorityEpoch: "epoch"}
	cleanup, err := recordstore.PrepareBindingsWithFollowers(nil, nil, map[string]recordstore.FollowerConfig{
		name: {SQLitePath: filepath.Join(t.TempDir(), "follower.db"), Enrollment: enrollment, CreateIfMissing: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup() })
	resolver := &Authoritative{Store: name, CompleteCNAME: true}
	question := new(dns.Msg)
	question.SetQuestion("alias.invalid.", dns.TypeA)
	response, err := resolver.Resolve(question, 16)
	if err != nil || response.Rcode != dns.RcodeServerFailure {
		t.Fatal("uninitialized follower did not fail closed", err, response)
	}
	store := recordstore.FollowerBinding(name)
	first, _ := recordset.New("rules", "lineage", 1, []recordset.Record{
		{Name: "alias.invalid.", Type: "CNAME", Values: []string{"target.invalid."}, TTLSeconds: 30},
		{Name: "target.invalid.", Type: "A", Values: []string{"192.0.2.1"}, TTLSeconds: 30},
	})
	wire, _ := first.MarshalJSON()
	if _, err = store.Accept(enrollment, wire); err != nil {
		t.Fatal(err)
	}
	response, err = resolver.Resolve(question, 16)
	if err != nil || len(response.Answer) != 2 || response.Answer[1].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatal("first generation not served atomically", err, response)
	}
	second, _ := recordset.New("rules", "lineage", 2, []recordset.Record{
		{Name: "alias.invalid.", Type: "CNAME", Values: []string{"target.invalid."}, TTLSeconds: 30},
		{Name: "target.invalid.", Type: "A", Values: []string{"192.0.2.2"}, TTLSeconds: 30},
	})
	wire, _ = second.MarshalJSON()
	if _, err = store.Accept(enrollment, wire); err != nil {
		t.Fatal(err)
	}
	response, err = resolver.Resolve(question, 16)
	if err != nil || len(response.Answer) != 2 || response.Answer[1].(*dns.A).A.String() != "192.0.2.2" {
		t.Fatal("second generation not served atomically", err, response)
	}
}
