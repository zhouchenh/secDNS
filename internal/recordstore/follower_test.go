package recordstore

import (
	"bytes"
	"errors"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

var followerEnrollment = FollowerEnrollment{"cluster-test", FollowerExactRecords, "rules-test", "lineage-test", "epoch-test"}

func followerWire(t *testing.T, revision uint64, records ...recordset.Record) []byte {
	t.Helper()
	s, e := recordset.New(followerEnrollment.RulesetID, followerEnrollment.LineageID, revision, records)
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.MarshalJSON()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func followerA(value string) recordset.Record {
	return recordset.Record{Name: "a.invalid.", Type: "A", Values: []string{value}, TTLSeconds: 30}
}
func followerStores(t *testing.T, test func(*testing.T, *FollowerStore, string)) {
	t.Helper()
	for _, durable := range []bool{false, true} {
		name := "memory"
		if durable {
			name = "sqlite"
		}
		t.Run(name, func(t *testing.T) {
			var s *FollowerStore
			var e error
			var p string
			if durable {
				p = dbPath(t)
				s, e = CreateFollowerSQLite(p, followerEnrollment)
			} else {
				s, e = NewFollowerMemory(followerEnrollment)
			}
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { s.Close() })
			test(t, s, p)
		})
	}
}
func acceptFollower(t *testing.T, s *FollowerStore, raw []byte, want string) FollowerAcceptance {
	t.Helper()
	r, e := s.Accept(followerEnrollment, raw)
	if e != nil || r.Outcome != want {
		t.Fatalf("outcome %q error %v", r.Outcome, e)
	}
	return r
}
func rejectFollower(t *testing.T, s *FollowerStore, a FollowerEnrollment, raw []byte, want error) {
	t.Helper()
	r, e := s.Accept(a, raw)
	if !errors.Is(e, want) || r != (FollowerAcceptance{}) {
		t.Fatalf("rejection %v result %#v", e, r)
	}
}
func followerView(t *testing.T, s *FollowerStore) FollowerView {
	t.Helper()
	v, e := s.Acquire()
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestFollowerOrderingAndRestart(t *testing.T) {
	followerStores(t, func(t *testing.T, s *FollowerStore, p string) {
		if _, e := s.Acquire(); !errors.Is(e, ErrFollowerNotReady) {
			t.Fatal(e)
		}
		if p != "" {
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			var e error
			s, e = OpenFollowerSQLite(p, followerEnrollment)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if _, e = s.Acquire(); !errors.Is(e, ErrFollowerNotReady) {
				t.Fatal(e)
			}
		}
		first := followerWire(t, 1)
		acceptFollower(t, s, first, "initial")
		old := followerView(t, s)
		acceptFollower(t, s, first, "unchanged")
		rejectFollower(t, s, followerEnrollment, followerWire(t, 1, followerA("192.0.2.1")), ErrFollowerEquivocation)
		high := followerWire(t, 9007199254740993)
		acceptFollower(t, s, high, "advanced")
		rejectFollower(t, s, followerEnrollment, first, ErrFollowerRollback)
		if old.State().Snapshot.Revision != 1 || len(old.Records()) != 0 {
			t.Fatal("old view changed")
		}
		if p != "" {
			s.Close()
			var e error
			s, e = OpenFollowerSQLite(p, followerEnrollment)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if followerView(t, s).State().Snapshot.Revision != 9007199254740993 {
				t.Fatal("watermark lost")
			}
			rejectFollower(t, s, followerEnrollment, first, ErrFollowerRollback)
		}
		max := followerWire(t, math.MaxUint64, followerA("192.0.2.2"))
		acceptFollower(t, s, max, "advanced")
		acceptFollower(t, s, max, "unchanged")
		rejectFollower(t, s, followerEnrollment, high, ErrFollowerRollback)
		held := followerView(t, s)
		s.Close()
		s.Close()
		if _, e := s.Acquire(); !errors.Is(e, ErrClosed) {
			t.Fatal(e)
		}
		rejectFollower(t, s, FollowerEnrollment{}, nil, ErrClosed)
		if held.State().Snapshot.Revision != math.MaxUint64 {
			t.Fatal("closed held view")
		}
	})
}
func TestFollowerIdentityAndStrictInput(t *testing.T) {
	followerStores(t, func(t *testing.T, s *FollowerStore, _ string) {
		raw := followerWire(t, 7, followerA("192.0.2.1"))
		for _, field := range []string{"cluster", "rules", "lineage", "epoch"} {
			a := followerEnrollment
			switch field {
			case "cluster":
				a.ClusterID = "other"
			case "rules":
				a.RulesetID = "other"
			case "lineage":
				a.LineageID = "other"
			case "epoch":
				a.AuthorityEpoch = "other"
			}
			rejectFollower(t, s, a, raw, ErrFollowerIdentity)
		}
		bad := followerEnrollment
		bad.Kind = "other"
		rejectFollower(t, s, bad, raw, ErrFollowerInput)
		for _, bad := range [][]byte{nil, []byte(`{}`), bytes.Replace(raw, []byte(`"revision":"7"`), []byte(`"revision":"07"`), 1), bytes.Replace(raw, []byte(`"revision":"7"`), []byte(`"revision":"7","revision":"7"`), 1), bytes.Replace(raw, []byte(`192.0.2.1`), []byte(`192.0.2.2`), 1), bytes.Replace(raw, []byte(`"name"`), []byte(`"Name"`), 1), bytes.Replace(raw, []byte(`"a.invalid."`), []byte(`null`), 1), bytes.Replace(raw, []byte(`a.invalid.`), []byte(`\ud800`), 1)} {
			rejectFollower(t, s, followerEnrollment, bad, ErrFollowerInput)
		}
		rejectFollower(t, s, followerEnrollment, make([]byte, recordset.MaxBytes+1), ErrFollowerLimit)
		other, e := recordset.New("other", followerEnrollment.LineageID, math.MaxUint64, nil)
		if e != nil {
			t.Fatal(e)
		}
		wire, _ := other.MarshalJSON()
		rejectFollower(t, s, followerEnrollment, wire, ErrFollowerIdentity)
		if _, e = s.Acquire(); !errors.Is(e, ErrFollowerNotReady) {
			t.Fatal("rejection initialized store")
		}
		acceptFollower(t, s, append([]byte(" \n"), raw...), "initial")
		want := append([]byte(nil), raw...)
		for i := range raw {
			raw[i] = 'x'
		}
		if !bytes.Equal(followerView(t, s).EnvelopeJSON(), want) {
			t.Fatal("retained caller input or formatting")
		}
	})
	for _, value := range []string{"", strings.Repeat("a", 129), " bad", "x/y", "x\x00y", "é"} {
		e := followerEnrollment
		e.ClusterID = value
		if s, err := NewFollowerMemory(e); s != nil || !errors.Is(err, ErrFollowerInput) {
			t.Fatal("invalid enrollment accepted")
		}
	}
}
func TestFollowerViewsFidelityAndExpiry(t *testing.T) {
	followerStores(t, func(t *testing.T, s *FollowerStore, _ string) {
		at := time.Date(2030, 1, 1, 0, 0, 0, 123456789, time.UTC)
		s.now = func() time.Time { return at }
		records := []recordset.Record{{Name: "a.invalid.", Type: "A", Values: []string{"192.0.2.1"}, TTLSeconds: 0, ExpiresAt: at.Add(time.Nanosecond).Format(time.RFC3339Nano)}, {Name: "past.invalid.", Type: "AAAA", Values: []string{"2001:db8::1"}, ExpiresAt: at.Add(-time.Second).Format(time.RFC3339Nano)}, {Name: "text.invalid.", Type: "TXT", Values: []string{"", "repeat", "repeat"}, TTLSeconds: math.MaxUint32}}
		acceptFollower(t, s, followerWire(t, 8, records...), "initial")
		v := followerView(t, s)
		if len(v.Records()) != 3 || len(v.LiveRecords()) != 2 || !v.CapturedAt().Equal(at) {
			t.Fatal("expiry or fidelity")
		}
		r, ok := v.Lookup("A.INVALID", "A")
		if !ok || r.TTLSeconds != 0 {
			t.Fatal("lookup")
		}
		r.Values[0] = "changed"
		v.Records()[0].Values[0] = "changed"
		v.LiveRecords()[0].Values[0] = "changed"
		wire := v.EnvelopeJSON()
		wire[0] = 'x'
		if got, _ := v.Lookup("a.invalid.", "A"); got.Values[0] != "192.0.2.1" {
			t.Fatal("copy isolation")
		}
		s.now = func() time.Time { return at.Add(time.Nanosecond) }
		if _, ok = followerView(t, s).Lookup("a.invalid.", "A"); ok {
			t.Fatal("expiry boundary")
		}
		if _, ok = v.Lookup("a.invalid.", "A"); !ok {
			t.Fatal("held timestamp changed")
		}
		txt, _ := v.Lookup("text.invalid.", "TXT")
		if strings.Join(txt.Values, "|") != "|repeat|repeat" {
			t.Fatal("TXT chunks changed")
		}
		acceptFollower(t, s, followerWire(t, 9), "advanced")
		s.Close()
		if len(v.Records()) != 3 {
			t.Fatal("view lifetime")
		}
	})
}
func TestFollowerConcurrentAcceptAcquireClose(t *testing.T) {
	followerStores(t, func(t *testing.T, s *FollowerStore, _ string) {
		acceptFollower(t, s, followerWire(t, 1, followerA("192.0.2.1")), "initial")
		held := followerView(t, s)
		var wg sync.WaitGroup
		for n := 0; n < 12; n++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				for i := 0; i < 10; i++ {
					if n%3 == 0 {
						raw := followerWire(t, uint64(2+i), followerA("192.0.2.2"))
						_, e := s.Accept(followerEnrollment, raw)
						if e != nil && !errors.Is(e, ErrFollowerRollback) && !errors.Is(e, ErrClosed) {
							t.Error(e)
						}
					} else {
						v, e := s.Acquire()
						if e == nil {
							r := v.Records()
							if len(r) != 1 || v.State().Snapshot.Revision == 0 {
								t.Error("partial generation")
							}
						} else if !errors.Is(e, ErrClosed) {
							t.Error(e)
						}
					}
				}
			}(n)
		}
		wg.Add(1)
		go func() { defer wg.Done(); s.Close() }()
		wg.Wait()
		if _, e := s.Acquire(); !errors.Is(e, ErrClosed) {
			t.Fatal(e)
		}
		if held.Records()[0].Values[0] != "192.0.2.1" {
			t.Fatal("held view mutation")
		}
	})
}
