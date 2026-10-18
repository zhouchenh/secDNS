package authoritative

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"time"
)

type recordReader interface {
	Get(string, uint16) (recordstore.Record, bool)
	HasName(string) bool
	RecordsForName(string) map[uint16]recordstore.Record
}
type viewReader struct{ view recordstore.View }
type followerViewReader struct{ view recordstore.FollowerView }

func (r viewReader) Get(name string, typ uint16) (recordstore.Record, bool) {
	rec, ok := r.view.Lookup(name, dns.TypeToString[typ])
	if !ok {
		return recordstore.Record{}, false
	}
	expiry, _ := time.Parse(time.RFC3339Nano, rec.ExpiresAt)
	return recordstore.Record{Name: rec.Name, Type: typ, Values: rec.Values, TTL: rec.TTLSeconds, ExpiresAt: expiry}, true
}
func (r viewReader) HasName(name string) bool { return len(r.RecordsForName(name)) > 0 }
func (r viewReader) RecordsForName(name string) map[uint16]recordstore.Record {
	out := map[uint16]recordstore.Record{}
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeTXT} {
		if rec, ok := r.Get(name, typ); ok {
			out[typ] = rec
		}
	}
	return out
}

func (r followerViewReader) Get(name string, typ uint16) (recordstore.Record, bool) {
	rec, ok := r.view.Lookup(name, dns.TypeToString[typ])
	if !ok {
		return recordstore.Record{}, false
	}
	expiry, _ := time.Parse(time.RFC3339Nano, rec.ExpiresAt)
	return recordstore.Record{Name: rec.Name, Type: typ, Values: rec.Values, TTL: rec.TTLSeconds, ExpiresAt: expiry}, true
}
func (r followerViewReader) HasName(name string) bool { return len(r.RecordsForName(name)) > 0 }
func (r followerViewReader) RecordsForName(name string) map[uint16]recordstore.Record {
	out := map[uint16]recordstore.Record{}
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeTXT} {
		if rec, ok := r.Get(name, typ); ok {
			out[typ] = rec
		}
	}
	return out
}
