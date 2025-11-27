package doh

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestDoHResolveDepthLimit(t *testing.T) {
	d := &DoH{}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	if _, err := d.Resolve(query, -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
}

func TestDoHResolveSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request: %v", err)
		}
		query := new(dns.Msg)
		if err := query.Unpack(body); err != nil {
			t.Fatalf("invalid DNS payload: %v", err)
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   query.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IP{93, 184, 216, 34},
			},
		}
		wire, err := response.Pack()
		if err != nil {
			t.Fatalf("pack dns response: %v", err)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	host := common.EnsureFQDN(parsed.Hostname())
	resolutionReply := new(dns.Msg)
	resolutionReply.SetQuestion(host, dns.TypeA)
	resolutionReply.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP(parsed.Hostname()).To4(),
		},
	}

	d := &DoH{
		URL:          parsed,
		QueryTimeout: 2 * time.Second,
		Resolver:     &stubResolver{response: resolutionReply},
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	resp, err := d.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response, got nil")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected one answer, got %d", len(resp.Answer))
	}
	if resp.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("unexpected rr type %d", resp.Answer[0].Header().Rrtype)
	}
}

type stubResolver struct {
	response *dns.Msg
	err      error
}

func (s *stubResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*stubResolver)) }
func (s *stubResolver) TypeName() string      { return "stub" }
func (s *stubResolver) Resolve(*dns.Msg, int) (*dns.Msg, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.response != nil {
		return s.response.Copy(), nil
	}
	return nil, nil
}
func (s *stubResolver) NameServerResolver() {}
