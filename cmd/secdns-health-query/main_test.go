package main

import (
	"bytes"
	"encoding/json"
	"github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

func localServer(t *testing.T, network string, delay time.Duration) string {
	t.Helper()
	server := &dns.Server{Net: network, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		time.Sleep(delay)
		r := new(dns.Msg)
		r.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(1, 1, 1, 1)}}
		} else {
			r.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("64:ff9b::101:101")}}
		}
		_ = w.WriteMsg(r)
	})}
	var endpoint string
	if network == "udp" {
		c, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		server.PacketConn = c
		endpoint = c.LocalAddr().String()
	} else {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		server.Listener = l
		endpoint = l.Addr().String()
	}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go server.ActivateAndServe()
	<-ready
	t.Cleanup(func() { server.Shutdown() })
	return endpoint
}
func TestConfiguredTimeoutRealUDPAndTCP(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			endpoint := localServer(t, network, 800*time.Millisecond)
			var b bytes.Buffer
			if code := execute([]string{"query", network, endpoint, "example.test.", "A", "1000"}, &b); code != 0 {
				t.Fatal(code, b.String())
			}
			var r reply
			if e := json.Unmarshal(b.Bytes(), &r); e != nil || r.Outcome != "response" || r.Rcode != 0 || len(r.Question) != 1 || r.Question[0].Qtype != dns.TypeA || len(r.Answers) != 1 || r.Answers[0] != "example.test.\t60\tIN\tA\t1.1.1.1" {
				t.Fatal("semantics", r, e)
			}
			b.Reset()
			start := time.Now()
			if code := execute([]string{"query", network, endpoint, "example.test.", "A", "500"}, &b); code == 0 || b.String() != "{\"outcome\":\"timeout\"}\n" {
				t.Fatal(code, b.String())
			}
			if time.Since(start) > 750*time.Millisecond {
				t.Fatal("timeout ignored")
			}
		})
	}
}
func TestAAAAAndBounds(t *testing.T) {
	endpoint := localServer(t, "udp", 0)
	for _, timeout := range []string{"500", "2500"} {
		var b bytes.Buffer
		if execute([]string{"query", "udp", endpoint, "example.test.", "AAAA", timeout}, &b) != 0 {
			t.Fatal(b.String())
		}
		var r reply
		json.Unmarshal(b.Bytes(), &r)
		if r.Question[0].Qtype != dns.TypeAAAA || len(r.Answers) != 1 {
			t.Fatal(r)
		}
	}
	for _, args := range [][]string{{"query", "udp", endpoint, "test.", "A", "499"}, {"query", "udp", endpoint, "test.", "A", "2501"}, {"query", "udp", endpoint, "test.", "A", "1.5"}, {"query", "udp", endpoint, "test.", "MX", "1000"}, {"serve"}, {"query", "udp", "secret.invalid:53", "test.", "A", "1000"}} {
		var b bytes.Buffer
		if execute(args, &b) == 0 || b.String() != "{\"outcome\":\"invalid_arguments\"}\n" {
			t.Fatal(args, b.String())
		}
	}
}

func TestNetworkErrorSafe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().String()
	listener.Close()
	var b bytes.Buffer
	if execute([]string{"query", "tcp", endpoint, "test.", "A", "500"}, &b) == 0 || b.String() != "{\"outcome\":\"network_error\"}\n" {
		t.Fatal(b.String())
	}
}
