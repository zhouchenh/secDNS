package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const clampTestName = "large.clamp.invalid."
const clampTestAnswers = 12

// Serve has no shutdown API. The parent owns, kills and waits for this exact
// subprocess, including when a wire assertion fails.
func TestDNSServerFamilyClampHelper(t *testing.T) {
	protocol := os.Getenv("SECDNS_CLAMP_TEST_PROTOCOL")
	if protocol == "" {
		return
	}
	port, err := strconv.ParseUint(os.Getenv("SECDNS_CLAMP_TEST_PORT"), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion(clampTestName, dns.TypeTXT)
	q.Id = 0x4242
	shared := new(dns.Msg)
	shared.SetReply(q)
	for i := 0; i < clampTestAnswers; i++ {
		shared.Answer = append(shared.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: clampTestName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{strconv.Itoa(i) + "-" + strings.Repeat("x", 180)},
		})
	}
	if shared.Len() <= 1232 || shared.Len() > 4096 {
		t.Fatal("invalid large-response fixture size", shared.Len())
	}
	d := &DNSServer{Listen: net.ParseIP(os.Getenv("SECDNS_CLAMP_TEST_HOST")), Port: uint16(port), Protocol: protocol}
	d.Serve(func(query *dns.Msg) *dns.Msg {
		if len(query.Question) == 1 && query.Question[0].Name == clampTestName {
			return shared
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		return reply
	}, func(err error) { t.Fatal(err) })
}

// Read the complete datagram rather than using a DNS client's EDNS-sized receive
// buffer, which could hide an oversized response by truncating it client-side.
func exchangeClampWire(protocol, endpoint string, query *dns.Msg) (*dns.Msg, int, error) {
	conn, err := net.DialTimeout(protocol, endpoint, 200*time.Millisecond)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return nil, 0, err
	}
	data, err := query.Pack()
	if err != nil {
		return nil, 0, err
	}
	tcp := strings.HasPrefix(protocol, "tcp")
	if tcp {
		data = append(binary.BigEndian.AppendUint16(nil, uint16(len(data))), data...)
	}
	if n, err := conn.Write(data); err != nil || n != len(data) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return nil, 0, err
	}
	wire := make([]byte, dns.MaxMsgSize)
	var n int
	if tcp {
		var prefix [2]byte
		if _, err = io.ReadFull(conn, prefix[:]); err == nil {
			n, err = io.ReadFull(conn, wire[:binary.BigEndian.Uint16(prefix[:])])
		}
	} else {
		n, err = conn.Read(wire)
	}
	if err != nil {
		return nil, 0, err
	}
	reply := new(dns.Msg)
	if err = reply.Unpack(wire[:n]); err != nil {
		return nil, n, err
	}
	if reply.Id != query.Id || reply.Rcode != dns.RcodeSuccess {
		return nil, n, fmt.Errorf("unexpected reply ID or response code")
	}
	return reply, n, nil
}

func TestDNSServerResponseClampTransports(t *testing.T) {
	for _, protocol := range []string{"udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"} {
		t.Run(protocol, func(t *testing.T) {
			host := "127.0.0.1"
			if strings.HasSuffix(protocol, "6") {
				host = "::1"
			}
			var endpoint string
			if strings.HasPrefix(protocol, "udp") {
				listener, err := net.ListenPacket(protocol, net.JoinHostPort(host, "0"))
				if err != nil {
					t.Fatal(err)
				}
				endpoint = listener.LocalAddr().String()
				listener.Close()
			} else {
				listener, err := net.Listen(protocol, net.JoinHostPort(host, "0"))
				if err != nil {
					t.Fatal(err)
				}
				endpoint = listener.Addr().String()
				listener.Close()
			}
			_, port, err := net.SplitHostPort(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestDNSServerFamilyClampHelper$", "-test.timeout=15s")
			cmd.Env = append(os.Environ(), "SECDNS_CLAMP_TEST_PROTOCOL="+protocol, "SECDNS_CLAMP_TEST_HOST="+host, "SECDNS_CLAMP_TEST_PORT="+port)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cancel(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
			ready := new(dns.Msg)
			ready.SetQuestion("ready.clamp.invalid.", dns.TypeA)
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, _, err = exchangeClampWire(protocol, endpoint, ready); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("listener readiness", err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			for _, test := range []struct {
				name string
				edns uint16
				max  int
			}{{"no-edns", 0, 512}, {"edns-floor", 200, 512}, {"edns-1232", 1232, 1232}, {"edns-4096", 4096, 4096}} {
				t.Run(test.name, func(t *testing.T) {
					query := new(dns.Msg)
					query.SetQuestion(clampTestName, dns.TypeTXT)
					query.Id = 0x4242
					if test.edns != 0 {
						query.SetEdns0(test.edns, false)
					}
					reply, size, err := exchangeClampWire(protocol, endpoint, query)
					if err != nil {
						t.Fatal(err)
					}
					truncated := strings.HasPrefix(protocol, "udp") && test.max < 4096
					if reply.Truncated != truncated {
						t.Fatalf("TC=%v, want %v (wire=%d, answers=%d)", reply.Truncated, truncated, size, len(reply.Answer))
					}
					if truncated {
						if size > test.max || len(reply.Answer) >= clampTestAnswers {
							t.Fatalf("response not clamped: wire=%d limit=%d answers=%d", size, test.max, len(reply.Answer))
						}
					} else if len(reply.Answer) != clampTestAnswers || size <= 1232 {
						t.Fatalf("full/shared response changed: wire=%d answers=%d", size, len(reply.Answer))
					}
				})
			}
		})
	}
}
