package config

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The helper owns actual listeners in a separate process because the legacy
// listener API has no shutdown operation. The parent always kills and waits for
// that exact child, including on assertion failure.
func TestListenerPolicyTransportHelper(t *testing.T) {
	raw := os.Getenv("SECDNS_POLICY_TEST_CONFIG")
	if raw == "" {
		return
	}
	i, err := LoadConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ParseRecordStores([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	versioned, err := ParseVersionedRecordStores([]byte(raw), legacy)
	if err != nil {
		t.Fatal(err)
	}
	followers, err := ParseFollowerRecordStores([]byte(raw), legacy, versioned)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy) > 0 || len(versioned) > 0 || len(followers) > 0 {
		cleanup, prepareErr := recordstore.PrepareBindingsWithFollowers(legacy, versioned, FollowerBindings(followers))
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		defer cleanup()
	}
	failure := func(q *dns.Msg) *dns.Msg { r := new(dns.Msg); r.SetRcode(q, dns.RcodeServerFailure); return r }
	i.Listen(failure, failure, func(err error) {
		if err != nil {
			os.Exit(2)
		}
	})
}

func TestExactStoreOverlaySourcePolicyTransportAndCacheIsolation(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			dnsPort := freeTransportPort(t, protocol)
			adminPort := freeTransportPort(t, "tcp")
			for protocol == "tcp" && adminPort == dnsPort {
				adminPort = freeTransportPort(t, "tcp")
			}
			config := map[string]any{
				"versionedRecordStores": map[string]any{"owned": map[string]any{
					"backend": "memory", "rulesetId": "rules", "lineageId": "lineage",
				}},
				"listeners": []any{
					map[string]any{
						"type": "dnsServer", "sourcePolicyRole": "normal",
						"config": map[string]any{"listen": "127.0.0.1", "port": dnsPort, "protocol": protocol},
					},
					map[string]any{
						"type":   "httpAdminServer",
						"config": map[string]any{"listen": "127.0.0.1", "port": adminPort, "token": "synthetic-admin-token", "store": "owned"},
					},
				},
				"resolvers": map[string]any{
					"cache": map[string]any{
						"ordinary-cache": map[string]any{"resolver": map[string]any{"type": "address", "config": "192.0.2.10"}, "maxEntries": 32},
						"special-cache":  map[string]any{"resolver": map[string]any{"type": "address", "config": "192.0.2.20"}, "maxEntries": 32},
					},
					"exactStoreOverlay": map[string]any{
						"ordinary-overlay": map[string]any{"store": "owned", "fallback": "ordinary-cache"},
						"special-overlay":  map[string]any{"store": "owned", "fallback": "special-cache"},
					},
				},
				"sourcePolicy": map[string]any{
					"sourceSets": []any{map[string]any{
						"id": "special-clients", "members": []any{map[string]any{"prefix": "127.0.0.2/32", "expiresAt": "2099-01-01T00:00:00Z"}},
					}},
					"rules":    []any{map[string]any{"listenerRole": "normal", "sourceSet": "special-clients", "resolver": "special-overlay"}},
					"defaults": []any{map[string]any{"listenerRole": "normal", "resolver": "ordinary-overlay"}},
				},
				"rules":           []any{},
				"defaultResolver": "ordinary-overlay",
			}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestListenerPolicyTransportHelper$")
			cmd.Env = append(os.Environ(), "SECDNS_POLICY_TEST_CONFIG="+string(raw))
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

			endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))
			assertAddress := func(source, want string) {
				t.Helper()
				var local net.Addr
				if protocol == "udp" {
					local = &net.UDPAddr{IP: net.ParseIP(source)}
				} else {
					local = &net.TCPAddr{IP: net.ParseIP(source)}
				}
				client := &dns.Client{Net: protocol, Timeout: 300 * time.Millisecond, Dialer: &net.Dialer{LocalAddr: local}}
				query := new(dns.Msg)
				query.SetQuestion("same.invalid.", dns.TypeA)
				deadline := time.Now().Add(5 * time.Second)
				for {
					answer, _, exchangeErr := client.Exchange(query, endpoint)
					if exchangeErr == nil {
						if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
							t.Fatalf("source %s: %v", source, answer)
						}
						record, ok := answer.Answer[0].(*dns.A)
						if !ok || record.A.String() != want {
							t.Fatalf("source %s: %v", source, answer.Answer)
						}
						return
					}
					if time.Now().After(deadline) {
						t.Fatal(exchangeErr)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			postSnapshot := func(body string) {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for {
					request, requestErr := http.NewRequest(http.MethodPost, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(adminPort))+"/admin/snapshot", strings.NewReader(body))
					if requestErr != nil {
						t.Fatal(requestErr)
					}
					request.Header.Set("Authorization", "Bearer synthetic-admin-token")
					response, requestErr := (&http.Client{Timeout: time.Second}).Do(request)
					if requestErr == nil {
						response.Body.Close()
						if response.StatusCode != http.StatusOK {
							t.Fatalf("snapshot replace: %s", response.Status)
						}
						return
					}
					if time.Now().After(deadline) {
						t.Fatal(requestErr)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}

			// Prime two independent fallback caches with the identical question.
			assertAddress("127.0.0.1", "192.0.2.10")
			assertAddress("127.0.0.2", "192.0.2.20")
			postSnapshot(`{"expected":{"ruleset_id":"rules","lineage_id":"lineage","revision":"1"},"operation_id":"add-owner","records":[{"name":"same.invalid.","type":"A","values":["203.0.113.30"],"ttl_seconds":45}]}`)
			for _, source := range []string{"127.0.0.2", "127.0.0.1"} {
				assertAddress(source, "203.0.113.30")
			}
			postSnapshot(`{"expected":{"ruleset_id":"rules","lineage_id":"lineage","revision":"2"},"operation_id":"remove-owner","records":[]}`)
			// Removal exposes the still-partitioned fallback caches again.
			assertAddress("127.0.0.2", "192.0.2.20")
			assertAddress("127.0.0.1", "192.0.2.10")
		})
	}
}

func freeTransportPort(t *testing.T, protocol string) int {
	t.Helper()
	if protocol == "udp" {
		listener, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.LocalAddr().(*net.UDPAddr).Port
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestListenerPolicyDualStackTransports(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, protocol := range []string{"udp", "tcp"} {
			t.Run(host+protocol, func(t *testing.T) {
				listeners := make([]any, 0, 2)
				endpoints := make([]string, 0, 2)
				for _, selected := range []bool{false, true} {
					var port int
					if protocol == "udp" {
						c, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
						if err != nil {
							t.Fatal(err)
						}
						port = c.LocalAddr().(*net.UDPAddr).Port
						c.Close()
					} else {
						c, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
						if err != nil {
							t.Fatal(err)
						}
						port = c.Addr().(*net.TCPAddr).Port
						c.Close()
					}
					item := map[string]any{"type": "dnsServer", "config": map[string]any{"listen": host, "port": port, "protocol": protocol}}
					if selected {
						item["resolver"] = "dns64-policy"
					}
					listeners = append(listeners, item)
					endpoints = append(endpoints, net.JoinHostPort(host, strconv.Itoa(port)))
				}
				var config map[string]any
				if err := json.Unmarshal([]byte(selectedConfig), &config); err != nil {
					t.Fatal(err)
				}
				config["listeners"] = listeners
				raw, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(executable, "-test.run=^TestListenerPolicyTransportHelper$")
				cmd.Env = append(os.Environ(), "SECDNS_POLICY_TEST_CONFIG="+string(raw))
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
				client := &dns.Client{Net: protocol, Timeout: 200 * time.Millisecond}
				ask := func(endpoint, name string) *dns.Msg {
					t.Helper()
					q := new(dns.Msg)
					q.SetQuestion(name, dns.TypeAAAA)
					deadline := time.Now().Add(5 * time.Second)
					for {
						r, _, err := client.Exchange(q, endpoint)
						if err == nil {
							return r
						}
						if time.Now().After(deadline) {
							t.Fatal(err)
						}
						time.Sleep(20 * time.Millisecond)
					}
				}
				// Repeat both roles after the other: no final response crosses policy roles.
				for iteration := 0; iteration < 2; iteration++ {
					for _, index := range []int{iteration % 2, 1 - iteration%2} {
						endpoint := endpoints[index]
						answer := ask(endpoint, "ordinary.invalid.")
						if answer.Rcode != dns.RcodeSuccess {
							t.Fatal(answer.Rcode)
						}
						if index == 0 {
							if len(answer.Answer) != 0 {
								t.Fatal("ordinary listener synthesized")
							}
						} else {
							if len(answer.Answer) != 1 {
								t.Fatal(answer)
							}
							rr, ok := answer.Answer[0].(*dns.AAAA)
							if !ok || rr.AAAA.String() != "64:ff9b::c000:20a" {
								t.Fatal(answer)
							}
						}
						native := ask(endpoint, "native.invalid.")
						if len(native.Answer) != 1 || native.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::10" {
							t.Fatal(native)
						}
						excluded := ask(endpoint, "exclude.invalid.")
						if len(excluded.Answer) != 0 {
							t.Fatal("override synthesized", excluded)
						}
					}
				}
				var concurrent sync.WaitGroup
				for n := 0; n < 8; n++ {
					concurrent.Add(1)
					go func(index int) {
						defer concurrent.Done()
						answer := ask(endpoints[index], "ordinary.invalid.")
						if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != index {
							t.Error("concurrent policy/cache contamination")
						}
					}(n % 2)
				}
				concurrent.Wait()
			})
		}
	}
}

func TestSourcePolicyDualClientTransportAndCacheIsolation(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			var port int
			if protocol == "udp" {
				listener, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port = listener.LocalAddr().(*net.UDPAddr).Port
				listener.Close()
			} else {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port = listener.Addr().(*net.TCPAddr).Port
				listener.Close()
			}

			var config map[string]any
			if err := json.Unmarshal([]byte(sourceSelectedConfig), &config); err != nil {
				t.Fatal(err)
			}
			config["listeners"] = []any{map[string]any{
				"type": "dnsServer", "sourcePolicyRole": "normal",
				"config": map[string]any{"listen": "127.0.0.1", "port": port, "protocol": protocol},
			}}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestListenerPolicyTransportHelper$")
			cmd.Env = append(os.Environ(), "SECDNS_POLICY_TEST_CONFIG="+string(raw))
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

			endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			ask := func(source string) (*dns.Msg, error) {
				var local net.Addr
				if protocol == "udp" {
					local = &net.UDPAddr{IP: net.ParseIP(source)}
				} else {
					local = &net.TCPAddr{IP: net.ParseIP(source)}
				}
				client := &dns.Client{Net: protocol, Timeout: 300 * time.Millisecond, Dialer: &net.Dialer{LocalAddr: local}}
				query := new(dns.Msg)
				query.SetQuestion("same.invalid.", dns.TypeA)
				deadline := time.Now().Add(5 * time.Second)
				var lastErr error
				for {
					answer, _, err := client.Exchange(query, endpoint)
					if err == nil {
						return answer, nil
					}
					lastErr = err
					if time.Now().After(deadline) {
						return nil, lastErr
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			assertAddress := func(source, want string) error {
				answer, err := ask(source)
				if err != nil {
					return err
				}
				if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
					return fmt.Errorf("source %s: %v", source, answer)
				}
				record, ok := answer.Answer[0].(*dns.A)
				if !ok || record.A.String() != want {
					return fmt.Errorf("source %s: %v", source, answer.Answer)
				}
				return nil
			}

			// Reversing request order proves neither cache can satisfy the other
			// policy's identical question.
			for _, pair := range [][2]string{{"127.0.0.1", "192.0.2.10"}, {"127.0.0.2", "192.0.2.20"}, {"127.0.0.2", "192.0.2.20"}, {"127.0.0.1", "192.0.2.10"}} {
				if err := assertAddress(pair[0], pair[1]); err != nil {
					t.Fatal(err)
				}
			}
			var group sync.WaitGroup
			for n := 0; n < 8; n++ {
				group.Add(1)
				go func(index int) {
					defer group.Done()
					if index%2 == 0 {
						if err := assertAddress("127.0.0.1", "192.0.2.10"); err != nil {
							t.Error(err)
						}
					} else {
						if err := assertAddress("127.0.0.2", "192.0.2.20"); err != nil {
							t.Error(err)
						}
					}
				}(n)
			}
			group.Wait()
		})
	}
}

type taggedUDPObservation struct {
	name   string
	source string
}

type taggedUDPUpstream struct {
	connection net.PacketConn
	port       int
	tag        string

	mu           sync.Mutex
	observations []taggedUDPObservation
}

func startTaggedUDPUpstream(t *testing.T, network, host, tag string) *taggedUDPUpstream {
	t.Helper()
	connection, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	upstream := &taggedUDPUpstream{connection: connection, tag: tag}
	switch address := connection.LocalAddr().(type) {
	case *net.UDPAddr:
		upstream.port = address.Port
	default:
		connection.Close()
		t.Fatalf("unexpected upstream address %T", address)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		buffer := make([]byte, 64<<10)
		for {
			n, peer, readErr := connection.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			var query dns.Msg
			if unpackErr := query.Unpack(buffer[:n]); unpackErr != nil {
				t.Errorf("%s upstream unpack: %v", tag, unpackErr)
				continue
			}
			if len(query.Question) != 1 {
				t.Errorf("%s upstream question count: %d", tag, len(query.Question))
				continue
			}
			peerAddress, ok := peer.(*net.UDPAddr)
			if !ok {
				t.Errorf("%s upstream peer type: %T", tag, peer)
				continue
			}
			upstream.mu.Lock()
			upstream.observations = append(upstream.observations, taggedUDPObservation{
				name: query.Question[0].Name, source: peerAddress.IP.String(),
			})
			upstream.mu.Unlock()

			answer := new(dns.Msg)
			answer.SetReply(&query)
			answer.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{tag},
			}}
			wire, packErr := answer.Pack()
			if packErr != nil {
				t.Errorf("%s upstream pack: %v", tag, packErr)
				continue
			}
			if _, writeErr := connection.WriteTo(wire, peer); writeErr != nil {
				return
			}
		}
	}()
	return upstream
}

func (u *taggedUDPUpstream) snapshot() []taggedUDPObservation {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]taggedUDPObservation(nil), u.observations...)
}

// TestObservedEgressPolicyComposition is a local resolver-policy regression.
// Its upstream labels mirror the observed RouterHK classes, but it does not
// emulate policy routing, NAT64 translation, or any production interface.
func TestObservedEgressPolicyComposition(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			defaultUpstream := startTaggedUDPUpstream(t, "udp4", "127.0.0.1", "default-source")
			hkt2IPv4 := startTaggedUDPUpstream(t, "udp4", "127.0.0.1", "hkt2-ipv4")
			mainIPv6 := startTaggedUDPUpstream(t, "udp6", "::1", "main-native-ipv6")
			hkt2NAT64 := startTaggedUDPUpstream(t, "udp6", "::1", "hkt2-nat64-destination")

			dnsPort := freeTransportPort(t, protocol)
			const (
				ipv4Name  = "ipv4-upstream.invalid."
				nativeV6  = "native-ipv6-upstream.invalid."
				nat64Name = "nat64-destination.invalid."
			)
			nameServer := func(address, sendThrough string, port int) map[string]any {
				return map[string]any{
					"address": address, "port": port, "protocol": "udp",
					"queryTimeout": 0.5, "sendThrough": sendThrough,
				}
			}
			config := map[string]any{
				"listeners": []any{map[string]any{
					"type": "dnsServer", "sourcePolicyRole": "normal",
					"config": map[string]any{"listen": "127.0.0.1", "port": dnsPort, "protocol": protocol},
				}},
				"resolvers": map[string]any{
					"nameServer": map[string]any{
						"default-upstream": nameServer("127.0.0.1", "127.0.0.1", defaultUpstream.port),
						"hkt2-ipv4":        nameServer("127.0.0.1", "127.0.0.2", hkt2IPv4.port),
						"main-native-ipv6": nameServer("::1", "::1", mainIPv6.port),
						"hkt2-nat64":       nameServer("::1", "::1", hkt2NAT64.port),
					},
					"policy": map[string]any{
						"default-policy": map[string]any{"rules": []any{}, "defaultResolver": "default-upstream"},
						"observed-hkt2-policy": map[string]any{
							"rules": []any{map[string]any{"type": "collection", "config": []any{
								map[string]any{"name": strconv.Quote(ipv4Name), "resolver": "hkt2-ipv4"},
								map[string]any{"name": strconv.Quote(nativeV6), "resolver": "main-native-ipv6"},
								map[string]any{"name": strconv.Quote(nat64Name), "resolver": "hkt2-nat64"},
							}}},
							"defaultResolver": "hkt2-ipv4",
						},
					},
					"cache": map[string]any{
						"default-cache": map[string]any{"resolver": "default-policy", "maxEntries": 32},
						"hkt2-cache":    map[string]any{"resolver": "observed-hkt2-policy", "maxEntries": 32},
					},
				},
				"sourcePolicy": map[string]any{
					"sourceSets": []any{map[string]any{
						"id": "observed-hkt2-source", "members": []any{map[string]any{"prefix": "127.0.0.2/32"}},
					}},
					"rules": []any{map[string]any{
						"listenerRole": "normal", "sourceSet": "observed-hkt2-source", "resolver": "hkt2-cache",
					}},
					"defaults": []any{map[string]any{"listenerRole": "normal", "resolver": "default-cache"}},
				},
				"rules": []any{}, "defaultResolver": "default-cache",
			}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateConfig(strings.NewReader(string(raw))); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestListenerPolicyTransportHelper$")
			cmd.Env = append(os.Environ(), "SECDNS_POLICY_TEST_CONFIG="+string(raw))
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

			endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))
			ask := func(source, name, wantTag string) {
				t.Helper()
				var local net.Addr
				if protocol == "udp" {
					local = &net.UDPAddr{IP: net.ParseIP(source)}
				} else {
					local = &net.TCPAddr{IP: net.ParseIP(source)}
				}
				client := &dns.Client{Net: protocol, Timeout: 300 * time.Millisecond, Dialer: &net.Dialer{LocalAddr: local}}
				query := new(dns.Msg)
				query.SetQuestion(name, dns.TypeTXT)
				deadline := time.Now().Add(5 * time.Second)
				for {
					answer, _, exchangeErr := client.Exchange(query, endpoint)
					if exchangeErr == nil {
						if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
							t.Fatalf("source %s name %s: %v", source, name, answer)
						}
						txt, ok := answer.Answer[0].(*dns.TXT)
						if !ok || len(txt.Txt) != 1 || txt.Txt[0] != wantTag {
							t.Fatalf("source %s name %s: %v", source, name, answer.Answer)
						}
						return
					}
					if time.Now().After(deadline) {
						t.Fatal(exchangeErr)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}

			// Prime the same names through both source-selected graphs in mixed order.
			ask("127.0.0.2", ipv4Name, "hkt2-ipv4")
			ask("127.0.0.1", ipv4Name, "default-source")
			ask("127.0.0.1", nativeV6, "default-source")
			ask("127.0.0.2", nativeV6, "main-native-ipv6")
			ask("127.0.0.2", nat64Name, "hkt2-nat64-destination")
			ask("127.0.0.1", nat64Name, "default-source")
			// Reversing the second pass proves the final-answer caches remain disjoint.
			for _, name := range []string{nat64Name, nativeV6, ipv4Name} {
				ask("127.0.0.1", name, "default-source")
			}
			for name, tag := range map[string]string{
				ipv4Name: "hkt2-ipv4", nativeV6: "main-native-ipv6", nat64Name: "hkt2-nat64-destination",
			} {
				ask("127.0.0.2", name, tag)
			}

			assertObservations := func(upstream *taggedUDPUpstream, want map[string]string) {
				t.Helper()
				observed := upstream.snapshot()
				if len(observed) != len(want) {
					t.Fatalf("%s observations: %+v", upstream.tag, observed)
				}
				for _, item := range observed {
					if wantSource, ok := want[item.name]; !ok || item.source != wantSource {
						t.Fatalf("%s unexpected observation: %+v", upstream.tag, item)
					}
				}
			}
			assertObservations(defaultUpstream, map[string]string{
				ipv4Name: "127.0.0.1", nativeV6: "127.0.0.1", nat64Name: "127.0.0.1",
			})
			assertObservations(hkt2IPv4, map[string]string{ipv4Name: "127.0.0.2"})
			assertObservations(mainIPv6, map[string]string{nativeV6: "::1"})
			assertObservations(hkt2NAT64, map[string]string{nat64Name: "::1"})
		})
	}
}
