package config

import (
	"encoding/json"
	"github.com/miekg/dns"
	"net"
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
	failure := func(q *dns.Msg) *dns.Msg { r := new(dns.Msg); r.SetRcode(q, dns.RcodeServerFailure); return r }
	i.Listen(failure, failure, func(err error) {
		if err != nil {
			os.Exit(2)
		}
	})
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
