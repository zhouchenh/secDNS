// secdns-health-query performs one bounded DNS health query. It never serves DNS.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

type reply struct {
	Outcome  string         `json:"outcome"`
	Rcode    int            `json:"rcode"`
	Question []dns.Question `json:"question"`
	Answers  []string       `json:"answers"`
}

func execute(args []string, output io.Writer) int {
	fail := func(outcome string) int {
		_ = json.NewEncoder(output).Encode(map[string]string{"outcome": outcome})
		return 1
	}
	if len(args) != 6 || args[0] != "query" || (args[1] != "udp" && args[1] != "tcp") {
		return fail("invalid_arguments")
	}
	host, port, err := net.SplitHostPort(args[2])
	if err != nil || net.ParseIP(host) == nil {
		return fail("invalid_arguments")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fail("invalid_arguments")
	}
	timeout, err := strconv.Atoi(args[5])
	if err != nil || timeout < 500 || timeout > 2500 {
		return fail("invalid_arguments")
	}
	qtype := uint16(dns.TypeA)
	if args[4] == "AAAA" {
		qtype = dns.TypeAAAA
	} else if args[4] != "A" {
		return fail("invalid_arguments")
	}
	name := dns.Fqdn(args[3])
	if _, ok := dns.IsDomainName(name); !ok || args[3] == "" {
		return fail("invalid_arguments")
	}
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	client := &dns.Client{Net: args[1], Timeout: time.Duration(timeout) * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()
	response, _, err := client.ExchangeContext(ctx, q, args[2])
	if err != nil {
		var network net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &network) && network.Timeout()) {
			return fail("timeout")
		}
		return fail("network_error")
	}
	if response == nil {
		return fail("network_error")
	}
	result := reply{Outcome: "response", Rcode: response.Rcode, Question: response.Question, Answers: make([]string, 0, len(response.Answer))}
	for _, rr := range response.Answer {
		result.Answers = append(result.Answers, rr.String())
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return 1
	}
	return 0
}
func main() { os.Exit(execute(os.Args[1:], os.Stdout)) }
