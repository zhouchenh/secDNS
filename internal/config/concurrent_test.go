package config

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

func concurrentConfig(address, name string) string {
	return fmt.Sprintf(`{"listeners":[{"type":"dnsServer","config":{"listen":"127.0.0.1","port":5353,"protocol":"udp"}}],"resolvers":{"address":{"shared":%q}},"rules":[],"defaultResolver":%q}`, address, name)
}

func TestConcurrentConfigTransactions(t *testing.T) {
	const workers = 16
	start := make(chan struct{})
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			<-start
			address := fmt.Sprintf("192.0.2.%d", worker+1)
			valid := concurrentConfig(address, "shared")
			invalid := concurrentConfig(address, fmt.Sprintf("absent-%d", worker))
			for attempt := 0; attempt < 30; attempt++ {
				if err := ValidateConfig(strings.NewReader(invalid)); err == nil {
					errors <- fmt.Errorf("worker %d: invalid config accepted", worker)
					return
				}
				if err := ValidateConfig(strings.NewReader(valid)); err != nil {
					errors <- fmt.Errorf("worker %d: valid preflight: %w", worker, err)
					return
				}
				instance, err := LoadConfig(strings.NewReader(valid))
				if err != nil {
					errors <- fmt.Errorf("worker %d: valid load: %w", worker, err)
					return
				}
				r, ok := instance.GetResolver()
				if !ok {
					errors <- fmt.Errorf("worker %d: missing resolver", worker)
					return
				}
				q := new(dns.Msg)
				q.SetQuestion("example.test.", dns.TypeA)
				answer, err := r.Resolve(q, 64)
				if err != nil || answer == nil || len(answer.Answer) != 1 {
					errors <- fmt.Errorf("worker %d: resolution failed: %v", worker, err)
					return
				}
				a, ok := answer.Answer[0].(*dns.A)
				if !ok || a.A.String() != address {
					errors <- fmt.Errorf("worker %d: resolver bound to another config: %v", worker, answer.Answer)
					return
				}
			}
		}(worker)
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
