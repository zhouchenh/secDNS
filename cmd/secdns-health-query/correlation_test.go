package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWireCorrelation(t *testing.T) {
	t.Setenv("SECDNS_QUERY_TRACE_SALT", strings.Repeat("ab", 32))
	t.Setenv("SECDNS_QUERY_TRACE_UNTIL", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
	for _, network := range []string{"udp", "tcp"} {
		for _, delay := range []time.Duration{0, 600 * time.Millisecond} {
			tokens := make(chan string, 1)
			endpoint := localServerObserved(t, network, delay, tokens)
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			old := os.Stderr
			os.Stderr = write
			var output bytes.Buffer
			code := execute([]string{"query", network, endpoint, "secdnshealth0123456789abcdef01234567.1-1-1-1.sslip.io.", "AAAA", "500"}, &output)
			os.Stderr = old
			write.Close()
			raw, _ := io.ReadAll(read)
			read.Close()
			var event struct {
				DialEnded    int64  `json:"dial_ended_unix_ms"`
				WriteStarted int64  `json:"write_started_unix_ms"`
				WriteEnded   int64  `json:"write_ended_unix_ms"`
				Started      int64  `json:"started_unix_ms"`
				Ended        int64  `json:"ended_unix_ms"`
				Correlation  string `json:"correlation"`
				Duration     int64  `json:"duration_ms"`
				Outcome      string `json:"outcome"`
			}
			if err := json.Unmarshal(raw, &event); err != nil {
				t.Fatal(string(raw), err)
			}
			if !(event.Started <= event.DialEnded && event.DialEnded <= event.WriteStarted && event.WriteStarted <= event.WriteEnded && event.WriteEnded <= event.Ended) {
				t.Fatal("wire timing order", event)
			}
			if event.Correlation == "" || event.Correlation != <-tokens {
				t.Fatal("wire token mismatch")
			}
			if delay == 0 && (code != 0 || event.Outcome != "response") {
				t.Fatal("response changed")
			}
			if delay > 0 && (code != 1 || event.Outcome != "exchange_error" || event.Duration < 450) {
				t.Fatal("deadline changed", event)
			}
		}
	}
}

type blockingWriter struct{ release chan struct{} }

func (w blockingWriter) Write(p []byte) (int, error) { <-w.release; return len(p), nil }
func TestDiagnosticWriteBounded(t *testing.T) {
	release := make(chan struct{})
	start := time.Now()
	emitExchange(blockingWriter{release}, map[string]string{"kind": "test"})
	close(release)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("blocked diagnostic delayed exit")
	}
}
