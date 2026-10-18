package snapshotfollower

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/authoritative"
)

var testEnrollment = recordstore.FollowerEnrollment{ClusterID: "cluster", Kind: recordstore.FollowerExactRecords, RulesetID: "rules", LineageID: "lineage", AuthorityEpoch: "epoch"}
var dnsStoreSequence atomic.Uint64

const testReaderToken = "reader-token-0123456789abcdef-0001"

func testSnapshot(t *testing.T, revision uint64, address string) []byte {
	return testSnapshotIdentity(t, "rules", "lineage", revision, address)
}

func testSnapshotIdentity(t *testing.T, ruleset, lineage string, revision uint64, address string) []byte {
	t.Helper()
	records := []recordset.Record{}
	if address != "" {
		records = append(records, recordset.Record{Name: "service.invalid.", Type: "A", Values: []string{address}, TTLSeconds: 30})
	}
	snapshot, err := recordset.New(ruleset, lineage, revision, records)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := snapshot.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func testConfig(serverURL, database string) Config {
	return Config{StoreName: "replica", SQLitePath: database, Enrollment: testEnrollment, NodeID: "node-one", AuthorityURL: serverURL + "/admin", Token: testReaderToken}
}

func waitStatus(t *testing.T, worker *Worker, predicate func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status := worker.Status()
		if predicate(status) {
			return status
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("worker status timed out", worker.Status())
	return Status{}
}

func TestFetchRequiresAccepted200BeforeETag(t *testing.T) {
	var mode atomic.Int32
	wire := testSnapshot(t, 1, "192.0.2.1")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testReaderToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if mode.Load() == 0 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Header.Get("If-None-Match") == `"revision-1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"revision-1"`)
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	worker, err := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "unused.db")), store, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	etag, initialized, category := worker.fetch(context.Background(), "", false)
	if category != errorProtocol || initialized || etag != "" {
		t.Fatal("prefetch 304 established state", etag, initialized, category)
	}
	if _, err = store.Acquire(); err != recordstore.ErrFollowerNotReady {
		t.Fatal("prefetch 304 published state", err)
	}
	mode.Store(1)
	etag, initialized, category = worker.fetch(context.Background(), "", false)
	if category != "" || !initialized || etag != `"revision-1"` || worker.Status().Revision != 1 {
		t.Fatal("accepted 200 did not establish validator", etag, initialized, category, worker.Status())
	}
	etag, initialized, category = worker.fetch(context.Background(), etag, initialized)
	if category != "" || !initialized || etag != `"revision-1"` {
		t.Fatal("valid conditional 304 failed", etag, initialized, category)
	}
}

func TestHTTPSWorkerSSEConvergenceAndCancellation(t *testing.T) {
	type authorityState struct {
		wire     []byte
		etag     string
		revision uint64
	}
	state := authorityState{wire: testSnapshot(t, 1, "192.0.2.1"), etag: `"revision-1"`, revision: 1}
	var stateMu sync.RWMutex
	notify := make(chan struct{}, 2)
	var conditional atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testReaderToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		stateMu.RLock()
		current := state
		stateMu.RUnlock()
		switch r.URL.Path {
		case "/admin/snapshot":
			if r.Header.Get("If-None-Match") != "" {
				conditional.Store(true)
			}
			if r.Header.Get("If-None-Match") == current.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", current.etag)
			_, _ = w.Write(current.wire)
		case "/admin/snapshot/events":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-notify:
			}
			stateMu.RLock()
			current = state
			stateMu.RUnlock()
			_, _ = fmt.Fprintf(w, "id: lineage:%d\nevent: snapshot-revision\ndata: {\"status\":\"advanced\",\"ruleset_id\":\"rules\",\"lineage_id\":\"lineage\",\"revision\":\"%d\"}\n\n", current.revision, current.revision)
			w.(http.Flusher).Flush()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	worker, err := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "unused.db")), store, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	worker.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); worker.Run(ctx) }()
	waitStatus(t, worker, func(status Status) bool {
		return status.Ready && status.Revision == 1 && status.ConnectionState == "streaming"
	})
	stateMu.Lock()
	state = authorityState{wire: testSnapshot(t, 2, "192.0.2.2"), etag: `"revision-2"`, revision: 2}
	stateMu.Unlock()
	notify <- struct{}{}
	status := waitStatus(t, worker, func(status Status) bool { return status.Revision == 2 })
	if !conditional.Load() || status.ContentSHA256 == "" || status.LastSuccess.IsZero() {
		t.Fatal("event did not cause conditional full fetch", conditional.Load(), status)
	}
	view, err := store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	record, ok := view.Lookup("service.invalid.", "A")
	if !ok || len(record.Values) != 1 || record.Values[0] != "192.0.2.2" {
		t.Fatal("durable follower did not converge", record, ok)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop before store close")
	}
	if worker.Status().ConnectionState != "stopped" {
		t.Fatal("stopped state not recorded", worker.Status())
	}
}

func TestHTTPSFollowerConvergesOverUDPAndTCPDNS(t *testing.T) {
	name := fmt.Sprintf("follower-dns-%d", dnsStoreSequence.Add(1))
	database := filepath.Join(t.TempDir(), "follower.db")
	cleanup, err := recordstore.PrepareBindingsWithFollowers(nil, nil, map[string]recordstore.FollowerConfig{
		name: {SQLitePath: database, Enrollment: testEnrollment, CreateIfMissing: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := recordstore.FollowerBinding(name)
	state := struct {
		sync.RWMutex
		wire     []byte
		etag     string
		revision uint64
	}{wire: testSnapshot(t, 1, "192.0.2.10"), etag: `"dns-1"`, revision: 1}
	notify := make(chan struct{}, 1)
	authorityServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.RLock()
		wire, etag, revision := append([]byte(nil), state.wire...), state.etag, state.revision
		state.RUnlock()
		switch r.URL.Path {
		case "/admin/snapshot":
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			_, _ = w.Write(wire)
		case "/admin/snapshot/events":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-notify:
			}
			state.RLock()
			revision = state.revision
			state.RUnlock()
			_, _ = fmt.Fprintf(w, "id: lineage:%d\nevent: snapshot-revision\ndata: {\"status\":\"advanced\",\"ruleset_id\":\"rules\",\"lineage_id\":\"lineage\",\"revision\":\"%d\"}\n\n", revision, revision)
			w.(http.Flusher).Flush()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer authorityServer.Close()
	config := testConfig(authorityServer.URL, database)
	config.StoreName = name
	worker, err := newWithClient(config, store, authorityServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	worker.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); worker.Run(ctx) }()
	resolver := &authoritative.Authoritative{Store: name}
	dnsHandler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response, resolveErr := resolver.Resolve(request, 16)
		if resolveErr != nil {
			response = new(dns.Msg)
			response.SetRcode(request, dns.RcodeServerFailure)
		}
		_ = writer.WriteMsg(response)
	})
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpServer := &dns.Server{PacketConn: udpConn, Handler: dnsHandler}
	go func() { _ = udpServer.ActivateAndServe() }()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: dnsHandler}
	go func() { _ = tcpServer.ActivateAndServe() }()
	queryAddress := func(network, address, want string) {
		t.Helper()
		query := new(dns.Msg)
		query.SetQuestion("service.invalid.", dns.TypeA)
		response, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(query, address)
		if err != nil || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != want {
			t.Fatalf("%s DNS answer = %v error %v, want %s", network, response, err, want)
		}
	}
	waitStatus(t, worker, func(status Status) bool {
		return status.Ready && status.Revision == 1 && status.ConnectionState == "streaming"
	})
	queryAddress("udp", udpConn.LocalAddr().String(), "192.0.2.10")
	queryAddress("tcp", tcpListener.Addr().String(), "192.0.2.10")
	state.Lock()
	state.wire, state.etag, state.revision = testSnapshot(t, 2, "192.0.2.20"), `"dns-2"`, 2
	state.Unlock()
	notify <- struct{}{}
	waitStatus(t, worker, func(status Status) bool { return status.Revision == 2 })
	queryAddress("udp", udpConn.LocalAddr().String(), "192.0.2.20")
	queryAddress("tcp", tcpListener.Addr().String(), "192.0.2.20")
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker shutdown timed out")
	}
	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableRestartStillRequiresFresh200(t *testing.T) {
	database := filepath.Join(t.TempDir(), "follower.db")
	store, err := recordstore.CreateFollowerSQLite(database, testEnrollment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Accept(testEnrollment, testSnapshot(t, 7, "192.0.2.7")); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	store, err = recordstore.OpenFollowerSQLite(database, testEnrollment)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var validator string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validator = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	worker, err := newWithClient(testConfig(server.URL, database), store, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !worker.Status().Ready || worker.Status().Revision != 7 {
		t.Fatal("durable last-good not reflected at restart", worker.Status())
	}
	_, initialized, category := worker.fetch(context.Background(), "", false)
	if validator != "" || initialized || category != errorProtocol {
		t.Fatal("restarted worker reused an unestablished validator", validator, initialized, category)
	}
	if view, err := store.Acquire(); err != nil || view.State().Snapshot.Revision != 7 {
		t.Fatal("protocol refusal damaged last-good", err, view.State())
	}
}

func TestSSEBoundsAndMalformedEvents(t *testing.T) {
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	worker := &Worker{config: Config{Enrollment: testEnrollment}}
	valid := "id: lineage:2\nevent: snapshot-revision\ndata: {\"status\":\"advanced\",\"ruleset_id\":\"rules\",\"lineage_id\":\"lineage\",\"revision\":\"2\"}\n\n"
	if trigger, category := worker.consumeEvents(context.Background(), strings.NewReader(valid)); !trigger || category != "" {
		t.Fatal("valid event rejected", trigger, category)
	}
	staleResync := "id: lineage:1\nevent: snapshot-revision\ndata: {\"status\":\"resync\",\"ruleset_id\":\"rules\",\"lineage_id\":\"lineage\",\"revision\":\"1\"}\n\n"
	if trigger, category := worker.consumeEvents(context.Background(), strings.NewReader(staleResync)); !trigger || category != "" {
		t.Fatal("stale resync hint did not request a full fetch", trigger, category)
	}
	for name, body := range map[string]string{
		"line":      "data: " + strings.Repeat("x", maxSSELineBytes) + "\n\n",
		"event":     strings.Repeat(": comment\n", maxSSEEventBytes/3),
		"stream":    strings.Repeat(":\n\n", maxSSEStreamBytes/2),
		"truncated": strings.TrimSuffix(valid, "\n\n"),
		"unknown":   strings.Replace(valid, "event:", "other:", 1),
		"lineage":   strings.Replace(valid, `"lineage_id":"lineage"`, `"lineage_id":"other"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if trigger, category := worker.consumeEvents(context.Background(), strings.NewReader(body)); trigger || category != errorProtocol && category != errorTransport {
				t.Fatal("malformed stream admitted", trigger, category)
			}
		})
	}
}

func TestProductionClientHasNoProxyAndRejectsRedirect(t *testing.T) {
	client := productionClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.MaxConnsPerHost != 1 || transport.MaxResponseHeaderBytes != 16<<10 {
		t.Fatal("unsafe transport defaults")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://second.invalid/", nil)
	if client.CheckRedirect(request, []*http.Request{{}}) == nil {
		t.Fatal("redirect accepted")
	}
	for _, invalid := range []string{"http://authority.invalid/admin", "https://:443/admin", "https://user@authority.invalid/admin", "https://authority.invalid/admin?q=x", "https://authority.invalid/admin/", "https://authority.invalid/a//b"} {
		config := testConfig("https://authority.invalid", filepath.Join(t.TempDir(), "db"))
		config.AuthorityURL = invalid
		if ValidateConfig(config) == nil {
			t.Fatal("invalid authority accepted", invalid)
		}
	}
	config := testConfig("https://authority.invalid", filepath.Join(t.TempDir(), "db"))
	config.Token = strings.Repeat("x", 31) + "é"
	if ValidateConfig(config) == nil {
		t.Fatal("non-ASCII bearer token accepted")
	}
}

func TestFetchRejectsAmbiguousETag(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("ETag", `"one"`)
		w.Header().Add("ETag", `"two"`)
		_, _ = w.Write(testSnapshot(t, 1, "192.0.2.1"))
	}))
	defer server.Close()
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	worker, _ := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "db")), store, server.Client())
	if etag, initialized, category := worker.fetch(context.Background(), "", false); etag != "" || initialized || category != errorProtocol {
		t.Fatal("ambiguous ETag admitted", etag, initialized, category)
	}
	if _, err := store.Acquire(); !errors.Is(err, recordstore.ErrFollowerNotReady) {
		t.Fatal("ambiguous ETag published state", err)
	}
}

func TestStreamRequiresExactEventMediaType(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-streamx")
		_, _ = io.WriteString(w, "event: snapshot-revision\n\n")
	}))
	defer server.Close()
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	if _, err := store.Accept(testEnrollment, testSnapshot(t, 1, "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	worker, _ := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "db")), store, server.Client())
	if trigger, category := worker.stream(context.Background()); trigger || category != errorProtocol {
		t.Fatal("near-match event media type admitted", trigger, category)
	}
}

func TestTLSRedirectAndStallFailuresPublishNothing(t *testing.T) {
	t.Run("untrusted certificate", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("ETag", `"unexpected"`)
			_, _ = w.Write(testSnapshot(t, 1, "192.0.2.1"))
		}))
		defer server.Close()
		store, _ := recordstore.NewFollowerMemory(testEnrollment)
		defer store.Close()
		worker, err := New(testConfig(server.URL, filepath.Join(t.TempDir(), "db")), store)
		if err != nil {
			t.Fatal(err)
		}
		_, initialized, category := worker.fetch(context.Background(), "", false)
		if initialized || category != errorTransport {
			t.Fatal("untrusted TLS published state", initialized, category)
		}
	})
	t.Run("wrong trust name", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("ETag", `"unexpected"`)
			_, _ = w.Write(testSnapshot(t, 1, "192.0.2.1"))
		}))
		defer server.Close()
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		client := server.Client()
		transport := client.Transport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		client.Transport = transport
		store, _ := recordstore.NewFollowerMemory(testEnrollment)
		defer store.Close()
		config := testConfig(strings.Replace(server.URL, "127.0.0.1", "localhost", 1), filepath.Join(t.TempDir(), "db"))
		worker, err := newWithClient(config, store, client)
		if err != nil {
			t.Fatal(err)
		}
		_, initialized, category := worker.fetch(context.Background(), "", false)
		if initialized || category != errorTransport {
			t.Fatal("wrong TLS name published state", initialized, category)
		}
	})
	t.Run("redirect", func(t *testing.T) {
		var targetReached atomic.Bool
		target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetReached.Store(true) }))
		defer target.Close()
		redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
		defer redirect.Close()
		client := redirect.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }
		store, _ := recordstore.NewFollowerMemory(testEnrollment)
		defer store.Close()
		worker, _ := newWithClient(testConfig(redirect.URL, filepath.Join(t.TempDir(), "db")), store, client)
		_, initialized, category := worker.fetch(context.Background(), "", false)
		if initialized || category != errorTransport || targetReached.Load() {
			t.Fatal("redirect escaped pinned origin", initialized, category, targetReached.Load())
		}
	})
	for _, phase := range []string{"headers", "body"} {
		t.Run("stalled "+phase, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "body" {
					w.Header().Set("ETag", `"partial"`)
					_, _ = io.WriteString(w, "{")
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer server.Close()
			store, _ := recordstore.NewFollowerMemory(testEnrollment)
			defer store.Close()
			worker, _ := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "db")), store, server.Client())
			worker.fetchTimeout = 25 * time.Millisecond
			_, initialized, category := worker.fetch(context.Background(), "", false)
			if initialized || category != errorTransport {
				t.Fatal("stalled transfer published state", initialized, category)
			}
			if _, err := store.Acquire(); err != recordstore.ErrFollowerNotReady {
				t.Fatal("stalled transfer changed follower", err)
			}
		})
	}
}

func TestRejectedSnapshotKeepsDurableLastGoodAndValidator(t *testing.T) {
	var wire atomic.Value
	wire.Store(testSnapshot(t, 2, "192.0.2.2"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"candidate"`)
		_, _ = w.Write(wire.Load().([]byte))
	}))
	defer server.Close()
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	worker, _ := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "db")), store, server.Client())
	etag, initialized, category := worker.fetch(context.Background(), "", false)
	if category != "" || !initialized || etag != `"candidate"` {
		t.Fatal(etag, initialized, category)
	}
	previous := worker.Status()
	for name, rejected := range map[string][]byte{
		"rollback":     testSnapshot(t, 1, "192.0.2.1"),
		"equivocation": testSnapshot(t, 2, "192.0.2.99"),
		"ruleset":      testSnapshotIdentity(t, "other", "lineage", 3, "192.0.2.3"),
		"lineage":      testSnapshotIdentity(t, "rules", "other", 3, "192.0.2.3"),
		"malformed":    []byte("{"),
	} {
		t.Run(name, func(t *testing.T) {
			wire.Store(rejected)
			returnedETag, returnedInitialized, category := worker.fetch(context.Background(), etag, initialized)
			if category != errorSnapshot || returnedETag != etag || returnedInitialized != initialized {
				t.Fatal("rejection changed validator state", returnedETag, returnedInitialized, category)
			}
			if current := worker.Status(); current.Revision != previous.Revision || current.ContentSHA256 != previous.ContentSHA256 {
				t.Fatal("rejection changed last-good status", previous, current)
			}
			view, err := store.Acquire()
			if err != nil || view.State().Snapshot.Revision != 2 {
				t.Fatal("rejection changed last-good store", err, view.State())
			}
		})
	}
	wire.Store(testSnapshot(t, 3, "192.0.2.2"))
	returnedETag, returnedInitialized, category := worker.fetch(context.Background(), etag, initialized)
	if category != "" || returnedETag != `"candidate"` || !returnedInitialized {
		t.Fatal("same-content higher revision rejected", returnedETag, returnedInitialized, category)
	}
	if current := worker.Status(); current.Revision != 3 || current.ContentSHA256 != previous.ContentSHA256 {
		t.Fatal("same-content advancement changed content identity", previous, current)
	}
}

func TestFetchStatusNeverContainsAuthorityOrCredential(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	worker, _ := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "db")), store, server.Client())
	_, _, category := worker.fetch(context.Background(), "", false)
	if category != errorAuth {
		t.Fatal(category)
	}
	statusText := fmt.Sprintf("%+v", worker.Status())
	if strings.Contains(statusText, server.URL) || strings.Contains(statusText, testReaderToken) {
		t.Fatal("status leaked authority material")
	}
}

func TestSnapshotBodyLimit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"oversized"`)
		_, _ = io.WriteString(w, strings.Repeat("x", recordset.MaxBytes+1))
	}))
	defer server.Close()
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	worker, _ := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "db")), store, server.Client())
	_, initialized, category := worker.fetch(context.Background(), "", false)
	if initialized || category != errorSnapshot {
		t.Fatal("oversized snapshot admitted", initialized, category)
	}
}
