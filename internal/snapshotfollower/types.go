package snapshotfollower

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordstore"
)

const (
	maxTokenBytes       = 512
	minTokenBytes       = 32
	defaultFetchTimeout = 10 * time.Second
	defaultEventTimeout = 35 * time.Second
	minBackoff          = 250 * time.Millisecond
	maxBackoff          = 5 * time.Second
)

var ErrConfig = errors.New("invalid direct follower configuration")

// Config pins one local follower to one operator-configured direct authority.
// AuthorityURL is never learned or changed by a response.
type Config struct {
	StoreName       string
	SQLitePath      string
	CreateIfMissing bool
	Enrollment      recordstore.FollowerEnrollment
	NodeID          string
	AuthorityURL    string
	Token           string
}

// Status is a sanitized in-process snapshot. It deliberately excludes source
// address, credentials, raw errors, records and TLS peer material.
type Status struct {
	NodeID          string
	RulesetID       string
	LineageID       string
	AuthorityEpoch  string
	Ready           bool
	Revision        uint64
	ContentSHA256   string
	LastSuccess     time.Time
	LastContact     time.Time
	StoreState      string
	ConnectionState string
	ErrorCategory   string
}

func validIdentity(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if len(value) < minTokenBytes || len(value) > maxTokenBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func parseAuthority(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return nil, ErrConfig
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if !strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "//") || path.Clean(u.Path) != u.Path || strings.HasSuffix(u.Path, "/") && u.Path != "/" {
		return nil, ErrConfig
	}
	return u, nil
}

// ValidateConfig is syntax-only and performs no filesystem or network I/O.
func ValidateConfig(config Config) error {
	if config.StoreName == "" || strings.TrimSpace(config.StoreName) != config.StoreName || config.SQLitePath == "" || !validIdentity(config.NodeID) || !validToken(config.Token) {
		return ErrConfig
	}
	if _, err := parseAuthority(config.AuthorityURL); err != nil {
		return err
	}
	if err := recordstore.ValidateBindingsWithFollowers(nil, nil, map[string]recordstore.FollowerConfig{
		config.StoreName: {SQLitePath: config.SQLitePath, Enrollment: config.Enrollment, CreateIfMissing: config.CreateIfMissing},
	}); err != nil {
		return ErrConfig
	}
	return nil
}

func productionClient() *http.Client {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           2,
		MaxIdleConnsPerHost:    1,
		MaxConnsPerHost:        1,
		IdleConnTimeout:        45 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		ExpectContinueTimeout:  time.Second,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused")
		},
	}
}

type Worker struct {
	config Config
	store  *recordstore.FollowerStore
	client *http.Client
	base   *url.URL

	statusMu     sync.RWMutex
	running      atomic.Bool
	status       Status
	now          func() time.Time
	sleep        func(context.Context, time.Duration) bool
	jitter       func(time.Duration) time.Duration
	fetchTimeout time.Duration
	eventTimeout time.Duration
}

// New constructs a worker with ordinary verified TLS roots and no proxy or
// redirect behavior. It does not start a goroutine or perform network I/O.
func New(config Config, store *recordstore.FollowerStore) (*Worker, error) {
	return newWithClient(config, store, productionClient())
}

func newWithClient(config Config, store *recordstore.FollowerStore, client *http.Client) (*Worker, error) {
	if ValidateConfig(config) != nil || store == nil || client == nil || client.Transport == nil {
		return nil, ErrConfig
	}
	base, _ := parseAuthority(config.AuthorityURL)
	w := &Worker{config: config, store: store, client: client, base: base, now: time.Now, fetchTimeout: defaultFetchTimeout, eventTimeout: defaultEventTimeout}
	w.sleep = func(ctx context.Context, duration time.Duration) bool {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	w.jitter = func(base time.Duration) time.Duration {
		upper := int64(base / 4)
		if upper < 1 {
			return base
		}
		n, err := rand.Int(rand.Reader, big.NewInt(upper+1))
		if err != nil {
			return base
		}
		return base + time.Duration(n.Int64())
	}
	w.status = Status{NodeID: config.NodeID, RulesetID: config.Enrollment.RulesetID, LineageID: config.Enrollment.LineageID, AuthorityEpoch: config.Enrollment.AuthorityEpoch, ConnectionState: "starting"}
	if view, err := store.Acquire(); err == nil {
		meta := view.State().Snapshot
		w.status.Ready = true
		w.status.Revision = meta.Revision
		w.status.ContentSHA256 = meta.ContentSHA256
	}
	return w, nil
}

func (w *Worker) Status() Status {
	w.statusMu.RLock()
	status := w.status
	w.statusMu.RUnlock()
	status.StoreState = "available"
	if _, err := w.store.Acquire(); err != nil {
		status.StoreState = "unavailable"
		if errors.Is(err, recordstore.ErrFollowerNotReady) {
			status.StoreState = "not_ready"
		}
	}
	return status
}

func (w *Worker) update(mutator func(*Status)) {
	w.statusMu.Lock()
	defer w.statusMu.Unlock()
	mutator(&w.status)
}

func (w *Worker) endpoint(suffix string) string {
	u := *w.base
	base := strings.TrimSuffix(u.Path, "/")
	u.Path = base + suffix
	return u.String()
}
