package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/internal/upstream/diagnostics"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type DoH struct {
	URL                   *url.URL
	QueryTimeout          time.Duration
	TlsServerName         string
	SendThrough           net.IP
	Resolver              resolver.Resolver
	Socks5Proxy           string
	Socks5Username        string
	Socks5Password        string
	EcsMode               string
	EcsClientSubnet       string
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	MaxConcurrentRequests int
	ecsConfig             *ecs.Config
	queryClient           *client
	requestLimiter        chan struct{}
	initOnce              sync.Once
	refreshMutex          sync.Mutex
	refreshing            bool
	refreshDone           chan struct{}
	refreshAfter          time.Time
}

type client struct {
	httpClient   *http.Client
	serverName   string
	resolvedURLs []string
	urlMutex     sync.RWMutex
}

var typeOfDoH = descriptor.TypeOfNew(new(*DoH))

func (d *DoH) Type() descriptor.Type {
	return typeOfDoH
}

func (d *DoH) TypeName() string {
	return "doh"
}

func (d *DoH) acquireRequestSlot(ctx context.Context) (func(), error) {
	if d.requestLimiter == nil || d.MaxConcurrentRequests <= 0 {
		return func() {}, ctx.Err()
	}
	select {
	case d.requestLimiter <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-d.requestLimiter
			return nil, err
		}
		return func() { <-d.requestLimiter }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// refreshURLs coalesces failed-request bootstrap work. The Resolver interface
// cannot cancel bootstrap lookups, so at most one such worker may exist per
// DoH instance, including after any caller's deadline. Warm queries never wait for it.
// Empty results never replace a previously usable endpoint snapshot.
func (d *DoH) refreshURLs(query *dns.Msg, depth int) <-chan struct{} {
	d.refreshMutex.Lock()
	if d.refreshing || time.Now().Before(d.refreshAfter) {
		done := d.refreshDone
		d.refreshMutex.Unlock()
		return done
	}
	d.refreshDone = make(chan struct{})
	done := d.refreshDone
	d.refreshing = true
	d.refreshAfter = time.Now().Add(time.Second)
	d.refreshMutex.Unlock()
	copied := query.Copy()
	go func() {
		defer func() { d.refreshMutex.Lock(); d.refreshing = false; close(done); d.refreshMutex.Unlock() }()
		trace := diagnostics.Begin(copied, "doh.failed_refresh")
		defer trace.End("complete")
		urls := d.resolveURL(depth)
		if len(urls) > 0 {
			d.queryClient.urlMutex.Lock()
			d.queryClient.resolvedURLs = urls
			d.queryClient.urlMutex.Unlock()
		}
	}()
	return done
}

func (d *DoH) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	trace := diagnostics.Begin(query, "doh.resolve")
	defer trace.End("complete")
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	d.initOnce.Do(func() { d.initClient() })
	// Initial endpoint bootstrap retains its existing resolver semantics. Once
	// initialized, the request budget covers slot wait, HTTP headers and body.
	ctx, cancel := context.WithCancel(context.Background())
	if d.QueryTimeout > 0 {
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), d.QueryTimeout)
	}
	defer cancel()
	if d.ecsConfig != nil {
		copied := query.Copy()
		if err := d.ecsConfig.ApplyToQuery(copied); err != nil {
			return nil, err
		}
		query = copied
	}
	wire, err := query.Pack()
	if err != nil {
		return nil, err
	}
	d.queryClient.urlMutex.RLock()
	urls := append([]string(nil), d.queryClient.resolvedURLs...)
	d.queryClient.urlMutex.RUnlock()
	if len(urls) == 0 {
		// An empty snapshot may recover the same query, but only within its budget.
		done := d.refreshURLs(query, depth-1)
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		d.queryClient.urlMutex.RLock()
		urls = append([]string(nil), d.queryClient.resolvedURLs...)
		d.queryClient.urlMutex.RUnlock()
		if len(urls) == 0 {
			return nil, UnknownHostError(d.URL.Hostname())
		}
	}
	type result struct {
		msg *dns.Msg
		err error
	}
	results := make(chan result, len(urls))
	for _, urlString := range urls {
		go func(urlString string) {
			queued := diagnostics.Begin(query, "doh.slot_wait")
			release, e := d.acquireRequestSlot(ctx)
			if e != nil {
				queued.End("canceled")
				results <- result{err: e}
				return
			}
			queued.End("acquired")
			defer release()
			active := diagnostics.Begin(query, "doh.http")
			outcome := "error"
			defer func() { active.End(outcome) }()
			request, e := http.NewRequestWithContext(ctx, http.MethodPost, urlString, bytes.NewReader(wire))
			if e != nil {
				results <- result{err: e}
				return
			}
			request.Host = d.queryClient.serverName
			request.Header.Set("Accept", "application/dns-message")
			request.Header.Set("Content-Type", "application/dns-message")
			response, e := d.queryClient.httpClient.Do(request)
			if e != nil {
				results <- result{err: e}
				return
			}
			defer response.Body.Close()
			body, e := io.ReadAll(response.Body)
			if e != nil {
				results <- result{err: e}
				return
			}
			msg := new(dns.Msg)
			if e = msg.Unpack(body); e != nil {
				results <- result{err: e}
				return
			}
			outcome = "response"
			results <- result{msg: msg}
		}(urlString)
	}
	var last error
	for range urls {
		select {
		case r := <-results:
			if r.err == nil {
				return r.msg, nil
			}
			last = r.err
		case <-ctx.Done():
			d.refreshURLs(query, depth-1)
			return nil, ctx.Err()
		}
	}
	d.refreshURLs(query, depth-1)
	if last == nil {
		last = UnknownHostError(d.URL.Hostname())
	}
	return nil, last
}

func (d *DoH) NameServerResolver() {}

func (d *DoH) initClient() {
	serverName := d.serverName()
	resolvedURLs := d.resolveURL(64)
	var proxyFunc func(*http.Request) (*url.URL, error)
	if d.Socks5Proxy != "" {
		var user *url.Userinfo
		if d.Socks5Username != "" || d.Socks5Password != "" {
			user = url.UserPassword(d.Socks5Username, d.Socks5Password)
		}
		u := &url.URL{
			Scheme: "socks5",
			User:   user,
			Host:   d.Socks5Proxy,
		}
		proxyFunc = func(*http.Request) (*url.URL, error) {
			return u, nil
		}
	}

	if d.MaxIdleConnsPerHost == 0 {
		d.MaxIdleConnsPerHost = 32
	}
	if d.MaxConnsPerHost == 0 {
		d.MaxConnsPerHost = 128
	}
	if d.IdleConnTimeout == 0 {
		d.IdleConnTimeout = 90 * time.Second
	}
	if d.MaxConcurrentRequests <= 0 {
		d.MaxConcurrentRequests = 256
	}
	d.requestLimiter = make(chan struct{}, d.MaxConcurrentRequests)

	d.queryClient = &client{
		httpClient: &http.Client{
			Transport: &http.Transport{
				// Custom dialing and SNI otherwise disable automatic HTTP/2 negotiation.
				// Multiplexing lets canceled queries release streams without closing healthy TLS connections.
				ForceAttemptHTTP2: true,
				DialContext: (&net.Dialer{
					LocalAddr: &net.TCPAddr{IP: d.SendThrough},
				}).DialContext,
				Proxy: proxyFunc,
				TLSClientConfig: &tls.Config{
					ServerName: serverName,
				},
				MaxIdleConns:        d.MaxIdleConnsPerHost * 2,
				MaxIdleConnsPerHost: d.MaxIdleConnsPerHost,
				MaxConnsPerHost:     d.MaxConnsPerHost,
				IdleConnTimeout:     d.IdleConnTimeout,
			},
			Timeout: d.QueryTimeout,
		},
		serverName:   serverName,
		resolvedURLs: resolvedURLs,
	}

	// Initialize ECS configuration if specified
	if d.EcsMode != "" || d.EcsClientSubnet != "" {
		cfg, err := ecs.ParseConfig(d.EcsMode, d.EcsClientSubnet)
		if err != nil {
			common.ErrOutput(err)
		} else {
			d.ecsConfig = cfg
		}
	}
}

func (d *DoH) serverName() string {
	if d.TlsServerName != "" {
		return d.TlsServerName
	}
	if d.URL != nil {
		return d.URL.Hostname()
	}
	return ""
}

func (d *DoH) resolveURL(resolutionDepth int) (resolvedURLs []string) {
	if d.URL == nil {
		return
	}
	hostname := d.URL.Hostname()
	seen := make(map[string]struct{})
	appendURL := func(ip net.IP) {
		if ip == nil {
			return
		}
		urlStruct := *d.URL
		var host string
		if port := d.URL.Port(); port != "" {
			host = net.JoinHostPort(ip.String(), port)
		} else {
			if ip.To4() != nil {
				host = ip.String()
			} else {
				host = "[" + ip.String() + "]"
			}
		}
		urlStruct.Host = host
		urlStr := urlStruct.String()
		if _, ok := seen[urlStr]; ok {
			return
		}
		seen[urlStr] = struct{}{}
		resolvedURLs = append(resolvedURLs, urlStr)
	}
	if ip := net.ParseIP(hostname); ip != nil {
		appendURL(ip)
	}
	if common.IsDomainName(hostname) {
		hostname = common.EnsureFQDN(hostname)
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			if d.Resolver == nil {
				break
			}
			query := new(dns.Msg)
			query.SetQuestion(hostname, qtype)
			reply, err := d.Resolver.Resolve(query, resolutionDepth)
			if err != nil {
				continue
			}
			for _, rawRecord := range reply.Answer {
				switch record := rawRecord.(type) {
				case *dns.A:
					appendURL(record.A)
				case *dns.AAAA:
					appendURL(record.AAAA)
				}
			}
		}
	}
	return
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfDoH,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"URL"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"url"},
					AssignableKind: descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							str, ok := original.(string)
							if !ok {
								return
							}
							converted, err := url.Parse(str)
							ok = err == nil
							return
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"QueryTimeout"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"queryTimeout"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.ConvertibleKind{
								Kind: descriptor.KindFloat64,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									num, ok := original.(float64)
									if !ok {
										return
									}
									return time.Duration(num * float64(time.Second)), true
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									str, ok := original.(string)
									if !ok {
										return
									}
									num, err := strconv.ParseFloat(str, 64)
									if err != nil {
										return nil, false
									}
									return time.Duration(num * float64(time.Second)), true
								},
							},
						},
					},
					descriptor.DefaultValue{Value: 8 * time.Second},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"TlsServerName"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"tlsServerName"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"SendThrough"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"sendThrough"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return
								}
								converted = net.ParseIP(str)
								ok = converted != nil
								return
							},
						},
					},
					descriptor.DefaultValue{Value: nil},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"MaxIdleConnsPerHost"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"maxIdleConnsPerHost"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.ConvertibleKind{
								Kind: descriptor.KindFloat64,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									num, ok := original.(float64)
									if !ok || num < 0 {
										return nil, false
									}
									return int(num), true
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									str, ok := original.(string)
									if !ok {
										return nil, false
									}
									i, err := strconv.Atoi(str)
									if err != nil || i < 0 {
										return nil, false
									}
									return i, true
								},
							},
						},
					},
					descriptor.DefaultValue{Value: 32},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"MaxConnsPerHost"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"maxConnsPerHost"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.ConvertibleKind{
								Kind: descriptor.KindFloat64,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									num, ok := original.(float64)
									if !ok || num < 0 {
										return nil, false
									}
									return int(num), true
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									str, ok := original.(string)
									if !ok {
										return nil, false
									}
									i, err := strconv.Atoi(str)
									if err != nil || i < 0 {
										return nil, false
									}
									return i, true
								},
							},
						},
					},
					descriptor.DefaultValue{Value: 128},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"IdleConnTimeout"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"idleConnTimeout"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.ConvertibleKind{
								Kind: descriptor.KindFloat64,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									num, ok := original.(float64)
									if !ok || num < 0 {
										return nil, false
									}
									return time.Duration(num * float64(time.Second)), true
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									str, ok := original.(string)
									if !ok {
										return nil, false
									}
									num, err := strconv.ParseFloat(str, 64)
									if err != nil || num < 0 {
										return nil, false
									}
									return time.Duration(num * float64(time.Second)), true
								},
							},
						},
					},
					descriptor.DefaultValue{Value: 90 * time.Second},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"MaxConcurrentRequests"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"maxConcurrentRequests"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.ConvertibleKind{
								Kind: descriptor.KindFloat64,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									num, ok := original.(float64)
									if !ok || num < 0 {
										return nil, false
									}
									return int(num), true
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									str, ok := original.(string)
									if !ok {
										return nil, false
									}
									i, err := strconv.Atoi(str)
									if err != nil || i < 0 {
										return nil, false
									}
									return i, true
								},
							},
						},
					},
					descriptor.DefaultValue{Value: 256},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Resolver"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"urlResolver"},
						AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
							object, s, f := resolver.Descriptor().Describe(i)
							ok = s > 0 && f < 1
							return
						}),
					},
					descriptor.ObjectAtPath{
						AssignableKind: descriptor.AssignmentFunction(func(interface{}) (object interface{}, ok bool) {
							object, s, f := resolver.Descriptor().Describe("")
							ok = s > 0 && f < 1
							return
						}),
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Socks5Proxy"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"socks5Proxy"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Socks5Username"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"socks5Username"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Socks5Password"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"socks5Password"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"EcsMode"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"ecsMode"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return
								}
								// Validate mode
								if !ecs.ValidateMode(str) {
									return nil, false
								}
								return str, true
							},
						},
					},
					descriptor.DefaultValue{Value: string(ecs.ModePassthrough)},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"EcsClientSubnet"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"ecsClientSubnet"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return
								}
								// Empty string is valid (will be validated with mode later)
								if str == "" {
									return str, true
								}
								// Validate CIDR format
								_, _, err := ecs.ParseClientSubnet(str)
								if err != nil {
									return nil, false
								}
								return str, true
							},
						},
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

func (r *DoH) ResolverDependencies() []resolver.Resolver {
	if r.Resolver == nil {
		return nil
	}
	return []resolver.Resolver{r.Resolver}
}
