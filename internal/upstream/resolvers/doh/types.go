package doh

import (
	"bytes"
	"crypto/tls"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type DoH struct {
	URL             *url.URL
	QueryTimeout    time.Duration
	TlsServerName   string
	SendThrough     net.IP
	Resolver        resolver.Resolver
	Socks5Proxy     string
	Socks5Username  string
	Socks5Password  string
	EcsMode         string
	EcsClientSubnet string
	ecsConfig       *ecs.Config
	queryClient     *client
	initOnce        sync.Once
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

func (d *DoH) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	d.initOnce.Do(func() {
		d.initClient()
	})

	// Apply ECS configuration to query if configured
	if d.ecsConfig != nil {
		// Create a copy of the query to avoid modifying the original
		queryCopy := query.Copy()
		if err := d.ecsConfig.ApplyToQuery(queryCopy); err != nil {
			return nil, err
		}
		query = queryCopy
	}

	wireFormattedQuery, e := query.Pack()
	if e != nil {
		return nil, e
	}

	// Get a snapshot of URLs with read lock
	d.queryClient.urlMutex.RLock()
	urls := make([]string, len(d.queryClient.resolvedURLs))
	copy(urls, d.queryClient.resolvedURLs)
	d.queryClient.urlMutex.RUnlock()

	once := new(sync.Once)
	msg := make(chan *dns.Msg)
	err := make(chan error)
	errCollector := make(chan error, len(urls))
	wg := new(sync.WaitGroup)
	wg.Add(len(urls))
	sendRequest := func(urlString string) {
		defer wg.Done()
		request, e := http.NewRequest(http.MethodPost, urlString, bytes.NewReader(wireFormattedQuery))
		if e != nil {
			errCollector <- e
			return
		}
		request.Host = d.queryClient.serverName
		request.Header.Set("Accept", "application/dns-message")
		request.Header.Set("Content-Type", "application/dns-message")
		response, e := d.queryClient.httpClient.Do(request)
		if e != nil {
			errCollector <- e
			return
		}
		defer response.Body.Close()
		wireFormattedMsg, e := ioutil.ReadAll(response.Body)
		if e != nil {
			errCollector <- e
			return
		}
		m := new(dns.Msg)
		e = m.Unpack(wireFormattedMsg)
		if e != nil {
			errCollector <- e
			return
		}
		once.Do(func() {
			msg <- m
			err <- nil
		})
	}
	for _, urlString := range urls {
		go sendRequest(urlString)
	}
	go func() {
		wg.Wait()
		once.Do(func() {
			resolvedURLs := d.resolveURL(depth - 1)
			if len(resolvedURLs) < 1 {
				if len(errCollector) < 1 {
					msg <- nil
					err <- UnknownHostError(d.URL.Hostname())
					return
				}
			} else {
				// Update URL list with write lock
				d.queryClient.urlMutex.Lock()
				d.queryClient.resolvedURLs = resolvedURLs
				d.queryClient.urlMutex.Unlock()

				if len(errCollector) < 1 {
					m, e := d.Resolve(query, depth-1)
					msg <- m
					err <- e
					return
				}
			}
			msg <- nil
			// Safely drain errCollector
			if len(errCollector) > 0 {
				for len(errCollector) > 1 {
					<-errCollector
				}
				err <- <-errCollector
			} else {
				err <- UnknownHostError(d.URL.Hostname())
			}
		})
	}()
	return <-msg, <-err
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
	d.queryClient = &client{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					LocalAddr: &net.TCPAddr{IP: d.SendThrough},
				}).DialContext,
				Proxy: proxyFunc,
				TLSClientConfig: &tls.Config{
					ServerName: serverName,
				},
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
	if ip := net.ParseIP(hostname); ip != nil {
		resolvedURLs = append(resolvedURLs, d.URL.String())
	}
	if common.IsDomainName(hostname) {
		hostname = common.EnsureFQDN(hostname)
		query := new(dns.Msg)
		query.SetQuestion(hostname, dns.TypeA)
		reply, err := d.Resolver.Resolve(query, resolutionDepth)
		if err != nil {
			return
		}
		for _, rawRecord := range reply.Answer {
			record, ok := rawRecord.(*dns.A)
			if !ok {
				continue
			}
			urlStruct := *d.URL
			var host string
			if port := d.URL.Port(); port != "" {
				host = net.JoinHostPort(record.A.String(), port)
			} else {
				host = record.A.String()
			}
			urlStruct.Host = host
			resolvedURLs = append(resolvedURLs, (&urlStruct).String())
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
					descriptor.DefaultValue{Value: 2 * time.Second},
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
						ObjectPath:     descriptor.Path{"ecsMode"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"EcsClientSubnet"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"ecsClientSubnet"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}
