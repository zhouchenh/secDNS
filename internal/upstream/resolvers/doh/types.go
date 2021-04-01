package doh

import (
	"bytes"
	"crypto/tls"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/pkg/common"
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
	URL           *url.URL
	QueryTimeout  time.Duration
	TlsServerName string
	SendThrough   net.IP
	Resolver      resolver.Resolver
	queryClient   *client
	initializing  bool
}

type client struct {
	httpClient   *http.Client
	serverName   string
	resolvedURLs []string
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
	if d.initializing {
		return nil, ErrResolverNotReady
	}
	if d.queryClient == nil {
		d.initializing = true
		d.initClient()
		d.initializing = false
	}
	wireFormattedQuery, e := query.Pack()
	if e != nil {
		return nil, e
	}
	once := new(sync.Once)
	msg := make(chan *dns.Msg)
	err := make(chan error)
	errCollector := make(chan error, len(d.queryClient.resolvedURLs))
	wg := new(sync.WaitGroup)
	wg.Add(len(d.queryClient.resolvedURLs))
	sendRequest := func(urlString string) {
		request, e := http.NewRequest(http.MethodPost, urlString, bytes.NewReader(wireFormattedQuery))
		if e != nil {
			errCollector <- e
			wg.Done()
			return
		}
		request.Host = d.queryClient.serverName
		request.Header.Set("Accept", "application/dns-message")
		request.Header.Set("Content-Type", "application/dns-message")
		response, e := d.queryClient.httpClient.Do(request)
		if e != nil {
			errCollector <- e
			wg.Done()
			return
		}
		wireFormattedMsg, e := ioutil.ReadAll(response.Body)
		response.Body.Close()
		m := new(dns.Msg)
		e = m.Unpack(wireFormattedMsg)
		if e != nil {
			errCollector <- e
			wg.Done()
			return
		}
		once.Do(func() {
			msg <- m
			err <- nil
		})
		wg.Done()
	}
	for _, urlString := range d.queryClient.resolvedURLs {
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
				d.queryClient.resolvedURLs = resolvedURLs
				if len(errCollector) < 1 {
					m, e := d.Resolve(query, depth-1)
					msg <- m
					err <- e
					return
				}
			}
			msg <- nil
			for len(errCollector) > 1 {
				<-errCollector
			}
			err <- <-errCollector
		})
	}()
	return <-msg, <-err
}

func (d *DoH) NameServerResolver() {}

func (d *DoH) initClient() {
	serverName := d.serverName()
	resolvedURLs := d.resolveURL(64)
	d.queryClient = &client{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					LocalAddr: &net.TCPAddr{IP: d.SendThrough},
				}).DialContext,
				TLSClientConfig: &tls.Config{
					ServerName: serverName,
				},
			},
			Timeout: d.QueryTimeout,
		},
		serverName:   serverName,
		resolvedURLs: resolvedURLs,
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
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Root,
					AssignableKind: descriptor.AssignmentFunction(func(interface{}) (object interface{}, ok bool) {
						object, s, f := resolver.Descriptor().Describe("")
						ok = s > 0 && f < 1
						return
					}),
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}
