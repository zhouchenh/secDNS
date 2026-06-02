package nameserver

import (
	"crypto/tls"
	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NameServer struct {
	Address           net.IP
	Port              uint16
	Protocol          string
	QueryTimeout      time.Duration
	TlsServerName     string
	SendThrough       net.IP
	Socks5Proxy       string
	Socks5Username    string
	Socks5Password    string
	EcsMode           string
	EcsClientSubnet   string
	ecsConfig         *ecs.Config
	queryClient       *client
	tcpFallbackClient *client // Cached TCP client for UDP→TCP fallback
	initOnce          sync.Once
	tcpFallbackOnce   sync.Once // Thread-safe TCP fallback client initialization
}

type client struct {
	dialFunc     func(network, address string) (conn net.Conn, err error)
	dialTLSFunc  func(network, address string) (conn net.Conn, err error)
	socks5Client *socks5.Client
	*dns.Client
}

var typeOfNameServer = descriptor.TypeOfNew(new(*NameServer))

func (ns *NameServer) Type() descriptor.Type {
	return typeOfNameServer
}

func (ns *NameServer) TypeName() string {
	return "nameServer"
}

func (ns *NameServer) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	ns.initOnce.Do(func() {
		ns.initClient()
	})

	// Work on a copy so the caller's message is never mutated, and randomize the
	// transaction ID for the upstream query to raise the bar for off-path spoofing.
	// The caller's original ID is restored on the reply before returning.
	originalID := query.Id
	outbound := query.Copy()
	outbound.Id = dns.Id()

	// Apply ECS configuration to the outbound query if configured.
	if ns.ecsConfig != nil {
		if err := ns.ecsConfig.ApplyToQuery(outbound); err != nil {
			return nil, err
		}
	}

	address := net.JoinHostPort(ns.Address.String(), strconv.Itoa(int(ns.Port)))

	// Try with the configured protocol.
	msg, err := ns.queryWithProtocol(outbound, address, ns.Protocol)
	if err != nil {
		return nil, err
	}

	// If the UDP response is truncated, retry over TCP; keep the truncated UDP
	// response if the TCP attempt fails.
	if msg.Truncated && ns.Protocol == "udp" {
		if tcpMsg, tcpErr := ns.queryWithProtocol(outbound, address, "tcp"); tcpErr == nil {
			msg = tcpMsg
		}
	}

	msg.Id = originalID
	return msg, nil
}

func (ns *NameServer) queryWithProtocol(query *dns.Msg, address string, protocol string) (*dns.Msg, error) {
	var clientToUse *client

	// Select appropriate client based on protocol
	if protocol == ns.Protocol {
		// Use the primary client for the configured protocol
		clientToUse = ns.queryClient
	} else if protocol == "tcp" && ns.Protocol == "udp" {
		// Use cached TCP fallback client (initialized once, reused for all truncated responses)
		ns.tcpFallbackOnce.Do(func() {
			ns.tcpFallbackClient = ns.createClientForProtocol("tcp")
		})
		clientToUse = ns.tcpFallbackClient
	} else {
		// Edge case: other protocol combinations (rare, create temporary client)
		clientToUse = ns.createClientForProtocol(protocol)
	}

	connection, err := clientToUse.Dial(address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(ns.QueryTimeout))
	if err := connection.WriteMsg(query); err != nil {
		return nil, err
	}
	// Read until a response that matches the query (transaction ID + question)
	// arrives or the deadline fires, discarding unsolicited or mismatched datagrams
	// so a forged or stray packet cannot be accepted as the answer.
	for {
		msg, err := connection.ReadMsg()
		if err != nil {
			return nil, err
		}
		if responseMatchesQuery(msg, query) {
			return msg, nil
		}
	}
}

// responseMatchesQuery reports whether resp is a plausible answer to query: the
// transaction ID and the question section (name/type/class) must match. Name
// comparison is case-insensitive per RFC 4343.
func responseMatchesQuery(resp, query *dns.Msg) bool {
	if resp == nil || resp.Id != query.Id {
		return false
	}
	if len(resp.Question) != len(query.Question) {
		return false
	}
	for i := range query.Question {
		q := query.Question[i]
		r := resp.Question[i]
		if r.Qtype != q.Qtype || r.Qclass != q.Qclass || !strings.EqualFold(r.Name, q.Name) {
			return false
		}
	}
	return true
}

func (ns *NameServer) NameServerResolver() {}

func (ns *NameServer) createClientForProtocol(protocol string) *client {
	var addr net.Addr
	switch strings.TrimSuffix(protocol, "-tls") {
	case "tcp":
		addr = &net.TCPAddr{IP: ns.SendThrough}
	case "udp":
		addr = &net.UDPAddr{IP: ns.SendThrough}
	default:
		addr = nil
	}
	c := &client{
		dialFunc:     nil,
		socks5Client: nil,
		Client: &dns.Client{
			Net:     protocol,
			UDPSize: 4096, // Enable EDNS0 for larger UDP responses
			TLSConfig: &tls.Config{
				ServerName: ns.TlsServerName,
			},
			Dialer: &net.Dialer{
				LocalAddr: addr,
				Timeout:   ns.QueryTimeout,
			},
		},
	}
	if ns.Socks5Proxy != "" {
		c.socks5Client = &socks5.Client{
			Server:     ns.Socks5Proxy,
			UserName:   ns.Socks5Username,
			Password:   ns.Socks5Password,
			TCPTimeout: ns.socks5Timeout(ns.QueryTimeout),
			UDPTimeout: ns.socks5Timeout(ns.QueryTimeout),
		}
		c.dialFunc = func(network, address string) (conn net.Conn, err error) {
			return c.socks5Client.DialWithLocalAddr(network, c.Dialer.LocalAddr.String(), address, nil)
		}
		c.dialTLSFunc = func(network, address string) (conn net.Conn, err error) {
			conn, err = c.dialFunc(network, address)
			if err != nil {
				return
			}
			conn = tls.Client(conn, c.TLSConfig)
			return
		}
	} else {
		c.dialFunc = c.Dialer.Dial
		c.dialTLSFunc = func(network, address string) (conn net.Conn, err error) {
			return tls.DialWithDialer(c.Dialer, network, address, c.TLSConfig)
		}
	}
	return c
}

func (ns *NameServer) initClient() {
	ns.queryClient = ns.createClientForProtocol(ns.Protocol)

	// Initialize ECS configuration if specified
	if ns.EcsMode != "" || ns.EcsClientSubnet != "" {
		cfg, err := ecs.ParseConfig(ns.EcsMode, ns.EcsClientSubnet)
		if err != nil {
			common.ErrOutput(err)
		} else {
			ns.ecsConfig = cfg
		}
	}
}

func (ns *NameServer) socks5Timeout(timeout time.Duration) int {
	d := timeout / time.Second
	if d*time.Second < timeout {
		return int(d) + 1
	}
	return int(d)
}

func (c *client) Dial(address string) (conn *dns.Conn, err error) {
	network := c.Net
	if network == "" {
		network = "udp"
	}
	useTLS := strings.HasPrefix(network, "tcp") && strings.HasSuffix(network, "-tls")
	conn = new(dns.Conn)
	if useTLS {
		network = strings.TrimSuffix(network, "-tls")
		conn.Conn, err = c.dialTLSFunc(network, address)
	} else {
		conn.Conn, err = c.dialFunc(network, address)
	}
	if err != nil {
		return nil, err
	}
	conn.UDPSize = c.UDPSize
	return conn, nil
}

func init() {
	convertibleKindIP := descriptor.ConvertibleKind{
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
	}
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfNameServer,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Address"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath:     descriptor.Path{"address"},
					AssignableKind: convertibleKindIP,
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Port"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"port"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.ConvertibleKind{
								Kind: descriptor.KindFloat64,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									num, ok := original.(float64)
									if !ok {
										return
									}
									i := int(num)
									if i >= 0 && i <= 65535 {
										return uint16(i), true
									}
									return nil, false
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									str, ok := original.(string)
									if !ok {
										return
									}
									i, err := strconv.Atoi(str)
									if err != nil {
										return nil, false
									}
									if i >= 0 && i <= 65535 {
										return uint16(i), true
									}
									return nil, false
								},
							},
						},
					},
					descriptor.DefaultValue{Value: uint16(53)},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Protocol"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"protocol"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: "udp"},
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
						ObjectPath:     descriptor.Path{"sendThrough"},
						AssignableKind: convertibleKindIP,
					},
					descriptor.DefaultValue{Value: nil},
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
