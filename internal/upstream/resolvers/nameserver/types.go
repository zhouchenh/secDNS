package nameserver

import (
	"crypto/tls"
	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
	"strconv"
	"strings"
	"time"
)

type NameServer struct {
	Address        net.IP
	Port           uint16
	Protocol       string
	QueryTimeout   time.Duration
	TlsServerName  string
	SendThrough    net.IP
	Socks5Proxy    string
	Socks5Username string
	Socks5Password string
	queryClient    *client
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
	if ns.queryClient == nil {
		ns.initClient()
	}
	connection, err := ns.queryClient.Dial(net.JoinHostPort(ns.Address.String(), strconv.Itoa(int(ns.Port))))
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(ns.QueryTimeout))
	if err := connection.WriteMsg(query); err != nil {
		return nil, err
	}
	msg, err := connection.ReadMsg()
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (ns *NameServer) NameServerResolver() {}

func (ns *NameServer) initClient() {
	var addr net.Addr
	switch strings.TrimSuffix(ns.Protocol, "-tls") {
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
			Net: ns.Protocol,
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
	ns.queryClient = c
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
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}
