package nameserver

import (
	"common"
	"crypto/tls"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"net"
	"strconv"
	"strings"
	"time"
	"upstream/resolver"
)

type NameServer struct {
	Address       net.IP
	Port          uint16
	Protocol      string
	QueryTimeout  time.Duration
	TlsServerName string
	SendThrough   net.IP
	queryClient   *dns.Client
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
	ns.queryClient = &dns.Client{
		Net: ns.Protocol,
		TLSConfig: &tls.Config{
			ServerName: ns.TlsServerName,
		},
		Dialer: &net.Dialer{
			LocalAddr: addr,
			Timeout:   ns.QueryTimeout,
		},
	}
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
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}
