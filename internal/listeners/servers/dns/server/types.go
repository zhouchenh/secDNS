package server

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"net"
	"strconv"
)

type DNSServer struct {
	Listen   net.IP
	Port     uint16
	Protocol string
}

var typeOfDNSServer = descriptor.TypeOfNew(new(*DNSServer))

func (d *DNSServer) Type() descriptor.Type {
	return typeOfDNSServer
}

func (d *DNSServer) TypeName() string {
	return "dnsServer"
}

func (d *DNSServer) Serve(handler func(query *dns.Msg) (reply *dns.Msg), errorHandler func(err error)) {
	if handler == nil {
		handleIfError(ErrNilHandler, errorHandler)
		return
	}
	handleIfError(dns.ListenAndServe(net.JoinHostPort(d.Listen.String(), strconv.Itoa(int(d.Port))), d.Protocol, dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		handleIfError(w.WriteMsg(handler(query)), errorHandler)
	})), errorHandler)
}

func handleIfError(err error, errorHandler func(err error)) {
	if err != nil && errorHandler != nil {
		errorHandler(err)
	}
}

func init() {
	if err := server.RegisterServer(&descriptor.Descriptor{
		Type: typeOfDNSServer,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Listen"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"listen"},
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
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}
