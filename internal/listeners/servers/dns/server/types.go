package server

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/upstream/diagnostics"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"net"
	"net/netip"
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
	d.serve(func(_ dns.ResponseWriter, query *dns.Msg) *dns.Msg {
		return safeHandle(handler, query, errorHandler)
	}, errorHandler)
}

// ServePeer is the peer-aware DNS transport seam. It derives the address only
// from miekg/dns's socket-backed ResponseWriter. An unrecognized, nil, or
// zone-qualified address is passed as the zero Addr so policy integration can
// fail closed rather than trust text supplied by a request.
func (d *DNSServer) ServePeer(handler func(query *dns.Msg, peer netip.Addr) (reply *dns.Msg), errorHandler func(err error)) {
	if handler == nil {
		handleIfError(ErrNilHandler, errorHandler)
		return
	}
	d.serve(func(w dns.ResponseWriter, query *dns.Msg) *dns.Msg {
		peer := peerAddress(w.RemoteAddr())
		return safeHandle(func(query *dns.Msg) *dns.Msg {
			return handler(query, peer)
		}, query, errorHandler)
	}, errorHandler)
}

func (d *DNSServer) serve(handler func(w dns.ResponseWriter, query *dns.Msg) *dns.Msg, errorHandler func(err error)) {
	handleIfError(dns.ListenAndServe(net.JoinHostPort(d.Listen.String(), strconv.Itoa(int(d.Port))), d.Protocol, dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		span := diagnostics.Begin(query, "listener.handler")
		reply := handler(w, query)
		span.End("returned")
		if reply == nil {
			reply = new(dns.Msg)
			reply.SetRcode(query, dns.RcodeServerFailure)
		}
		switch d.Protocol {
		case "udp", "udp4", "udp6":
			reply = clampUDPResponse(reply, query)
		}
		writeSpan := diagnostics.Begin(query, "listener.write")
		writeErr := w.WriteMsg(reply)
		outcome := "written"
		if writeErr != nil {
			outcome = "write_error"
		}
		writeSpan.End(outcome)
		handleIfError(writeErr, errorHandler)
	})), errorHandler)
}

func peerAddress(address net.Addr) netip.Addr {
	var ip net.IP
	var zone string
	switch value := address.(type) {
	case *net.UDPAddr:
		if value == nil {
			return netip.Addr{}
		}
		ip, zone = value.IP, value.Zone
	case *net.TCPAddr:
		if value == nil {
			return netip.Addr{}
		}
		ip, zone = value.IP, value.Zone
	default:
		return netip.Addr{}
	}
	if zone != "" {
		return netip.Addr{}
	}
	peer, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return peer.Unmap()
}

// safeHandle runs handler(query), converting a panic in the resolver tree into a nil
// reply so the caller can answer SERVFAIL. miekg's server does not recover handler
// panics, so without this a single defective code path would crash the whole process.
func safeHandle(handler func(query *dns.Msg) (reply *dns.Msg), query *dns.Msg, errorHandler func(err error)) (reply *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			handleIfError(fmt.Errorf("dnsServer: recovered from handler panic: %v", r), errorHandler)
			reply = nil
		}
	}()
	return handler(query)
}

// clampUDPResponse returns reply truncated (TC=1) to the requestor's advertised UDP
// payload size so secDNS never emits an oversized UDP datagram (a reflection /
// amplification vector). It only copies-and-truncates when the reply actually
// exceeds the limit, leaving the common case — and any shared/cached message — alone.
func clampUDPResponse(reply *dns.Msg, query *dns.Msg) *dns.Msg {
	max := udpSize(query)
	if reply.Len() <= max {
		return reply
	}
	out := reply.Copy()
	out.Truncate(max)
	return out
}

// udpSize is the maximum UDP payload the requestor will accept: the EDNS0 advertised
// size (floored at the 512-octet minimum), or 512 when the query carries no OPT.
func udpSize(query *dns.Msg) int {
	if query != nil {
		if opt := query.IsEdns0(); opt != nil {
			if size := int(opt.UDPSize()); size > dns.MinMsgSize {
				return size
			}
		}
	}
	return dns.MinMsgSize
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
