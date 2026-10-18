package server

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"net/netip"
)

type Server interface {
	Type() descriptor.Type
	TypeName() string
	Serve(handler func(query *dns.Msg) (reply *dns.Msg), errorHandler func(err error))
}

// PeerServer is implemented by transports that can bind each query to the
// address of the directly connected client. The address must come from the
// transport socket, not from DNS payload metadata or forwarded headers.
type PeerServer interface {
	Server
	ServePeer(handler func(query *dns.Msg, peer netip.Addr) (reply *dns.Msg), errorHandler func(err error))
}

var typeOfServer = descriptor.TypeOfNew(new(Server))

func Type() descriptor.Type {
	return typeOfServer
}

var registeredAssignmentFunctionByType = make(map[descriptor.Type]descriptor.AssignmentFunction)
var registeredAssignmentFunctionByKind = make(map[descriptor.Kind]descriptor.AssignmentFunction)

var privateDescriptor = descriptor.Descriptor{
	Type: typeOfServer,
	Filler: descriptor.ObjectFiller{
		ValueSource: descriptor.ObjectAtPath{
			ObjectPath: descriptor.Root,
			AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
				t := descriptor.TypeOf(i)
				f, ok := registeredAssignmentFunctionByType[t]
				if !ok {
					k := descriptor.KindOf(i)
					f, ok = registeredAssignmentFunctionByKind[k]
					if !ok {
						return
					}
				}
				return f(i)
			}),
		},
	},
}

func Descriptor() descriptor.Describable {
	return &privateDescriptor
}

func RegisterAssignmentFunctionByType(t descriptor.Type, f descriptor.AssignmentFunction) {
	if t == nil || f == nil {
		return
	}
	registeredAssignmentFunctionByType[t] = f
}

func RegisterAssignmentFunctionByKind(k descriptor.Kind, f descriptor.AssignmentFunction) {
	if f == nil {
		return
	}
	registeredAssignmentFunctionByKind[k] = f
}
