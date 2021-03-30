package list

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/pkg/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver/nameserver"
	"sync"
)

type ConcurrentNameServerList []resolver.Resolver

var typeOfConcurrentNameServerList = descriptor.TypeOfNew(new(*ConcurrentNameServerList))

func (nsl *ConcurrentNameServerList) Type() descriptor.Type {
	return typeOfConcurrentNameServerList
}

func (nsl *ConcurrentNameServerList) TypeName() string {
	return "concurrentNameServerList"
}

func (nsl *ConcurrentNameServerList) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	if len(*nsl) < 1 {
		return nil, ErrNoAvailableNameServer
	}
	once := new(sync.Once)
	msg := make(chan *dns.Msg)
	err := make(chan error)
	errCollector := make(chan error, len(*nsl))
	wg := new(sync.WaitGroup)
	wg.Add(len(*nsl))
	request := func(r resolver.Resolver) {
		ok := r != nil
		if ok {
			resolverType := r.Type()
			ok = resolverType != nil && resolverType.Implements(nameserver.Type())
		}
		if ok {
			m, e := r.Resolve(query, depth-1)
			if e != nil {
				errCollector <- e
			} else {
				once.Do(func() {
					msg <- m
					err <- nil
				})
			}
		} else {
			errCollector <- ErrNilNameServer
		}
		wg.Done()
	}
	for _, nameServerResolver := range *nsl {
		go request(nameServerResolver)
	}
	go func() {
		wg.Wait()
		once.Do(func() {
			msg <- nil
			for len(errCollector) > 1 {
				<-errCollector
			}
			err <- <-errCollector
		})
	}()
	return <-msg, <-err
}

func (nsl *ConcurrentNameServerList) NameServerResolver() {}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfConcurrentNameServerList,
		Filler: descriptor.ObjectFiller{
			ValueSource: descriptor.ObjectAtPath{
				ObjectPath: descriptor.Root,
				AssignableKind: descriptor.ConvertibleKind{
					Kind: descriptor.KindSlice,
					ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
						interfaces, ok := original.([]interface{})
						if !ok {
							return
						}
						var resolvers []resolver.Resolver
						for _, i := range interfaces {
							rawResolver, s, f := resolver.Descriptor().Describe(i)
							ok := s > 0 && f < 1
							if !ok {
								continue
							}
							r, ok := rawResolver.(resolver.Resolver)
							if !ok {
								continue
							}
							resolvers = append(resolvers, r)
						}
						return descriptor.PointerOf(ConcurrentNameServerList(resolvers)), true
					},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}
