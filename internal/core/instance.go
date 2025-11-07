package core

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"github.com/zhouchenh/secDNS/pkg/rules/provider"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"strings"
	"sync"
)

type Instance interface {
	initInstance()
	AddListener(listeners ...server.Server)
	AcceptProvider(rulesProvider provider.Provider, errorHandler func(err error))
	SetDefaultResolver(upstreamResolver resolver.Resolver)
	SetResolutionDepth(depth int)
	GetResolver() (upstreamResolver resolver.Resolver, ok bool)
	Listen(clientErrorMsgHandler func(query *dns.Msg) *dns.Msg, serverErrorMsgHandler func(query *dns.Msg) *dns.Msg, errorHandler func(err error))
}

type instance struct {
	listeners       []server.Server
	nameResolverMap map[string]resolver.Resolver // fully qualified names are required
	mapMutex        sync.RWMutex
	defaultResolver resolver.Resolver
	resolutionDepth int
}

func NewInstance() Instance {
	i := new(instance)
	i.initInstance()
	return i
}

func (i *instance) initInstance() {
	i.nameResolverMap = make(map[string]resolver.Resolver)
}

func (i *instance) AddListener(listeners ...server.Server) {
	i.listeners = append(i.listeners, listeners...)
}

func (i *instance) AcceptProvider(rulesProvider provider.Provider, errorHandler func(err error)) {
	if rulesProvider == nil {
		return
	}
	for rulesProvider.Provide(func(name string, r resolver.Resolver) {
		if r == nil {
			return
		}
		i.mapMutex.Lock()
		if _, hasKey := i.nameResolverMap[name]; !hasKey {
			i.nameResolverMap[name] = r
		}
		i.mapMutex.Unlock()
	}, func(err error) {
		handleIfError(err, errorHandler)
	}) {
	}
}

func (i *instance) SetDefaultResolver(upstreamResolver resolver.Resolver) {
	if upstreamResolver == nil {
		return
	}
	i.defaultResolver = upstreamResolver
}

func (i *instance) SetResolutionDepth(depth int) {
	i.resolutionDepth = depth
}

func (i *instance) GetResolver() (upstreamResolver resolver.Resolver, ok bool) {
	if i.defaultResolver == nil {
		return nil, false
	}
	return i, true
}

func (i *instance) Listen(clientErrorMsgHandler func(query *dns.Msg) *dns.Msg, serverErrorMsgHandler func(query *dns.Msg) *dns.Msg, errorHandler func(err error)) {
	if clientErrorMsgHandler == nil || serverErrorMsgHandler == nil {
		handleIfError(ErrNilErrorMsgHandler, errorHandler)
		return
	}
	instanceResolver, ok := i.GetResolver()
	if !ok {
		handleIfError(ErrNilDefaultResolver, errorHandler)
		return
	}
	wait := new(sync.WaitGroup)
	for _, listener := range i.listeners {
		if listener == nil {
			continue
		}
		wait.Add(1)
		go listen(listener, instanceResolver, i.resolutionDepth, clientErrorMsgHandler, serverErrorMsgHandler, errorHandler, wait)
	}
	wait.Wait()
}

func listen(s server.Server, r resolver.Resolver, resolutionDepth int, clientErrorMsgHandler func(query *dns.Msg) *dns.Msg, serverErrorMsgHandler func(query *dns.Msg) *dns.Msg, errorHandler func(err error), wait *sync.WaitGroup) {
	s.Serve(func(query *dns.Msg) (reply *dns.Msg) {
		if err := resolver.QueryCheck(query); err != nil {
			handleIfError(err, errorHandler)
			return clientErrorMsgHandler(query)
		}
		reply, err := r.Resolve(query, resolutionDepth)
		if err != nil {
			handleIfError(err, errorHandler)
			return serverErrorMsgHandler(query)
		}
		return
	}, errorHandler)
	wait.Done()
}

func (i *instance) Type() descriptor.Type {
	return nil
}

func (i *instance) TypeName() string {
	return ""
}

func (i *instance) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	name := query.Question[0].Name
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return nil, ErrInvalidDomainName
	}

	// Check exact match with quotes
	i.mapMutex.RLock()
	r, ok := i.nameResolverMap["\""+name+"\""]
	i.mapMutex.RUnlock()
	if ok {
		msg, err := r.Resolve(query, depth-1)
		if err == nil && msg != nil {
			return msg, nil
		}
	}

	// Check domain hierarchy
	for level := 0; level < len(labels)-1; level++ {
		domainName := strings.Join(labels[level:], ".")
		i.mapMutex.RLock()
		r, ok := i.nameResolverMap[domainName]
		i.mapMutex.RUnlock()
		if ok {
			msg, err := r.Resolve(query, depth-1)
			if err != nil {
				continue
			}
			return msg, nil
		}
	}

	msg, err := i.defaultResolver.Resolve(query, depth-1)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func handleIfError(err error, errorHandler func(err error)) {
	if err != nil && errorHandler != nil {
		errorHandler(err)
	}
}
