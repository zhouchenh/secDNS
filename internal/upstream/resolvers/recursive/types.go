package recursive

import (
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"golang.org/x/sync/singleflight"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Recursive is a full recursive, DNSSEC-validating resolver. It performs iterative
// resolution from the IANA root hints with qname minimization, UDP-first/TCP-fallback
// exchange, an RTT/health scoreboard for server selection, singleflight deduplication,
// optional SOCKS5/bind connectivity, and tri-state (Secure/Insecure/Bogus) DNSSEC
// validation gated by the configured policy.
type Recursive struct {
	RootServers        []RootServer
	ValidateDNSSEC     string
	QNameMinimize      bool
	EDNSSize           uint16
	Timeout            time.Duration
	Retries            int
	ProbeTopN          int
	ProbeInterval      time.Duration
	PreferIPv6         bool
	MaxDepth           int
	MaxCNAME           int
	MaxReferrals       int
	MaxQueries         int
	MaxResolutionTime  time.Duration
	Socks5Proxy        string
	Socks5Username     string
	Socks5Password     string
	SendThrough        net.IP
	EcsMode            string
	EcsClientSubnet    string
	HonorClientCD      bool
	Nsec3MaxIterations int

	initOnce       sync.Once
	clients        map[string]*dns.Client
	socksClient    *socks5.Client
	dialFunc       func(network, address string) (net.Conn, error)
	scoreboard     *nsScoreboard
	reqGroup       singleflight.Group
	glueCache      map[string]glueCacheEntry
	glueCacheMutex sync.Mutex
	validator      *dnssecValidator
	log            func(msg string)
	ecsConfig      *ecs.Config
	// exchangeFn, when set, replaces the real network exchange (tests inject it to
	// drive resolveWithServers deterministically); nil uses r.exchange.
	exchangeFn func(query *dns.Msg, ip net.IP) (*dns.Msg, time.Duration, error)
}

var (
	typeOfRecursive            = descriptor.TypeOfNew(new(*Recursive))
	ErrRecursiveNotImplemented = errors.New("recursive resolver: not implemented yet")
	defaultRecursiveConfig     = &Recursive{
		RootServers:       defaultRootHints(),
		ValidateDNSSEC:    "permissive",
		QNameMinimize:     true,
		EDNSSize:          1232,
		Timeout:           1500 * time.Millisecond,
		Retries:           2,
		ProbeTopN:         5,
		ProbeInterval:     time.Hour,
		PreferIPv6:        false,
		MaxDepth:          32,
		MaxCNAME:          8,
		MaxReferrals:      16,
		MaxQueries:        defaultMaxQueries,
		MaxResolutionTime: defaultMaxResolutionTime,
		Socks5Proxy:       "",
		Socks5Username:    "",
		Socks5Password:    "",
		SendThrough:       nil,
		EcsMode:           string(ecs.ModePassthrough),
		EcsClientSubnet:   "",
	}
)

func (r *Recursive) Type() descriptor.Type {
	return typeOfRecursive
}

func (r *Recursive) TypeName() string {
	return "recursive"
}

func (r *Recursive) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if query == nil {
		return nil, resolver.ErrNilQuery
	}
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	r.initOnce.Do(r.initialize)
	if r.scoreboard == nil {
		return nil, ErrRecursiveNotImplemented
	}
	if len(query.Question) == 0 {
		return nil, resolver.ErrNotSupportedQuestion
	}
	// Client DNSSEC signalling bits, read from the original query. They are NOT part
	// of the shared resolution; they select the per-waiter AD/SERVFAIL decision below.
	clientCD := query.CheckingDisabled
	clientAD := query.AuthenticatedData
	clientDO := dnssecOK(query)
	question := query.Question[0]

	baseECS := cloneECSOption(extractECSOption(query))
	queryCopy := query.Copy()
	if err := r.applyECS(queryCopy, baseECS); err != nil {
		return nil, err
	}
	// CD and DO are keyed into singleflight so CD/DO-distinct queries never share an
	// in-flight result; the AD/SERVFAIL stamp below is per-waiter regardless.
	key := singleflightKey(queryCopy, clientCD, clientDO)
	result, err, _ := r.reqGroup.Do(key, func() (interface{}, error) {
		resp, e := r.resolveIterative(queryCopy, depth, baseECS, r.newBudget())
		if e != nil {
			return nil, e
		}
		// Classify the security status once on the shared answer with AD cleared;
		// only the per-waiter applyPolicy stamp may set AD.
		resp.AuthenticatedData = false
		status, authentic := r.classifyTerminal(resp, question)
		return &validatedMsg{msg: resp, status: status, authentic: authentic}, nil
	})
	if err != nil {
		return nil, err
	}
	vm := result.(*validatedMsg)
	res := applyPolicy(vm.status, r.ValidateDNSSEC, clientCD, clientDO, clientAD, r.HonorClientCD, vm.authentic)
	if res.servfail {
		sf := new(dns.Msg)
		sf.SetRcode(query, dns.RcodeServerFailure)
		return sf, nil
	}
	// Per-waiter copy so no waiter mutates the shared, AD-cleared message.
	out := vm.msg.Copy()
	out.AuthenticatedData = res.setAD
	return out, nil
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfRecursive,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"RootServers"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"rootServers"},
						AssignableKind: descriptor.AssignmentFunction(func(original interface{}) (object interface{}, ok bool) {
							rawList, ok := original.([]interface{})
							if !ok {
								return nil, false
							}
							var servers []RootServer
							for _, item := range rawList {
								m, ok := item.(map[string]interface{})
								if !ok {
									continue
								}
								host, _ := m["host"].(string)
								addrsRaw, _ := m["addresses"].([]interface{})
								var addrs []net.IP
								for _, a := range addrsRaw {
									if s, ok := a.(string); ok {
										ip := net.ParseIP(strings.TrimSpace(s))
										if ip != nil {
											addrs = append(addrs, ip)
										}
									}
								}
								if len(addrs) > 0 || host != "" {
									servers = append(servers, RootServer{Host: host, Addresses: addrs})
								}
							}
							if len(servers) == 0 {
								return nil, false
							}
							return servers, true
						}),
					},
					descriptor.DefaultValue{Value: defaultRootHints()},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"ValidateDNSSEC"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"validateDNSSEC"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return nil, false
								}
								str = strings.ToLower(strings.TrimSpace(str))
								switch str {
								case "strict", "permissive", "off":
									return str, true
								default:
									return nil, false
								}
							},
						},
					},
					descriptor.DefaultValue{Value: "permissive"},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"QNameMinimize"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"qnameMinimize"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.KindBool,
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									switch strings.ToLower(strings.TrimSpace(original.(string))) {
									case "true":
										return true, true
									case "false":
										return false, true
									default:
										return nil, false
									}
								},
							},
						},
					},
					descriptor.DefaultValue{Value: true},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"EDNSSize"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"ednsSize"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.ConvertibleKind{
								Kind: descriptor.KindFloat64,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									val := int(original.(float64))
									if val <= 0 || val > 4096 {
										return nil, false
									}
									return uint16(val), true
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									i, err := strconv.Atoi(strings.TrimSpace(original.(string)))
									if err != nil || i <= 0 || i > 4096 {
										return nil, false
									}
									return uint16(i), true
								},
							},
						},
					},
					descriptor.DefaultValue{Value: uint16(1232)},
				},
			},
			durationFiller("Timeout", "timeout", defaultRecursiveConfig.Timeout),
			durationFiller("ProbeInterval", "probeInterval", defaultRecursiveConfig.ProbeInterval),
			intFiller("Retries", "retries", 0, 5, defaultRecursiveConfig.Retries),
			intFiller("ProbeTopN", "probeTopN", 1, 13, defaultRecursiveConfig.ProbeTopN),
			intFiller("MaxDepth", "maxDepth", 1, 128, defaultRecursiveConfig.MaxDepth),
			intFiller("MaxCNAME", "maxCNAME", 1, 32, defaultRecursiveConfig.MaxCNAME),
			intFiller("MaxReferrals", "maxReferrals", 1, 64, defaultRecursiveConfig.MaxReferrals),
			intFiller("MaxQueries", "maxQueries", 16, 1000000, defaultRecursiveConfig.MaxQueries),
			durationFillerAllowZero("MaxResolutionTime", "maxResolutionTime", defaultRecursiveConfig.MaxResolutionTime),
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
								if str == "" {
									return str, true
								}
								if _, _, err := ecs.ParseClientSubnet(str); err != nil {
									return nil, false
								}
								return str, true
							},
						},
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
			boolFiller("HonorClientCD", "honorClientCD", true),
			intFiller("Nsec3MaxIterations", "nsec3MaxIterations", 0, 2500, 100),
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

func (r *Recursive) initialize() {
	if len(r.RootServers) == 0 {
		r.RootServers = defaultRootHints()
	}
	if r.MaxQueries <= 0 {
		// A directly-constructed resolver (not built through the descriptor, e.g. in
		// tests) gets the same per-query work cap as a configured one.
		r.MaxQueries = defaultMaxQueries
	}
	if r.log == nil {
		r.log = func(msg string) { common.ErrOutput(msg) }
	}
	if len(r.RootServers) == 0 {
		return
	}
	r.scoreboard = newScoreboard(r.RootServers, r.ProbeTopN)
	r.prepareDialers()
	r.glueCache = make(map[string]glueCacheEntry)
	if r.EcsMode != "" || r.EcsClientSubnet != "" {
		cfg, err := ecs.ParseConfig(r.EcsMode, r.EcsClientSubnet)
		if err != nil {
			common.ErrOutput(err)
		} else {
			r.ecsConfig = cfg
		}
	}
	validator := newValidator()
	validator.resolveDNSKEY = r.fetchDNSKEY
	validator.resolveDS = r.fetchDS
	validator.logger = func(msg string) {
		common.ErrOutput(errors.New(msg))
	}
	if r.Nsec3MaxIterations > 0 {
		validator.nsec3MaxIter = uint16(r.Nsec3MaxIterations)
	}
	r.validator = validator
	// Initial probes are best-effort and only refine root ordering; they MUST NOT block
	// the first query. Running them on the request path would stall startup on a host
	// with a broken address family (e.g. dead IPv6 egress) for the sum of every dead
	// root's timeout. Run them in the background — queries use the optimistic default
	// ordering (IPv4-first) until the scoreboard is refined.
	go r.scoreboard.probe(func(ip net.IP) (time.Duration, error) {
		msg := new(dns.Msg)
		msg.SetQuestion(".", dns.TypeNS)
		var best time.Duration
		var lastErr error
		for i := 0; i <= r.Retries; i++ {
			rtt, err := r.probeExchange(msg, ip)
			if err == nil {
				if best == 0 || rtt < best {
					best = rtt
				}
				break
			}
			lastErr = err
		}
		if best == 0 && lastErr != nil {
			return 0, lastErr
		}
		return best, nil
	})
}

func (r *Recursive) prepareDialers() {
	var udpLocal, tcpLocal net.Addr
	if r.SendThrough != nil {
		udpLocal = &net.UDPAddr{IP: r.SendThrough}
		tcpLocal = &net.TCPAddr{IP: r.SendThrough}
	}
	if r.Socks5Proxy != "" {
		timeout := r.socks5Timeout(r.Timeout)
		r.socksClient = &socks5.Client{
			Server:     r.Socks5Proxy,
			UserName:   r.Socks5Username,
			Password:   r.Socks5Password,
			TCPTimeout: timeout,
			UDPTimeout: timeout,
		}
		r.dialFunc = func(network, address string) (net.Conn, error) {
			local := ""
			switch network {
			case "tcp", "tcp4", "tcp6":
				if tcpLocal != nil {
					local = tcpLocal.String()
				}
			case "udp", "udp4", "udp6":
				if udpLocal != nil {
					local = udpLocal.String()
				}
			}
			return r.socksClient.DialWithLocalAddr(network, local, address, nil)
		}
	} else {
		r.clients = map[string]*dns.Client{
			"udp": {
				Net:     "udp",
				UDPSize: r.EDNSSize,
				Timeout: r.Timeout,
				Dialer: &net.Dialer{
					Timeout:   r.Timeout,
					LocalAddr: udpLocal,
				},
			},
			"tcp": {
				Net:     "tcp",
				Timeout: r.Timeout,
				Dialer: &net.Dialer{
					Timeout:   r.Timeout,
					LocalAddr: tcpLocal,
				},
			},
		}
		r.dialFunc = func(network, address string) (net.Conn, error) {
			var local net.Addr
			switch strings.ToLower(network) {
			case "udp", "udp4", "udp6":
				local = udpLocal
			default:
				local = tcpLocal
			}
			return (&net.Dialer{
				Timeout:   r.Timeout,
				LocalAddr: local,
			}).Dial(network, address)
		}
	}
}

func (r *Recursive) resolveIterative(query *dns.Msg, depth int, ecsOpt *dns.EDNS0_SUBNET, b *queryBudget) (*dns.Msg, error) {
	return r.resolveIterativeValidated(query, depth, true, ecsOpt, b)
}

func (r *Recursive) resolveIterativeNoValidate(query *dns.Msg, depth int, ecsOpt *dns.EDNS0_SUBNET, b *queryBudget) (*dns.Msg, error) {
	return r.resolveIterativeValidated(query, depth, false, ecsOpt, b)
}

func (r *Recursive) resolveIterativeValidated(query *dns.Msg, depth int, validate bool, ecsOpt *dns.EDNS0_SUBNET, b *queryBudget) (*dns.Msg, error) {
	if depth <= 0 {
		return nil, resolver.ErrLoopDetected
	}
	if err := r.applyECS(query, ecsOpt); err != nil {
		return nil, err
	}
	servers := r.scoreboard.pickRoots(r.PreferIPv6)
	return r.resolveWithServers(query, servers, depth, 0, validate, ecsOpt, b)
}

func (r *Recursive) resolveWithServers(query *dns.Msg, servers []net.IP, depth int, referrals int, validate bool, ecsOpt *dns.EDNS0_SUBNET, b *queryBudget) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("recursive resolver: no servers available")
	}
	if err := r.applyECS(query, ecsOpt); err != nil {
		return nil, err
	}
	question := query.Question[0]
	exchange := r.exchange
	if r.exchangeFn != nil {
		exchange = r.exchangeFn
	}
	// A SERVFAIL/FORMERR from one server is not authoritative; remember it but keep
	// trying the remaining servers, and only surface it if every server fails.
	var lastFailure *dns.Msg
	for _, ip := range servers {
		// Every upstream exchange across this query's whole tree — including the glue
		// chases and CNAME restarts reached below — draws from one shared budget; when
		// it is spent the resolution stops instead of fanning out further.
		if err := b.charge(); err != nil {
			return nil, err
		}
		resp, rtt, err := exchange(query, ip)
		if err != nil {
			if r.log != nil {
				r.log(fmt.Sprintf("exchange to %s failed: %v", ip, err))
			}
			r.scoreboard.markFailure(ip)
			continue
		}
		resp = r.finalizeResponse(resp)
		r.scoreboard.markSuccess(ip, rtt)

		nsNames := extractNS(resp)

		switch resp.Rcode {
		case dns.RcodeSuccess:
			// If answer contains the qtype or CNAME leading to it, return.
			if len(resp.Answer) > 0 {
				if final, follow := r.followCNAME(resp, question, depth); final != nil || follow == nil {
					if final != nil {
						return final, nil
					}
				} else if follow != nil && depth > 0 {
					next, err := r.resolveIterativeValidated(follow, depth-1, validate, ecsOpt, b)
					if err != nil {
						return nil, err
					}
					merged := mergeWithCNAME(resp, next)
					return merged, nil
				}
				return resp, nil
			}
			// No answer: treat like referral handling below.
		case dns.RcodeNameError:
			// Definitive authenticated/authoritative non-existence; return it.
			return resp, nil
		case dns.RcodeServerFailure, dns.RcodeFormatError:
			// One server could not answer; try the next, keeping this as a fallback.
			lastFailure = resp
			continue
		}

		if isTerminalNoData(resp, nsNames) {
			return resp, nil
		}

		// Referral path
		if referrals >= r.MaxReferrals {
			return nil, resolver.ErrLoopDetected
		}
		if len(nsNames) == 0 {
			continue
		}
		glueIPs := r.resolveGlue(nsNames, resp, depth-1, ecsOpt, b)
		if len(glueIPs) == 0 {
			continue
		}
		ordered := r.scoreboard.pickFrom(glueIPs, r.PreferIPv6, r.ProbeTopN)
		next, err := r.resolveWithServers(query, ordered, depth-1, referrals+1, validate, ecsOpt, b)
		if err == nil {
			return next, nil
		}
		// The budget is global to this query; once it is spent, stop descending into
		// sibling servers rather than re-failing on each.
		if errors.Is(err, ErrResolutionBudgetExceeded) {
			return nil, err
		}
	}
	// Every server either errored or returned SERVFAIL/FORMERR. Prefer surfacing a real
	// upstream failure response over a synthetic error when one is available.
	if lastFailure != nil {
		return lastFailure, nil
	}
	return nil, errors.New("recursive resolver: all servers failed")
}

func (r *Recursive) exchange(query *dns.Msg, ip net.IP) (*dns.Msg, time.Duration, error) {
	msg := query.Copy()
	// Ensure EDNS0 with DO bit
	o := msg.IsEdns0()
	if o == nil {
		o = &dns.OPT{}
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		msg.Extra = append(msg.Extra, o)
	}
	o.SetDo(true)
	o.SetUDPSize(r.EDNSSize)

	addr := net.JoinHostPort(ip.String(), "53")
	if r.socksClient != nil {
		return r.exchangeViaCustomDial(msg, addr, ip)
	}
	resp, rtt, err := r.clients["udp"].Exchange(msg, addr)
	if err == nil && resp != nil {
		if resp.Truncated {
			resp, rtt, err = r.clients["tcp"].Exchange(msg, addr)
		}
	}
	if err != nil {
		// UDP failed: try TCP once before giving up
		if alt, rtt2, err2 := r.clients["tcp"].Exchange(msg, addr); err2 == nil && alt != nil {
			return alt, rtt2, nil
		}
		return nil, 0, err
	}
	return resp, rtt, nil
}

func (r *Recursive) exchangeViaCustomDial(msg *dns.Msg, addr string, ip net.IP) (*dns.Msg, time.Duration, error) {
	start := time.Now()
	resp, err := r.exchangeOnce(msg, addr, "udp")
	if err == nil && resp != nil && resp.Truncated {
		resp, err = r.exchangeOnce(msg, addr, "tcp")
	}
	if err != nil {
		return nil, 0, err
	}
	return resp, time.Since(start), nil
}

func (r *Recursive) exchangeOnce(msg *dns.Msg, addr, network string) (*dns.Msg, error) {
	conn, err := r.dialFunc(network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(r.Timeout))
	c := &dns.Conn{Conn: conn, UDPSize: r.EDNSSize}
	if err := c.WriteMsg(msg); err != nil {
		return nil, err
	}
	resp, err := c.ReadMsg()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (r *Recursive) probeExchange(msg *dns.Msg, ip net.IP) (time.Duration, error) {
	_, rtt, err := r.exchange(msg, ip)
	return rtt, err
}

func (r *Recursive) applyECS(msg *dns.Msg, base *dns.EDNS0_SUBNET) error {
	if msg == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if base != nil {
		if opt == nil {
			opt = &dns.OPT{}
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			msg.Extra = append(msg.Extra, opt)
		}
		if !optHasECS(opt) {
			opt.Option = append(opt.Option, cloneECSOption(base))
		}
	}
	if r.ecsConfig != nil {
		return r.ecsConfig.ApplyToQuery(msg)
	}
	return nil
}

func (r *Recursive) followCNAME(resp *dns.Msg, q dns.Question, depth int) (*dns.Msg, *dns.Msg) {
	for _, ans := range resp.Answer {
		if c, ok := ans.(*dns.CNAME); ok {
			if depth <= 0 {
				return resp, nil
			}
			next := new(dns.Msg)
			next.SetQuestion(c.Target, q.Qtype)
			return nil, next
		}
	}
	return resp, nil
}

func mergeWithCNAME(referral *dns.Msg, target *dns.Msg) *dns.Msg {
	out := referral.Copy()
	out.Answer = append([]dns.RR{}, referral.Answer...)
	out.Answer = append(out.Answer, target.Answer...)
	out.Extra = append(out.Extra, target.Extra...)
	out.Authoritative = target.Authoritative
	out.Rcode = target.Rcode
	return out
}

func extractNS(resp *dns.Msg) []string {
	var ns []string
	for _, rr := range resp.Ns {
		if n, ok := rr.(*dns.NS); ok {
			ns = append(ns, n.Ns)
		}
	}
	return ns
}

func extractECSOption(msg *dns.Msg) *dns.EDNS0_SUBNET {
	if msg == nil {
		return nil
	}
	if opt := msg.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ecsOpt, ok := o.(*dns.EDNS0_SUBNET); ok {
				return ecsOpt
			}
		}
	}
	return nil
}

func cloneECSOption(opt *dns.EDNS0_SUBNET) *dns.EDNS0_SUBNET {
	if opt == nil {
		return nil
	}
	clone := *opt
	familyBits := 32
	if opt.Family == 2 {
		familyBits = 128
	}
	clone.Address = normalizeECSAddress(opt.Address, familyBits, int(opt.SourceNetmask))
	clone.SourceScope = 0 // RFC 7871: scope is ignored on requests; set to 0
	return &clone
}

func normalizeECSAddress(addr net.IP, familyBits int, maskBits int) net.IP {
	var ip net.IP
	if familyBits == 32 {
		base := addr.To4()
		if base == nil {
			base = addr
		}
		ip = make(net.IP, net.IPv4len)
		copy(ip, base)
	} else {
		base := addr.To16()
		if base == nil {
			base = addr
		}
		ip = make(net.IP, net.IPv6len)
		copy(ip, base)
	}
	if maskBits > familyBits {
		maskBits = familyBits
	}
	if maskBits > 0 {
		if m := net.CIDRMask(maskBits, familyBits); m != nil {
			ip = ip.Mask(m)
		}
	}
	return ip
}

func optHasECS(opt *dns.OPT) bool {
	if opt == nil {
		return false
	}
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); ok {
			return true
		}
	}
	return false
}

// isTerminalNoData reports whether a response is an authoritative NODATA-style reply
// (NOERROR with no answers and no usable NS referrals).
func isTerminalNoData(resp *dns.Msg, nsNames []string) bool {
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		return false
	}
	if len(nsNames) == 0 {
		return true
	}
	for _, rr := range resp.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

type glueCacheEntry struct {
	ips     []net.IP
	expires time.Time
}

// maxGlueCacheEntries bounds the glue cache so attacker-chosen NS names cannot grow it
// without limit (there is no teardown hook to flush it otherwise).
const maxGlueCacheEntries = 8192

// pruneGlueCache bounds m in place. Callers must hold the glue cache mutex. It first
// drops expired entries, then, if still over a soft target, drops arbitrary entries
// (map iteration order) until under the target.
func pruneGlueCache(m map[string]glueCacheEntry, now time.Time) {
	for k, e := range m {
		if !e.expires.After(now) {
			delete(m, k)
		}
	}
	target := maxGlueCacheEntries / 2
	for k := range m {
		if len(m) <= target {
			break
		}
		delete(m, k)
	}
}

// maxGlueNamesChased bounds how many distinct NS names a single glueless referral will
// trigger out-of-band glue resolution for, limiting the fan-out per referral.
const maxGlueNamesChased = 6

// resolveGlue resolves nameserver addresses for a referral. depth is the caller's
// remaining recursion budget: out-of-band glue lookups are charged against it (NOT a
// fresh MaxDepth reset, which let a chain of glueless referrals recurse without bound),
// and the number of NS names chased is capped, so a single client query cannot fan out
// into runaway upstream traffic.
func (r *Recursive) resolveGlue(nsNames []string, resp *dns.Msg, depth int, ecsOpt *dns.EDNS0_SUBNET, b *queryBudget) []net.IP {
	ips := r.extractGlue(resp)
	now := time.Now()
	// Dedup the NS names while consulting the glue cache for each.
	seen := make(map[string]struct{}, len(nsNames))
	unique := make([]string, 0, len(nsNames))
	for _, name := range nsNames {
		key := strings.ToLower(name)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, name)
		r.glueCacheMutex.Lock()
		if entry, ok := r.glueCache[key]; ok && entry.expires.After(now) {
			ips = append(ips, entry.ips...)
		}
		r.glueCacheMutex.Unlock()
	}
	if len(ips) > 0 {
		return dedupIPs(ips, r.PreferIPv6)
	}
	// No in-band glue or cached glue: chase it ourselves, but only with remaining budget
	// and only for a bounded number of names.
	if depth <= 0 {
		return nil
	}
	if len(unique) > maxGlueNamesChased {
		unique = unique[:maxGlueNamesChased]
	}
	for _, name := range unique {
		// Resolve the A and AAAA glue addresses concurrently: they are independent, each
		// is a full (and slow) sub-resolution, and waiting on them in series doubles the
		// latency of chasing a glueless referral. Both draw from the shared atomic query
		// budget, so the fan-out stays globally capped. Each goroutine has its own query
		// message and writes a distinct result; ecsOpt is only read (cloned) downstream.
		fqdn := dns.Fqdn(name)
		var aResp, aaaaResp *dns.Msg
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			aMsg := new(dns.Msg)
			aMsg.SetQuestion(fqdn, dns.TypeA)
			aResp, _ = r.resolveIterative(aMsg, depth-1, ecsOpt, b)
		}()
		go func() {
			defer wg.Done()
			aaaaMsg := new(dns.Msg)
			aaaaMsg.SetQuestion(fqdn, dns.TypeAAAA)
			aaaaResp, _ = r.resolveIterative(aaaaMsg, depth-1, ecsOpt, b)
		}()
		wg.Wait()
		collected := collectAandAAAA(aResp, aaaaResp)
		if len(collected) > 0 {
			r.scoreboard.register(collected)
			r.glueCacheMutex.Lock()
			if len(r.glueCache) >= maxGlueCacheEntries {
				pruneGlueCache(r.glueCache, now)
			}
			r.glueCache[strings.ToLower(name)] = glueCacheEntry{
				ips:     collected,
				expires: now.Add(10 * time.Minute),
			}
			r.glueCacheMutex.Unlock()
			ips = append(ips, collected...)
		}
	}
	return dedupIPs(ips, r.PreferIPv6)
}

// fetchDNSKEY uses the recursive resolver itself (without revalidation) to fetch DNSKEY for a zone.
// Each validation fetch carries its own fresh budget — it is bounded independently of
// the client query's main resolution tree (and of the other per-zone fetches).
func (r *Recursive) fetchDNSKEY(name string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeDNSKEY)
	return r.resolveIterativeValidated(msg, r.MaxDepth-1, false, nil, r.newBudget())
}

// fetchDS uses the recursive resolver to fetch DS for the zone (without revalidation).
func (r *Recursive) fetchDS(name string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeDS)
	return r.resolveIterativeValidated(msg, r.MaxDepth-1, false, nil, r.newBudget())
}

func parentZone(name string) string {
	name = strings.TrimSuffix(strings.ToLower(dns.Fqdn(name)), ".")
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return "."
	}
	return strings.Join(labels[1:], ".")
}

func collectAandAAAA(msgs ...*dns.Msg) []net.IP {
	var ips []net.IP
	for _, m := range msgs {
		if m == nil {
			continue
		}
		for _, rr := range m.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A)
			case *dns.AAAA:
				ips = append(ips, v.AAAA)
			}
		}
	}
	return ips
}

func (r *Recursive) extractGlue(resp *dns.Msg) []net.IP {
	var ips []net.IP
	for _, rr := range resp.Extra {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		}
	}
	return ips
}

func dedupIPs(list []net.IP, preferIPv6 bool) []net.IP {
	seen := make(map[string]bool)
	var v4, v6 []net.IP
	for _, ip := range list {
		key := ip.String()
		if seen[key] || ip == nil {
			continue
		}
		seen[key] = true
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	if preferIPv6 {
		return append(v6, v4...)
	}
	return append(v4, v6...)
}

func (r *Recursive) finalizeResponse(resp *dns.Msg) *dns.Msg {
	if resp == nil {
		return nil
	}
	resp.RecursionAvailable = true
	resp.Authoritative = false
	// Never trust an upstream AD bit; this resolver asserts AD only via its own
	// per-waiter applyPolicy stamp.
	resp.AuthenticatedData = false
	return resp
}

func (r *Recursive) socks5Timeout(timeout time.Duration) int {
	d := timeout / time.Second
	if d*time.Second < timeout {
		return int(d) + 1
	}
	return int(d)
}

func singleflightKey(msg *dns.Msg, clientCD, clientDO bool) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	key := strings.ToLower(q.Name) + "|" + strconv.Itoa(int(q.Qtype)) + "|" + strconv.Itoa(int(q.Qclass))
	if clientCD {
		key += "|cd"
	}
	if clientDO {
		key += "|do"
	}
	if opt := msg.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ecsOpt, ok := o.(*dns.EDNS0_SUBNET); ok {
				key += fmt.Sprintf("|ecs:%d/%d/%s/%d", ecsOpt.Family, ecsOpt.SourceNetmask, ecsOpt.Address.String(), ecsOpt.SourceScope)
				break
			}
		}
	}
	return key
}

type nsScore struct {
	ip          net.IP
	ewmaRTT     float64
	failStreak  int
	successes   int
	failures    int
	lastSuccess time.Time
	lastFail    time.Time
}

type nsScoreboard struct {
	mu     sync.RWMutex
	scores map[string]*nsScore
	topN   int
	roots  []net.IP
}

func newScoreboard(roots []RootServer, topN int) *nsScoreboard {
	var ips []net.IP
	for _, rs := range roots {
		ips = append(ips, rs.Addresses...)
	}
	return &nsScoreboard{
		scores: make(map[string]*nsScore),
		topN:   topN,
		roots:  ips,
	}
}

func (s *nsScoreboard) markSuccess(ip net.IP, rtt time.Duration) {
	key := ip.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.scores[key]
	if entry == nil {
		entry = &nsScore{ip: ip}
		s.scores[key] = entry
	}
	const alpha = 0.3
	// Store the EWMA in milliseconds. The optimistic seed used for untried servers
	// (scoreValue) is also in milliseconds, so a proven-fast server outranks an untried
	// one. Storing raw nanoseconds here would make every tried server score in the
	// millions and thus always lose to untried (often dead) servers.
	ms := float64(rtt) / float64(time.Millisecond)
	if ms <= 0 {
		ms = 0.1 // sub-millisecond RTT floor
	}
	if entry.ewmaRTT == 0 {
		entry.ewmaRTT = ms
	} else {
		entry.ewmaRTT = alpha*ms + (1-alpha)*entry.ewmaRTT
	}
	entry.failStreak = 0
	entry.successes++
	entry.lastSuccess = time.Now()
}

func (s *nsScoreboard) markFailure(ip net.IP) {
	key := ip.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.scores[key]
	if entry == nil {
		entry = &nsScore{ip: ip}
		s.scores[key] = entry
	}
	entry.failStreak++
	entry.failures++
	entry.lastFail = time.Now()
}

func (s *nsScoreboard) register(ips []net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ip := range ips {
		key := ip.String()
		if key == "" {
			continue
		}
		if _, exists := s.scores[key]; !exists {
			s.scores[key] = &nsScore{ip: ip, ewmaRTT: 50}
		}
	}
}

// probe measures every root concurrently. Probing all roots sequentially would, on a
// host with a broken address family, block for the sum of every dead server's timeout;
// running them in parallel bounds the wall time to the slowest single probe. The caller
// should still run probe off the request path (see initialize).
func (s *nsScoreboard) probe(exchange func(ip net.IP) (time.Duration, error)) {
	var wg sync.WaitGroup
	for _, ip := range s.roots {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			best, err := exchange(ip)
			if err != nil || best <= 0 {
				s.markFailure(ip)
				return
			}
			s.markSuccess(ip, best)
		}(ip)
	}
	wg.Wait()
}

// pickRoots returns the top ranked root IPs.
func (s *nsScoreboard) pickRoots(preferIPv6 bool) []net.IP {
	return s.pickFrom(s.roots, preferIPv6, s.topN)
}

// pickFrom orders the provided IP list by score and returns up to limit (or all if limit<=0).
func (s *nsScoreboard) pickFrom(ips []net.IP, preferIPv6 bool, limit int) []net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*nsScore
	seen := make(map[string]bool)
	for _, ip := range ips {
		key := ip.String()
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		entry := s.scores[key]
		if entry == nil {
			entry = &nsScore{ip: ip} // untried; scoreValue applies the optimistic seed
		}
		list = append(list, entry)
	}
	sort.Slice(list, func(i, j int) bool {
		si, sj := scoreValue(list[i], preferIPv6), scoreValue(list[j], preferIPv6)
		if si != sj {
			return si < sj
		}
		return list[i].ip.String() < list[j].ip.String() // deterministic tiebreak
	})
	if limit <= 0 || limit > len(list) {
		limit = len(list)
	}
	out := make([]net.IP, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, list[i].ip)
	}
	return ensureFamilyDiversity(out, list, limit)
}

// ensureFamilyDiversity guarantees that, whenever both address families are present in
// the candidate set, the returned selection contains at least one server of each. On a
// host where one family's egress is broken, the working family must always be attempted
// rather than starved by a full-of-the-dead-family selection. If the selection is
// single-family, the worst slot is replaced by the best-scored server of the missing
// family (the candidate list is already sorted best-first).
func ensureFamilyDiversity(out []net.IP, sorted []*nsScore, limit int) []net.IP {
	if limit < 2 || len(out) < 2 {
		return out
	}
	haveV4, haveV6 := false, false
	for _, ip := range out {
		if ip.To4() != nil {
			haveV4 = true
		} else {
			haveV6 = true
		}
	}
	if haveV4 && haveV6 {
		return out
	}
	missingIsV6 := !haveV6 // selection is all-IPv4 -> we need an IPv6, and vice versa
	for _, sc := range sorted {
		if (sc.ip.To4() == nil) == missingIsV6 {
			out[len(out)-1] = sc.ip
			return out
		}
	}
	return out // the missing family is not available at all
}

// familyBiasMillis is the small RTT-equivalent margin (in ms) that biases server
// selection toward the preferred address family (IPv4 by default). It is intentionally
// small so a genuinely faster opposite-family server still wins, but it breaks
// cold-start ties deterministically so a host with broken IPv6 egress does not stall on
// dead IPv6 servers.
const familyBiasMillis = 15.0

// scoreValue ranks a nameserver; lower is better. Score = EWMA RTT (ms) + a steep
// per-consecutive-failure penalty (a server that just failed drops far down) + the
// address-family bias.
func scoreValue(entry *nsScore, preferIPv6 bool) float64 {
	base := entry.ewmaRTT
	if base <= 0 {
		base = 50 // optimistic seed (ms) for an untried server
	}
	score := base + float64(entry.failStreak)*100
	if entry.ip.To4() == nil { // IPv6
		if preferIPv6 {
			score -= familyBiasMillis
		} else {
			score += familyBiasMillis
		}
	}
	return score
}

func durationFiller(field, jsonKey string, def time.Duration) descriptor.ObjectFiller {
	return descriptor.ObjectFiller{
		ObjectPath: descriptor.Path{field},
		ValueSource: descriptor.ValueSources{
			descriptor.ObjectAtPath{
				ObjectPath: descriptor.Path{jsonKey},
				AssignableKind: descriptor.AssignableKinds{
					descriptor.ConvertibleKind{
						Kind: descriptor.KindFloat64,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							seconds, ok := original.(float64)
							if !ok || seconds <= 0 {
								return nil, false
							}
							return time.Duration(seconds * float64(time.Second)), true
						},
					},
					descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							seconds, err := strconv.ParseFloat(strings.TrimSpace(original.(string)), 64)
							if err != nil || seconds <= 0 {
								return nil, false
							}
							return time.Duration(seconds * float64(time.Second)), true
						},
					},
				},
			},
			descriptor.DefaultValue{Value: def},
		},
	}
}

// durationFillerAllowZero is durationFiller but accepts 0 (and rejects negatives), so a
// config value of 0 can disable an optional time budget rather than falling back to the
// default.
func durationFillerAllowZero(field, jsonKey string, def time.Duration) descriptor.ObjectFiller {
	return descriptor.ObjectFiller{
		ObjectPath: descriptor.Path{field},
		ValueSource: descriptor.ValueSources{
			descriptor.ObjectAtPath{
				ObjectPath: descriptor.Path{jsonKey},
				AssignableKind: descriptor.AssignableKinds{
					descriptor.ConvertibleKind{
						Kind: descriptor.KindFloat64,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							seconds, ok := original.(float64)
							if !ok || seconds < 0 {
								return nil, false
							}
							return time.Duration(seconds * float64(time.Second)), true
						},
					},
					descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							seconds, err := strconv.ParseFloat(strings.TrimSpace(original.(string)), 64)
							if err != nil || seconds < 0 {
								return nil, false
							}
							return time.Duration(seconds * float64(time.Second)), true
						},
					},
				},
			},
			descriptor.DefaultValue{Value: def},
		},
	}
}

func intFiller(field, jsonKey string, min, max int, def int) descriptor.ObjectFiller {
	return descriptor.ObjectFiller{
		ObjectPath: descriptor.Path{field},
		ValueSource: descriptor.ValueSources{
			descriptor.ObjectAtPath{
				ObjectPath: descriptor.Path{jsonKey},
				AssignableKind: descriptor.AssignableKinds{
					descriptor.ConvertibleKind{
						Kind: descriptor.KindFloat64,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							i := int(original.(float64))
							if i < min || (max > 0 && i > max) {
								return nil, false
							}
							return i, true
						},
					},
					descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							i, err := strconv.Atoi(strings.TrimSpace(original.(string)))
							if err != nil || i < min || (max > 0 && i > max) {
								return nil, false
							}
							return i, true
						},
					},
				},
			},
			descriptor.DefaultValue{Value: def},
		},
	}
}

func boolFiller(field, jsonKey string, def bool) descriptor.ObjectFiller {
	return descriptor.ObjectFiller{
		ObjectPath: descriptor.Path{field},
		ValueSource: descriptor.ValueSources{
			descriptor.ObjectAtPath{
				ObjectPath: descriptor.Path{jsonKey},
				AssignableKind: descriptor.AssignableKinds{
					descriptor.KindBool,
					descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							switch strings.ToLower(strings.TrimSpace(original.(string))) {
							case "true":
								return true, true
							case "false":
								return false, true
							default:
								return nil, false
							}
						},
					},
				},
			},
			descriptor.DefaultValue{Value: def},
		},
	}
}
