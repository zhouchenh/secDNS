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

// Recursive is a placeholder for a full recursive, DNSSEC-validating resolver.
// It is scaffolded now to wire descriptors, defaults, and root hints; recursion and validation will be implemented in follow-up steps.
type Recursive struct {
	RootServers     []RootServer
	ValidateDNSSEC  string
	QNameMinimize   bool
	EDNSSize        uint16
	Timeout         time.Duration
	Retries         int
	ProbeTopN       int
	ProbeInterval   time.Duration
	PreferIPv6      bool
	MaxDepth        int
	MaxCNAME        int
	MaxReferrals    int
	Socks5Proxy     string
	Socks5Username  string
	Socks5Password  string
	SendThrough     net.IP
	EcsMode         string
	EcsClientSubnet string

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
}

var (
	typeOfRecursive            = descriptor.TypeOfNew(new(*Recursive))
	ErrRecursiveNotImplemented = errors.New("recursive resolver: not implemented yet")
	defaultRecursiveConfig     = &Recursive{
		RootServers:     defaultRootHints(),
		ValidateDNSSEC:  "permissive",
		QNameMinimize:   true,
		EDNSSize:        1232,
		Timeout:         1500 * time.Millisecond,
		Retries:         2,
		ProbeTopN:       5,
		ProbeInterval:   time.Hour,
		PreferIPv6:      false,
		MaxDepth:        32,
		MaxCNAME:        8,
		MaxReferrals:    16,
		Socks5Proxy:     "",
		Socks5Username:  "",
		Socks5Password:  "",
		SendThrough:     nil,
		EcsMode:         "",
		EcsClientSubnet: "",
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
	baseECS := cloneECSOption(extractECSOption(query))
	queryCopy := query.Copy()
	if err := r.applyECS(queryCopy, baseECS); err != nil {
		return nil, err
	}
	key := singleflightKey(queryCopy)
	result, err, _ := r.reqGroup.Do(key, func() (interface{}, error) {
		resp, e := r.resolveIterative(queryCopy, depth, baseECS)
		return resp, e
	})
	if err != nil {
		return nil, err
	}
	return result.(*dns.Msg), nil
}

func init() {
	convertibleKindIP := descriptor.ConvertibleKind{
		Kind: descriptor.KindString,
		ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
			str, ok := original.(string)
			if !ok {
				return
			}
			converted = net.ParseIP(strings.TrimSpace(str))
			ok = converted != nil
			return
		},
	}
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfRecursive,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ValueSource: descriptor.DefaultValue{Value: defaultRecursiveConfig},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"RootServers"},
				ValueSource: descriptor.ObjectAtPath{
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
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"ValidateDNSSEC"},
				ValueSource: descriptor.ObjectAtPath{
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
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"QNameMinimize"},
				ValueSource: descriptor.ObjectAtPath{
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
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"EDNSSize"},
				ValueSource: descriptor.ObjectAtPath{
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
			},
			durationFiller("Timeout", "timeout", defaultRecursiveConfig.Timeout),
			durationFiller("ProbeInterval", "probeInterval", defaultRecursiveConfig.ProbeInterval),
			intFiller("Retries", "retries", 0, 5, defaultRecursiveConfig.Retries),
			intFiller("ProbeTopN", "probeTopN", 1, 13, defaultRecursiveConfig.ProbeTopN),
			intFiller("MaxDepth", "maxDepth", 1, 128, defaultRecursiveConfig.MaxDepth),
			intFiller("MaxCNAME", "maxCNAME", 1, 32, defaultRecursiveConfig.MaxCNAME),
			intFiller("MaxReferrals", "maxReferrals", 1, 64, defaultRecursiveConfig.MaxReferrals),
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
					descriptor.DefaultValue{Value: ""},
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

func (r *Recursive) initialize() {
	if len(r.RootServers) == 0 {
		r.RootServers = defaultRootHints()
	}
	if r.log == nil {
		r.log = func(msg string) { common.ErrOutput(msg) }
	}
	r.prepareDialers()
	r.scoreboard = newScoreboard(r.RootServers, r.ProbeTopN)
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
		common.ErrOutput(fmt.Errorf(msg))
	}
	r.validator = validator
	// Initial probes are best-effort; failures keep default ordering.
	r.scoreboard.probe(func(ip net.IP) (time.Duration, error) {
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

func (r *Recursive) resolveIterative(query *dns.Msg, depth int, ecsOpt *dns.EDNS0_SUBNET) (*dns.Msg, error) {
	return r.resolveIterativeValidated(query, depth, true, ecsOpt)
}

func (r *Recursive) resolveIterativeNoValidate(query *dns.Msg, depth int, ecsOpt *dns.EDNS0_SUBNET) (*dns.Msg, error) {
	return r.resolveIterativeValidated(query, depth, false, ecsOpt)
}

func (r *Recursive) resolveIterativeValidated(query *dns.Msg, depth int, validate bool, ecsOpt *dns.EDNS0_SUBNET) (*dns.Msg, error) {
	if depth <= 0 {
		return nil, resolver.ErrLoopDetected
	}
	if err := r.applyECS(query, ecsOpt); err != nil {
		return nil, err
	}
	servers := r.scoreboard.pickRoots(r.PreferIPv6)
	return r.resolveWithServers(query, servers, depth, 0, validate, ecsOpt)
}

func (r *Recursive) resolveWithServers(query *dns.Msg, servers []net.IP, depth int, referrals int, validate bool, ecsOpt *dns.EDNS0_SUBNET) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("recursive resolver: no servers available")
	}
	if err := r.applyECS(query, ecsOpt); err != nil {
		return nil, err
	}
	question := query.Question[0]
	for _, ip := range servers {
		resp, rtt, err := r.exchange(query, ip)
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

		if validated, err := r.validator.validateResponse(resp, question, r.ValidateDNSSEC, validate); err != nil {
			if r.ValidateDNSSEC == "strict" {
				return nil, err
			}
			// permissive/off: continue without AD.
		} else if validated {
			resp.AuthenticatedData = true
		}

		// Cache DNSKEY/DS from authority for later trust decisions.
		r.cacheAuthDNSKEYDS(resp)

		switch resp.Rcode {
		case dns.RcodeSuccess:
			// If answer contains the qtype or CNAME leading to it, return.
			if len(resp.Answer) > 0 {
				if final, follow := r.followCNAME(resp, question, depth); final != nil || follow == nil {
					if final != nil {
						return final, nil
					}
				} else if follow != nil && depth > 0 {
					next, err := r.resolveIterativeValidated(follow, depth-1, validate, ecsOpt)
					if err != nil {
						return nil, err
					}
					merged := mergeWithCNAME(resp, next)
					return merged, nil
				}
				return resp, nil
			}
			// No answer: treat like referral handling below.
		case dns.RcodeNameError, dns.RcodeServerFailure, dns.RcodeFormatError:
			return resp, nil
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
		glueIPs := r.resolveGlue(nsNames, resp, ecsOpt)
		if len(glueIPs) == 0 {
			continue
		}
		ordered := r.scoreboard.pickFrom(glueIPs, r.PreferIPv6, r.ProbeTopN)
		next, err := r.resolveWithServers(query, ordered, depth-1, referrals+1, validate, ecsOpt)
		if err == nil {
			return next, nil
		}
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
	if err == nil && resp != nil && resp.Truncated {
		resp, rtt, err = r.clients["tcp"].Exchange(msg, addr)
	}
	if err != nil {
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
	if clone.SourceScope == 0 {
		clone.SourceScope = clone.SourceNetmask // RFC 7871 default
	}
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

func (r *Recursive) resolveGlue(nsNames []string, resp *dns.Msg, ecsOpt *dns.EDNS0_SUBNET) []net.IP {
	ips := r.extractGlue(resp)
	now := time.Now()
	for _, name := range nsNames {
		key := strings.ToLower(name)
		r.glueCacheMutex.Lock()
		if entry, ok := r.glueCache[key]; ok && entry.expires.After(now) {
			ips = append(ips, entry.ips...)
		}
		r.glueCacheMutex.Unlock()
	}
	if len(ips) > 0 {
		return dedupIPs(ips, r.PreferIPv6)
	}
	// Fallback: resolve A/AAAA for NS names using roots again (simple path)
	for _, name := range nsNames {
		aMsg := new(dns.Msg)
		aMsg.SetQuestion(dns.Fqdn(name), dns.TypeA)
		aResp, _ := r.resolveIterative(aMsg, r.MaxDepth-1, ecsOpt)
		aaaaMsg := new(dns.Msg)
		aaaaMsg.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
		aaaaResp, _ := r.resolveIterative(aaaaMsg, r.MaxDepth-1, ecsOpt)
		collected := collectAandAAAA(aResp, aaaaResp)
		if len(collected) > 0 {
			r.scoreboard.register(collected)
			r.glueCacheMutex.Lock()
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

// cacheAuthDNSKEYDS stores DNSKEY/DS from authority section for reuse in validation.
func (r *Recursive) cacheAuthDNSKEYDS(resp *dns.Msg) {
	// Simple in-memory hints via glueCache structure keyed by auth name; reuse its mutex.
	now := time.Now().Add(1 * time.Hour)
	r.glueCacheMutex.Lock()
	defer r.glueCacheMutex.Unlock()
	for _, rr := range resp.Ns {
		switch rrTyped := rr.(type) {
		case *dns.DNSKEY:
			key := "dnskey:" + strings.ToLower(rrTyped.Hdr.Name)
			r.glueCache[key] = glueCacheEntry{expires: now}
		case *dns.DS:
			key := "ds:" + strings.ToLower(rrTyped.Hdr.Name)
			r.glueCache[key] = glueCacheEntry{expires: now}
		}
	}
}

// fetchDNSKEY uses the recursive resolver itself (without revalidation) to fetch DNSKEY for a zone.
func (r *Recursive) fetchDNSKEY(name string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeDNSKEY)
	return r.resolveIterativeValidated(msg, r.MaxDepth-1, false, nil)
}

// fetchDS uses the recursive resolver to fetch DS for the zone (without revalidation).
func (r *Recursive) fetchDS(name string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeDS)
	return r.resolveIterativeValidated(msg, r.MaxDepth-1, false, nil)
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
	return resp
}

func (r *Recursive) socks5Timeout(timeout time.Duration) int {
	d := timeout / time.Second
	if d*time.Second < timeout {
		return int(d) + 1
	}
	return int(d)
}

func singleflightKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	key := strings.ToLower(q.Name) + "|" + strconv.Itoa(int(q.Qtype)) + "|" + strconv.Itoa(int(q.Qclass))
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
	if entry.ewmaRTT == 0 {
		entry.ewmaRTT = float64(rtt)
	} else {
		entry.ewmaRTT = alpha*float64(rtt) + (1-alpha)*entry.ewmaRTT
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

func (s *nsScoreboard) probe(exchange func(ip net.IP) (time.Duration, error)) {
	for _, ip := range s.roots {
		var best time.Duration
		var err error
		best, err = exchange(ip)
		if err != nil {
			best = 0
		}
		if best > 0 {
			s.markSuccess(ip, best)
		} else {
			s.markFailure(ip)
		}
	}
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
			entry = &nsScore{ip: ip, ewmaRTT: 50} // optimistic seed
		}
		list = append(list, entry)
	}
	sort.Slice(list, func(i, j int) bool {
		return scoreValue(list[i], preferIPv6) < scoreValue(list[j], preferIPv6)
	})
	if limit <= 0 || limit > len(list) {
		limit = len(list)
	}
	out := make([]net.IP, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, list[i].ip)
	}
	return out
}

func scoreValue(entry *nsScore, preferIPv6 bool) float64 {
	base := entry.ewmaRTT
	if base == 0 {
		base = 50 // seed default
	}
	penalty := float64(entry.failStreak * 100)
	if preferIPv6 && entry.ip.To4() == nil {
		return base + penalty - 5
	}
	return base + penalty
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
							v := time.Duration(original.(float64)) * time.Millisecond
							if v <= 0 {
								return nil, false
							}
							return v, true
						},
					},
					descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							v, err := time.ParseDuration(strings.TrimSpace(original.(string)))
							if err != nil || v <= 0 {
								return nil, false
							}
							return v, true
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
