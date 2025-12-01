package server

import (
	"encoding/json"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type HTTPServer struct {
	Listen net.IP
	Port   uint16
	Path   string
}

var typeOfHTTPServer = descriptor.TypeOfNew(new(*HTTPServer))

func (h *HTTPServer) Type() descriptor.Type {
	return typeOfHTTPServer
}

func (h *HTTPServer) TypeName() string {
	return "httpAPIServer"
}

func (h *HTTPServer) Serve(handler func(query *dns.Msg) (reply *dns.Msg), errorHandler func(err error)) {
	if handler == nil {
		handleIfError(ErrNilHandler, errorHandler)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc(h.path(), func(w http.ResponseWriter, r *http.Request) {
		h.handleResolve(w, r, handler, errorHandler)
	})
	srv := &http.Server{
		Addr:    net.JoinHostPort(h.Listen.String(), strconv.Itoa(int(h.Port))),
		Handler: mux,
	}
	handleIfError(srv.ListenAndServe(), errorHandler)
}

func (h *HTTPServer) path() string {
	if h.Path == "" {
		return "/resolve"
	}
	if strings.HasPrefix(h.Path, "/") {
		return h.Path
	}
	return "/" + h.Path
}

type queryRequest struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	ECS   string `json:"ecs"`
}

func (h *HTTPServer) handleResolve(w http.ResponseWriter, r *http.Request, handler func(query *dns.Msg) (reply *dns.Msg), errorHandler func(err error)) {
	req, err := h.parseRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = []dns.Question{
		{
			Name:   dns.Fqdn(req.Name),
			Qtype:  req.qType(),
			Qclass: req.qClass(),
		},
	}
	if req.ECS != "" {
		if err := applyECS(msg, req.ECS); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	reply := handler(msg)
	if reply == nil {
		writeError(w, http.StatusBadGateway, errNilReply)
		return
	}
	writeJSON(w, toHTTPResponse(reply))
}

func (qr queryRequest) qType() uint16 {
	if qr.Type == "" {
		return dns.TypeA
	}
	if v, ok := dns.StringToType[strings.ToUpper(qr.Type)]; ok {
		return v
	}
	if n, err := strconv.Atoi(qr.Type); err == nil {
		return uint16(n)
	}
	return dns.TypeA
}

func (qr queryRequest) qClass() uint16 {
	if qr.Class == "" {
		return dns.ClassINET
	}
	if v, ok := dns.StringToClass[strings.ToUpper(qr.Class)]; ok {
		return v
	}
	if n, err := strconv.Atoi(qr.Class); err == nil {
		return uint16(n)
	}
	return dns.ClassINET
}

func (h *HTTPServer) parseRequest(r *http.Request) (queryRequest, error) {
	if r.Method == http.MethodGet {
		return parseQueryValues(r.URL.Query())
	}
	if r.Method == http.MethodPost {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "application/json") {
			var req queryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				return queryRequest{}, err
			}
			return validateRequest(req)
		}
		if err := r.ParseForm(); err != nil {
			return queryRequest{}, err
		}
		return parseQueryValues(r.PostForm)
	}
	return queryRequest{}, ErrUnsupportedMethod
}

func parseQueryValues(values map[string][]string) (queryRequest, error) {
	req := queryRequest{
		Name:  first(values, "name"),
		Type:  first(values, "type"),
		Class: first(values, "class"),
		ECS:   first(values, "ecs"),
	}
	if req.ECS == "" {
		req.ECS = first(values, "edns_client_subnet")
	}
	return validateRequest(req)
}

func first(values map[string][]string, key string) string {
	if values == nil {
		return ""
	}
	if v, ok := values[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func validateRequest(req queryRequest) (queryRequest, error) {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return queryRequest{}, ErrMissingName
	}
	return req, nil
}

func applyECS(msg *dns.Msg, subnet string) error {
	ip, prefix, err := ecs.ParseClientSubnet(strings.TrimSpace(subnet))
	if err != nil {
		return err
	}
	family := uint16(1)
	if ip.To4() == nil {
		family = 2
	}
	if family == 1 {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}
	mask := net.CIDRMask(int(prefix), len(ip)*8)
	if mask != nil {
		ip = ip.Mask(mask)
	}
	opt := msg.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		}
		msg.Extra = append(msg.Extra, opt)
	}
	ecsOpt := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: prefix,
		SourceScope:   prefix, // RFC 7871: default scope equals the sent prefix length
		Address:       ip,
	}
	opt.Option = append(opt.Option, ecsOpt)
	return nil
}

type messageJSON struct {
	ID        uint16         `json:"id"`
	RCode     string         `json:"rcode"`
	Question  []questionJSON `json:"question"`
	Answer    []recordJSON   `json:"answer"`
	Authority []recordJSON   `json:"authority"`
	Extra     []recordJSON   `json:"additional"`
}

type questionJSON struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type recordJSON struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

func toHTTPResponse(msg *dns.Msg) messageJSON {
	res := messageJSON{
		ID:        msg.Id,
		RCode:     dns.RcodeToString[msg.Rcode],
		Question:  make([]questionJSON, len(msg.Question)),
		Answer:    make([]recordJSON, len(msg.Answer)),
		Authority: make([]recordJSON, len(msg.Ns)),
		Extra:     make([]recordJSON, len(msg.Extra)),
	}
	for i, q := range msg.Question {
		res.Question[i] = questionJSON{
			Name:  q.Name,
			Type:  dns.TypeToString[q.Qtype],
			Class: dns.ClassToString[q.Qclass],
		}
	}
	for i, rr := range msg.Answer {
		res.Answer[i] = toRecord(rr)
	}
	for i, rr := range msg.Ns {
		res.Authority[i] = toRecord(rr)
	}
	for i, rr := range msg.Extra {
		res.Extra[i] = toRecord(rr)
	}
	return res
}

func toRecord(rr dns.RR) recordJSON {
	return recordJSON{
		Name:  rr.Header().Name,
		Type:  dns.TypeToString[rr.Header().Rrtype],
		Class: dns.ClassToString[rr.Header().Class],
		TTL:   rr.Header().Ttl,
		Data:  rr.String(),
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func handleIfError(err error, errorHandler func(err error)) {
	if err != nil && errorHandler != nil {
		errorHandler(err)
	}
}

func init() {
	if err := server.RegisterServer(&descriptor.Descriptor{
		Type: typeOfHTTPServer,
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
					descriptor.DefaultValue{Value: uint16(8080)},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Path"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"path"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: "/resolve"},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}
