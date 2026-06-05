// Package server implements the HTTP admin listener that populates the record store the
// authoritative resolver answers from. It exposes a small bearer-authenticated CRUD API
// (POST/DELETE/GET /admin/records) and is meant to bind a loopback or management address,
// never the public internet. It fails closed: without a configured token it refuses to
// serve.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
)

// maxRequestBodyBytes bounds the request body; a record payload is tiny.
const maxRequestBodyBytes = 64 << 10

// allowedTypes is the record-type set the admin API accepts (issue #6 initial set).
var allowedTypes = map[uint16]bool{
	dns.TypeTXT:   true,
	dns.TypeA:     true,
	dns.TypeAAAA:  true,
	dns.TypeCNAME: true,
}

type HTTPAdminServer struct {
	Listen net.IP
	Port   uint16
	Path   string
	Store  string // shared store name; empty joins recordstore.DefaultName
	Token  string // bearer token; required (the listener fails closed without it)

	store *recordstore.Store
}

var typeOfHTTPAdminServer = descriptor.TypeOfNew(new(*HTTPAdminServer))

func (h *HTTPAdminServer) Type() descriptor.Type {
	return typeOfHTTPAdminServer
}

func (h *HTTPAdminServer) TypeName() string {
	return "httpAdminServer"
}

// Serve starts the admin HTTP API. The DNS resolve handler is irrelevant here (the admin
// API does not resolve) and is ignored.
func (h *HTTPAdminServer) Serve(_ func(query *dns.Msg) (reply *dns.Msg), errorHandler func(err error)) {
	if strings.TrimSpace(h.Token) == "" {
		handleIfError(ErrMissingToken, errorHandler)
		return
	}
	h.store = recordstore.GetOrCreate(h.Store)
	srv := &http.Server{
		Addr:              net.JoinHostPort(h.Listen.String(), strconv.Itoa(int(h.Port))),
		Handler:           h.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	handleIfError(srv.ListenAndServe(), errorHandler)
}

// routes builds the authenticated request multiplexer. It is separated from Serve so
// the handlers can be driven in tests without binding a socket.
func (h *HTTPAdminServer) routes() *http.ServeMux {
	base := h.basePath()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"/records", h.auth(h.handleList))
	mux.HandleFunc("POST "+base+"/records", h.auth(h.handleSet))
	mux.HandleFunc("DELETE "+base+"/records/{name}/{type}", h.auth(h.handleDelete))
	return mux
}

func (h *HTTPAdminServer) basePath() string {
	p := h.Path
	if p == "" {
		p = "/admin"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

// auth wraps a handler with the bearer-token check: a missing or malformed
// Authorization header is 401, a present-but-wrong token is 403 (constant-time compared).
func (h *HTTPAdminServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, errMissingBearer)
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(h.Token)) != 1 {
			writeError(w, http.StatusForbidden, errInvalidBearer)
			return
		}
		next(w, r)
	}
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

type setRequest struct {
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Values           []string `json:"values"`
	TTLSeconds       uint32   `json:"ttl_seconds"`
	ExpiresInSeconds *int64   `json:"expires_in_seconds,omitempty"`
}

func (h *HTTPAdminServer) handleSet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req setRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rec, err := req.toRecord(time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.store.Set(rec)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *HTTPAdminServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	rrtype, ok := dns.StringToType[strings.ToUpper(r.PathValue("type"))]
	if !ok || !allowedTypes[rrtype] {
		writeError(w, http.StatusBadRequest, errBadType)
		return
	}
	if !validName(name) {
		writeError(w, http.StatusBadRequest, errBadName)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": h.store.Delete(name, rrtype)})
}

type recordJSON struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Values     []string `json:"values"`
	TTLSeconds uint32   `json:"ttl_seconds"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
}

func (h *HTTPAdminServer) handleList(w http.ResponseWriter, _ *http.Request) {
	recs := h.store.List()
	out := make([]recordJSON, 0, len(recs))
	for _, rec := range recs {
		rj := recordJSON{
			Name:       rec.Name,
			Type:       dns.TypeToString[rec.Type],
			Values:     rec.Values,
			TTLSeconds: rec.TTL,
		}
		if !rec.ExpiresAt.IsZero() {
			rj.ExpiresAt = rec.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, rj)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"records": out})
}

// toRecord validates the request and converts it to a store record relative to now.
func (req setRequest) toRecord(now time.Time) (recordstore.Record, error) {
	name := strings.TrimSpace(req.Name)
	if !validName(name) {
		return recordstore.Record{}, errBadName
	}
	rrtype, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(req.Type))]
	if !ok || !allowedTypes[rrtype] {
		return recordstore.Record{}, errBadType
	}
	if len(req.Values) == 0 {
		return recordstore.Record{}, errEmptyValues
	}
	if rrtype == dns.TypeA || rrtype == dns.TypeAAAA {
		for _, v := range req.Values {
			ip := net.ParseIP(strings.TrimSpace(v))
			if ip == nil || (rrtype == dns.TypeA) != (ip.To4() != nil) {
				return recordstore.Record{}, errBadIP
			}
		}
	}
	ttl := req.TTLSeconds
	if ttl == 0 {
		ttl = 60
	}
	rec := recordstore.Record{Name: name, Type: rrtype, Values: req.Values, TTL: ttl}
	if req.ExpiresInSeconds != nil {
		if *req.ExpiresInSeconds < 0 {
			return recordstore.Record{}, errBadExpiry
		}
		if *req.ExpiresInSeconds > 0 {
			rec.ExpiresAt = now.Add(time.Duration(*req.ExpiresInSeconds) * time.Second)
		}
	}
	return rec, nil
}

func validName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 255 {
		return false
	}
	_, ok := dns.IsDomainName(name)
	return ok
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func handleIfError(err error, errorHandler func(err error)) {
	if err != nil && errorHandler != nil {
		errorHandler(err)
	}
}

func init() {
	if err := server.RegisterServer(&descriptor.Descriptor{
		Type: typeOfHTTPAdminServer,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Listen"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
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
					// Loopback by default: the admin API must not be reachable off-host
					// unless the operator deliberately binds a routable address.
					descriptor.DefaultValue{Value: net.ParseIP("127.0.0.1")},
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
									i := int(original.(float64))
									if i < 0 || i > 65535 {
										return nil, false
									}
									return uint16(i), true
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									i, err := strconv.Atoi(strings.TrimSpace(original.(string)))
									if err != nil || i < 0 || i > 65535 {
										return nil, false
									}
									return uint16(i), true
								},
							},
						},
					},
					descriptor.DefaultValue{Value: uint16(9053)},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Path"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"path"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: "/admin"},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Store"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"store"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Token"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"token"},
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
