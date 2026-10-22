// Package server implements the HTTP admin listener that populates the record store the
// authoritative resolver answers from. It exposes a small bearer-authenticated CRUD API
// (POST/DELETE/GET /admin/records) and is meant to bind a loopback or management address,
// never the public internet. It fails closed: without a configured token it refuses to
// serve.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/internal/sourcepolicy"
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
	nodeHealthRunner func(context.Context, string, string, string, []byte) (nodeHealthResult, error)
	nodeBGPRunner    func(context.Context, string, string, string, []byte) (nodeBGPResult, error)

	NodeAdapterExecutable string
	NodeAdapterScript     string
	NodeAuditDirectory    string
	nodeRunner            func(context.Context, string, string, string) (nodeSnapshot, error)
	AgentAuthConfigured   bool
	agent                 *agentBinding
	Listen                net.IP
	Port                  uint16
	Path                  string
	Store                 string // shared store name; empty joins recordstore.DefaultName
	Token                 string // bearer token; required (the listener fails closed without it)
	UI                    bool   // optional embedded UI; disabled by default
	FollowerStatusOnly    bool   // explicit status-only listener; never binds a record store
	// SourcePolicyExplain enables the authenticated, read-only offline selector
	// preview. Configuration binding supplies the immutable selector before Serve.
	SourcePolicyExplain       bool
	SnapshotReaders           []SnapshotReader
	RecordAuthorityURL        string // optional fixed loopback gateway base; local identity remains local
	RecordAuthorityToken      string // server-side upstream credential, never sent to browsers
	RecordAuthorityTokenFile  string // existing private credential; alternative to inline token
	recordAuthorityCredential string

	store                *recordstore.Store
	versioned            *recordstore.VersionedStore
	sourcePolicySelector sourcepolicy.Explainer
	followerStatusNames  []string
	followerStatus       func() []followerObservation
}

type SnapshotReader struct {
	NodeID string
	Token  string
}

type snapshotReaderContextKey struct{}

func SnapshotReaderNodeID(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(snapshotReaderContextKey{}).(string)
	return value, ok && value != ""
}

func validSnapshotReaderIdentity(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func validSnapshotReaderToken(value string) bool {
	if len(value) < 32 || len(value) > 512 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func (h *HTTPAdminServer) ValidateSnapshotReaders() error {
	if len(h.SnapshotReaders) > 64 {
		return ErrSnapshotReaders
	}
	ids := map[string]bool{}
	tokens := map[[sha256.Size]byte]bool{}
	admin := sha256.Sum256([]byte(h.Token))
	for _, reader := range h.SnapshotReaders {
		digest := sha256.Sum256([]byte(reader.Token))
		if !validSnapshotReaderIdentity(reader.NodeID) || !validSnapshotReaderToken(reader.Token) || ids[reader.NodeID] || tokens[digest] || subtle.ConstantTimeCompare(digest[:], admin[:]) == 1 {
			return ErrSnapshotReaders
		}
		ids[reader.NodeID] = true
		tokens[digest] = true
	}
	return nil
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
	if err := h.ValidateSnapshotReaders(); err != nil {
		handleIfError(err, errorHandler)
		return
	}
	if err := h.prepareRecordBinding(); err != nil {
		handleIfError(err, errorHandler)
		return
	}
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
	h.nodeRoutes(mux, base)
	if h.FollowerStatusOnly {
		if h.ValidateFollowerStatusOnly() != nil {
			return mux
		}
		h.followerRoutes(mux, base)
		if h.UI {
			h.consoleRoutes(mux, base)
			h.followerOnlyUIRoutes(mux, base)
		}
		return mux
	}
	if h.recordGatewayEnabled() {
		if h.ValidateRecordGateway() != nil || h.agent == nil || h.agent.origin == "" {
			return mux
		}
		h.agentRoutes(mux, base)
		h.recordGatewayRoutes(mux, base)
		if h.UI {
			h.consoleRoutes(mux, base)
			h.routerOSPreviewRoutes(mux, base)
			h.editorRoutes(mux, base)
		}
		return mux
	}
	h.agentRoutes(mux, base)
	h.followerRoutes(mux, base)
	if h.SourcePolicyExplain {
		h.sourcePolicyExplainRoutes(mux, base)
	}
	if h.UI {
		h.consoleRoutes(mux, base)
		h.routerOSPreviewRoutes(mux, base)
	}
	if h.versioned != nil {
		mux.HandleFunc("GET "+base+"/snapshot", h.withScopes(h.handleSnapshot, true, adminauth.RecordsRead))
		mux.HandleFunc("GET "+base+"/snapshot/events", h.withScopes(h.handleSnapshotEvents, true, adminauth.RecordsRead, adminauth.SnapshotEvents))
		mux.HandleFunc("POST "+base+"/snapshot", h.withScopes(h.handleReplace, false, adminauth.RecordsWrite))
		mux.HandleFunc("POST "+base+"/snapshot/rrset", h.withScopes(h.handleRRsetMutation, false, adminauth.RecordsWrite))
		blocked := func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "versioned_batch_required"})
		}
		mux.HandleFunc("GET "+base+"/records", h.withScopes(blocked, false, adminauth.RecordsRead))
		mux.HandleFunc("POST "+base+"/records", h.withScopes(blocked, false, adminauth.RecordsWrite))
		mux.HandleFunc("DELETE "+base+"/records/{name}/{type}", h.withScopes(blocked, false, adminauth.RecordsWrite))
		if h.UI {
			h.editorRoutes(mux, base)
		}
		return mux
	}

	mux.HandleFunc("GET "+base+"/records", h.withScopes(h.handleList, false, adminauth.RecordsRead))
	mux.HandleFunc("POST "+base+"/records", h.withScopes(h.handleSet, false, adminauth.RecordsWrite))
	mux.HandleFunc("DELETE "+base+"/records/{name}/{type}", h.withScopes(h.handleDelete, false, adminauth.RecordsWrite))
	if h.UI {
		h.editorRoutes(mux, base)
	}
	return mux
}

// readAuth admits the existing admin token or one configured read-only token.
// Every configured digest is compared on every request; request data never
// selects or overrides the configured reader identity.
func (h *HTTPAdminServer) readAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, errMissingBearer)
			return
		}
		presented := sha256.Sum256([]byte(token))
		admin := sha256.Sum256([]byte(h.Token))
		adminMatch := subtle.ConstantTimeCompare(presented[:], admin[:])
		readerMatch := 0
		nodeID := ""
		for _, reader := range h.SnapshotReaders {
			digest := sha256.Sum256([]byte(reader.Token))
			match := subtle.ConstantTimeCompare(presented[:], digest[:])
			readerMatch |= match
			if match == 1 {
				nodeID = reader.NodeID
			}
		}
		if adminMatch|readerMatch != 1 {
			writeError(w, http.StatusForbidden, errInvalidBearer)
			return
		}
		if adminMatch != 1 {
			r = r.WithContext(context.WithValue(r.Context(), snapshotReaderContextKey{}, nodeID))
		}
		next(w, r)
	}
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
	ExpiresAt        *string  `json:"expires_at,omitempty"`
	absolutePresent  bool
	relativePresent  bool
}

func (h *HTTPAdminServer) handleSet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req setRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid record request"))
		return
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		writeError(w, http.StatusBadRequest, errors.New("request must contain one JSON object"))
		return
	}
	rec, err := req.toRecord(time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.store.SetValidated(rec); err != nil {
		switch {
		case errors.Is(err, recordstore.ErrInvalidRecord), errors.Is(err, recordstore.ErrExpiredRecord):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, recordstore.ErrRecordConflict):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusServiceUnavailable, errors.New("record mutation failed"))
		}
		return
	}
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
	deleted, err := h.store.Delete(name, rrtype)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("record mutation failed"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": deleted})
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
			rj.ExpiresAt = rec.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		out = append(out, rj)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"records": out})
}

// toRecord validates the request and converts it to a store record relative to now.
func (req setRequest) toRecord(now time.Time) (recordstore.Record, error) {
	if (req.absolutePresent || req.ExpiresAt != nil) && (req.relativePresent || req.ExpiresInSeconds != nil) {
		return recordstore.Record{}, errBadExpiry
	}
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
	values := append([]string(nil), req.Values...)
	if rrtype == dns.TypeA || rrtype == dns.TypeAAAA {
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
	}
	rec := recordstore.Record{Name: name, Type: rrtype, Values: values, TTL: ttl}
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339Nano, *req.ExpiresAt)
		if err != nil || !expiry.After(now) || expiry.UTC().Year() < 1 || expiry.UTC().Year() > 9999 {
			return recordstore.Record{}, errBadExpiry
		}
		rec.ExpiresAt = expiry.UTC()
	}
	if req.ExpiresInSeconds != nil {
		if *req.ExpiresInSeconds < 0 || *req.ExpiresInSeconds > int64((1<<63-1)/time.Second) {
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
	return recordstore.ValidName(name)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
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
				ObjectPath: descriptor.Path{"UI"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"ui"}, AssignableKind: descriptor.KindBool},
					descriptor.DefaultValue{Value: false},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"FollowerStatusOnly"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"followerStatusOnly"}, AssignableKind: descriptor.KindBool},
					descriptor.DefaultValue{Value: false},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"SourcePolicyExplain"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"sourcePolicyExplain"}, AssignableKind: descriptor.KindBool},
					descriptor.DefaultValue{Value: false},
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
			descriptor.ObjectFiller{ObjectPath: descriptor.Path{"NodeAdapterExecutable"}, ValueSource: descriptor.ValueSources{descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"nodeAdapterExecutable"}, AssignableKind: descriptor.KindString}, descriptor.DefaultValue{Value: ""}}}, descriptor.ObjectFiller{ObjectPath: descriptor.Path{"NodeAdapterScript"}, ValueSource: descriptor.ValueSources{descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"nodeAdapterScript"}, AssignableKind: descriptor.KindString}, descriptor.DefaultValue{Value: ""}}}, descriptor.ObjectFiller{ObjectPath: descriptor.Path{"NodeAuditDirectory"}, ValueSource: descriptor.ValueSources{descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"nodeAuditDirectory"}, AssignableKind: descriptor.KindString}, descriptor.DefaultValue{Value: ""}}}, descriptor.ObjectFiller{ObjectPath: descriptor.Path{"RecordAuthorityURL"}, ValueSource: descriptor.ValueSources{descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"recordAuthorityURL"}, AssignableKind: descriptor.KindString}, descriptor.DefaultValue{Value: ""}}},
			descriptor.ObjectFiller{ObjectPath: descriptor.Path{"RecordAuthorityToken"}, ValueSource: descriptor.ValueSources{descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"recordAuthorityToken"}, AssignableKind: descriptor.KindString}, descriptor.DefaultValue{Value: ""}}},
			descriptor.ObjectFiller{ObjectPath: descriptor.Path{"RecordAuthorityTokenFile"}, ValueSource: descriptor.ValueSources{descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"recordAuthorityTokenFile"}, AssignableKind: descriptor.KindString}, descriptor.DefaultValue{Value: ""}}},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"SnapshotReaders"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"snapshotReaders"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindSlice,
							ConvertFunction: func(original interface{}) (interface{}, bool) {
								values, ok := original.([]interface{})
								if !ok || len(values) > 64 {
									return nil, false
								}
								readers := make([]SnapshotReader, 0, len(values))
								ids := map[string]bool{}
								tokens := map[[sha256.Size]byte]bool{}
								for _, value := range values {
									object, ok := value.(map[string]interface{})
									if !ok || len(object) != 2 {
										return nil, false
									}
									nodeID, nodeOK := object["nodeId"].(string)
									token, tokenOK := object["token"].(string)
									digest := sha256.Sum256([]byte(token))
									if !nodeOK || !tokenOK || !validSnapshotReaderIdentity(nodeID) || !validSnapshotReaderToken(token) || ids[nodeID] || tokens[digest] {
										return nil, false
									}
									ids[nodeID] = true
									tokens[digest] = true
									readers = append(readers, SnapshotReader{NodeID: nodeID, Token: token})
								}
								return readers, true
							},
						},
					},
					descriptor.DefaultValue{Value: []SnapshotReader(nil)},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}
