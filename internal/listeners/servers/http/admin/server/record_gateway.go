package server

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/recordset"
)

var ErrRecordGateway = errors.New("admin: invalid record authority gateway")

func (h *HTTPAdminServer) recordGatewayEnabled() bool {
	return h.RecordAuthorityURL != "" || h.RecordAuthorityToken != "" || h.RecordAuthorityTokenFile != ""
}

// ValidateRecordGateway performs no I/O. The only supported transport is an
// explicitly configured loopback endpoint (normally an existing pinned SSH forward).
// Browser input never selects its authority, path, credentials or transport.
func (h *HTTPAdminServer) ValidateRecordGateway() error {
	if !h.recordGatewayEnabled() {
		return nil
	}
	u, err := url.Parse(h.RecordAuthorityURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || strings.ContainsAny(h.RecordAuthorityURL, "?#") {
		return ErrRecordGateway
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 || u.Path == "" || strings.HasSuffix(u.Path, "/") {
		return ErrRecordGateway
	}
	for _, segment := range strings.Split(u.Path, "/")[1:] {
		if segment == "" || segment == "." || segment == ".." {
			return ErrRecordGateway
		}
		for _, c := range segment {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ErrRecordGateway
			}
		}
	}
	if port == int(h.Port) {
		return ErrRecordGateway
	} // refuse self-forwarding, even across aliases
	if (h.RecordAuthorityToken == "") == (h.RecordAuthorityTokenFile == "") {
		return ErrRecordGateway
	}
	if h.RecordAuthorityTokenFile != "" && !filepath.IsAbs(h.RecordAuthorityTokenFile) {
		return ErrRecordGateway
	}
	if h.RecordAuthorityToken != "" && !validSnapshotReaderToken(h.RecordAuthorityToken) {
		return ErrRecordGateway
	}
	if !h.AgentAuthConfigured || h.Store != "" || h.FollowerStatusOnly || h.SourcePolicyExplain || len(h.SnapshotReaders) != 0 || len(h.followerStatusNames) != 0 || h.store != nil || h.versioned != nil {
		return ErrRecordGateway
	}
	return nil
}

func (h *HTTPAdminServer) prepareRecordGateway() error {
	if err := h.ValidateRecordGateway(); err != nil {
		return err
	}
	if h.RecordAuthorityTokenFile == "" {
		h.recordAuthorityCredential = h.RecordAuthorityToken
		return nil
	}
	info, err := os.Lstat(h.RecordAuthorityTokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 514 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return ErrRecordGateway
	}
	f, err := os.Open(h.RecordAuthorityTokenFile)
	if err != nil {
		return ErrRecordGateway
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return ErrRecordGateway
	}
	raw, err := io.ReadAll(io.LimitReader(f, 515))
	if err != nil || len(raw) > 514 {
		return ErrRecordGateway
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if !validSnapshotReaderToken(token) {
		return ErrRecordGateway
	}
	h.recordAuthorityCredential = token
	return nil
}

func (h *HTTPAdminServer) recordGatewayRoutes(mux *http.ServeMux, base string) {
	denyLegacy := func(w http.ResponseWriter, r *http.Request) {
		agentError(w, http.StatusForbidden, "session_or_agent_required")
	}
	for _, route := range []struct {
		method, path string
		scope        adminauth.Scope
	}{
		{"GET", "/snapshot", adminauth.RecordsRead},
		{"POST", "/snapshot", adminauth.RecordsWrite},
		{"POST", "/snapshot/rrset", adminauth.RecordsWrite},
	} {
		method, path := route.method, route.path
		mux.HandleFunc(method+" "+base+path, h.authorizeAgent(func(w http.ResponseWriter, r *http.Request) { h.forwardRecordRequest(w, r, method, path) }, denyLegacy, []adminauth.Scope{route.scope}))
	}
}

func (h *HTTPAdminServer) forwardRecordRequest(w http.ResponseWriter, r *http.Request, method, path string) {
	if r.Method != method || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		agentError(w, 400, "invalid_gateway_request")
		return
	}
	if h.recordAuthorityCredential == "" {
		agentError(w, 503, "record_authority_unavailable")
		return
	}
	var body []byte
	if method == "POST" {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, recordset.MaxBytes))
		if err != nil {
			agentError(w, 413, "snapshot_too_large")
			return
		}
	}
	req, err := http.NewRequestWithContext(r.Context(), method, h.RecordAuthorityURL+path, bytes.NewReader(body))
	if err != nil {
		agentError(w, 502, "record_authority_unavailable")
		return
	}
	// Construct fresh headers: never transmit browser identity, cookies or CSRF.
	req.Header.Set("Authorization", "Bearer "+h.recordAuthorityCredential)
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == "GET" {
		for _, v := range r.Header.Values("If-None-Match") {
			req.Header.Add("If-None-Match", v)
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		agentError(w, 502, "record_authority_unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 && response.StatusCode != http.StatusNotModified {
		agentError(w, 502, "record_authority_unavailable")
		return
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, recordset.MaxBytes+1))
	if err != nil || len(data) > recordset.MaxBytes {
		agentError(w, 502, "record_authority_unavailable")
		return
	}
	// Preserve CAS/replay status and bytes; gateway never retries or creates receipts.
	for _, name := range []string{"ETag", "SecDNS-RRset-Mutations", operatorProvenanceProfileHeader, operatorProvenanceSourceHeader, operatorProvenanceContentHeader} {
		if value := response.Header.Get(name); value != "" {
			w.Header().Set(name, value)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(response.StatusCode)
	w.Write(data)
}
