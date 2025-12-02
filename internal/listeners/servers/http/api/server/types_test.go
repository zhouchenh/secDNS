package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPAPIServerPathDefaults(t *testing.T) {
	s := &HTTPAPIServer{}
	if got := s.path(); got != "/resolve" {
		t.Fatalf("default path = %s, want /resolve", got)
	}

	s.Path = "custom"
	if got := s.path(); got != "/custom" {
		t.Fatalf("missing slash path = %s, want /custom", got)
	}

	s.Path = "/explicit"
	if got := s.path(); got != "/explicit" {
		t.Fatalf("explicit slash path = %s, want /explicit", got)
	}
}

func TestParseRequestGet(t *testing.T) {
	req := httptestRequest(http.MethodGet, "", url.Values{
		"name": {"example.com"},
		"type": {"AAAA"},
	})

	h := &HTTPAPIServer{}
	q, err := h.parseRequest(req)
	if err != nil {
		t.Fatalf("parseRequest error = %v", err)
	}
	if q.Name != "example.com" || q.qType() != dns.TypeAAAA {
		t.Fatalf("unexpected query %+v", q)
	}
}

func TestParseRequestPostForm(t *testing.T) {
	values := url.Values{
		"name":  {"example.org"},
		"type":  {"15"},
		"class": {"1"},
	}
	req := httptestRequest(http.MethodPost, values.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h := &HTTPAPIServer{}
	q, err := h.parseRequest(req)
	if err != nil {
		t.Fatalf("parseRequest error = %v", err)
	}
	if q.Name != "example.org" || q.qType() != dns.TypeMX {
		t.Fatalf("unexpected query %+v", q)
	}
}

func TestParseRequestJSON(t *testing.T) {
	body := map[string]string{
		"name":  "example.net",
		"type":  "TXT",
		"class": "CH",
	}
	data, _ := json.Marshal(body)
	req := httptestRequest(http.MethodPost, string(data), nil)
	req.Header.Set("Content-Type", "application/json")

	h := &HTTPAPIServer{}
	q, err := h.parseRequest(req)
	if err != nil {
		t.Fatalf("parseRequest error = %v", err)
	}
	if q.Name != "example.net" || q.qType() != dns.TypeTXT || q.qClass() != dns.ClassCHAOS {
		t.Fatalf("unexpected query %+v", q)
	}
}

func TestParseRequestMissingName(t *testing.T) {
	req := httptestRequest(http.MethodGet, "", url.Values{})
	h := &HTTPAPIServer{}
	_, err := h.parseRequest(req)
	if !errors.Is(err, ErrMissingName) {
		t.Fatalf("expected ErrMissingName, got %v", err)
	}
}

func TestParseRequestUnsupportedMethod(t *testing.T) {
	req := httptestRequest(http.MethodDelete, "", url.Values{"name": {"example.com"}})
	h := &HTTPAPIServer{}
	_, err := h.parseRequest(req)
	if !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("expected ErrUnsupportedMethod, got %v", err)
	}
}

func TestToHTTPResponse(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.IP{93, 184, 216, 34},
		},
	}

	resp := toHTTPResponse(msg, true)
	if resp.ID != msg.Id {
		t.Fatalf("response ID = %d, want %d", resp.ID, msg.Id)
	}
	if got := resp.Question[0].Type; got != "A" {
		t.Fatalf("question type = %s, want A", got)
	}
	if resp.Answer[0].TTL != 60 {
		t.Fatalf("answer TTL = %d, want 60", resp.Answer[0].TTL)
	}
	if !strings.Contains(resp.Answer[0].Data, "93.184.216.34") {
		t.Fatalf("answer data = %s, want IP", resp.Answer[0].Data)
	}
}

func TestHandleResolveGETRoundTrip(t *testing.T) {
	server := &HTTPAPIServer{}
	rec := httptest.NewRecorder()
	req := httptestRequest(http.MethodGet, "", url.Values{
		"name": {"example.com"},
		"type": {"TXT"},
	})

	var captured *dns.Msg
	handler := func(query *dns.Msg) *dns.Msg {
		captured = query.Copy()
		resp := new(dns.Msg)
		resp.SetQuestion(query.Question[0].Name, query.Question[0].Qtype)
		resp.Question[0].Qclass = query.Question[0].Qclass
		resp.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   query.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    120,
				},
				Txt: []string{"hello"},
			},
		}
		return resp
	}

	server.handleResolve(rec, req, handler, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if captured == nil {
		t.Fatalf("handler was not invoked")
	}
	if got := captured.Question[0]; got.Name != "example.com." || got.Qtype != dns.TypeTXT {
		t.Fatalf("unexpected query forwarded: %+v", got)
	}

	var payload messageJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response JSON decode failed: %v", err)
	}
	if len(payload.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(payload.Answer))
	}
	if payload.Answer[0].TTL != 120 || payload.Answer[0].Type != "TXT" {
		t.Fatalf("unexpected answer payload: %+v", payload.Answer[0])
	}
}

func TestHandleResolveJSONBody(t *testing.T) {
	server := &HTTPAPIServer{}
	body := map[string]string{
		"name":  "api.example",
		"type":  "AAAA",
		"class": "CH",
	}
	data, _ := json.Marshal(body)
	rawBody := string(data)
	req := httptestRequest(http.MethodPost, rawBody, nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	checkReq := httptestRequest(http.MethodPost, rawBody, nil)
	checkReq.Header.Set("Content-Type", "application/json")
	parsed, err := server.parseRequest(checkReq)
	if err != nil {
		t.Fatalf("parseRequest error = %v", err)
	}
	if parsed.qClass() != dns.ClassCHAOS {
		t.Fatalf("expected parsed class CHAOS, got %d", parsed.qClass())
	}

	server.handleResolve(rec, req, func(query *dns.Msg) *dns.Msg {
		if query.Question[0].Qclass != dns.ClassCHAOS {
			t.Fatalf("expected class CHAOS, got %d", query.Question[0].Qclass)
		}
		resp := new(dns.Msg)
		resp.SetQuestion(query.Question[0].Name, query.Question[0].Qtype)
		resp.Question[0].Qclass = query.Question[0].Qclass
		if resp.Question[0].Qclass != dns.ClassCHAOS {
			t.Fatalf("reply question class = %d", resp.Question[0].Qclass)
		}
		return resp
	}, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload messageJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response JSON decode failed: %v", err)
	}
	if got := payload.Question[0]; got.Type != "AAAA" || got.Class != "CH" {
		t.Fatalf("unexpected question payload: %+v", got)
	}
}

func TestHandleResolveFormBody(t *testing.T) {
	server := &HTTPAPIServer{}
	values := url.Values{
		"name":  {"form.example"},
		"type":  {"15"},
		"class": {"1"},
	}
	req := httptestRequest(http.MethodPost, values.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	server.handleResolve(rec, req, func(query *dns.Msg) *dns.Msg {
		if q := query.Question[0]; q.Qtype != dns.TypeMX || q.Qclass != dns.ClassINET {
			t.Fatalf("unexpected query type/class: %+v", q)
		}
		resp := new(dns.Msg)
		resp.SetQuestion(query.Question[0].Name, query.Question[0].Qtype)
		resp.Answer = []dns.RR{
			&dns.MX{
				Hdr: dns.RR_Header{
					Name:   query.Question[0].Name,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				Preference: 10,
				Mx:         "mail.form.example.",
			},
		}
		return resp
	}, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload messageJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response JSON decode failed: %v", err)
	}
	if got := payload.Question[0]; got.Type != "MX" || got.Class != "IN" {
		t.Fatalf("unexpected question payload: %+v", got)
	}
	if len(payload.Answer) != 1 || payload.Answer[0].Type != "MX" {
		t.Fatalf("unexpected answer payload: %+v", payload.Answer)
	}
}

func TestHandleResolveErrorResponses(t *testing.T) {
	server := &HTTPAPIServer{}
	rec := httptest.NewRecorder()
	req := httptestRequest(http.MethodGet, "", url.Values{})

	server.handleResolve(rec, req, func(query *dns.Msg) *dns.Msg {
		return nil
	}, nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing name status = %d, want 400", rec.Code)
	}
	var errPayload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errPayload); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if errPayload["error"] != ErrMissingName.Error() {
		t.Fatalf("unexpected error payload: %v", errPayload)
	}

	rec = httptest.NewRecorder()
	req = httptestRequest(http.MethodGet, "", url.Values{"name": {"example.com"}})

	server.handleResolve(rec, req, func(query *dns.Msg) *dns.Msg {
		return nil
	}, nil)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("nil reply status = %d, want 502", rec.Code)
	}
	errPayload = map[string]string{}
	if err := json.Unmarshal(rec.Body.Bytes(), &errPayload); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if errPayload["error"] != errNilReply.Error() {
		t.Fatalf("unexpected error payload: %v", errPayload)
	}
}

func TestToSimpleResponseEmpty(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	out := toSimpleResponse(msg)
	if out == nil || len(out) != 0 {
		t.Fatalf("expected empty slice, got %#v", out)
	}
}

func httptestRequest(method, body string, query url.Values) *http.Request {
	urlStr := "http://example" + "/resolve"
	if query != nil {
		urlStr += "?" + query.Encode()
	}
	req, _ := http.NewRequest(method, urlStr, bytes.NewBufferString(body))
	return req
}
