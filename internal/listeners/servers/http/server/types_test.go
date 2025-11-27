package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPServerPathDefaults(t *testing.T) {
	s := &HTTPServer{}
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

	h := &HTTPServer{}
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

	h := &HTTPServer{}
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

	h := &HTTPServer{}
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
	h := &HTTPServer{}
	_, err := h.parseRequest(req)
	if !errors.Is(err, ErrMissingName) {
		t.Fatalf("expected ErrMissingName, got %v", err)
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

	resp := toHTTPResponse(msg)
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

func httptestRequest(method, body string, query url.Values) *http.Request {
	urlStr := "http://example" + "/resolve"
	if query != nil {
		urlStr += "?" + query.Encode()
	}
	req, _ := http.NewRequest(method, urlStr, bytes.NewBufferString(body))
	return req
}
