package server

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validationServer(t *testing.T, durable bool) (*HTTPAdminServer, string) {
	t.Helper()
	var s *recordstore.Store
	path := ""
	if durable {
		dir := t.TempDir()
		os.Chmod(dir, 0700)
		path = filepath.Join(dir, "db")
		var e error
		s, e = recordstore.OpenSQLite(path)
		if e != nil {
			t.Fatal(e)
		}
	} else {
		s = recordstore.New()
	}
	t.Cleanup(func() { s.Close() })
	return &HTTPAdminServer{Token: testToken, store: s}, path
}
func postRecord(h *HTTPAdminServer, body string) int {
	return do(h, http.MethodPost, "/admin/records", testToken, body).Code
}
func TestAdminValidationBothBackends(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprint(durable), func(t *testing.T) {
			h, path := validationServer(t, durable)
			good := `{"name":"host.example.","type":"A","values":["192.0.2.1"],"ttl_seconds":300}`
			if postRecord(h, good) != 200 {
				t.Fatal("setup")
			}
			before, _ := h.store.Get("host.example.", dns.TypeA)
			for _, body := range []string{
				`{"name":"bad name.example.","type":"A","values":["192.0.2.1"]}`,
				`{"name":"host.example.","type":"AAAA","values":["192.0.2.1"]}`,
				`{"name":"host.example.","type":"MX","values":["mail.example."]}`,
				`{"name":"host.example.","type":"TXT","values":[]}`, `{"name":"host.example.","type":"TXT","values":[null]}`,
				`{"name":"host.example.","type":"CNAME","values":["a.example.","b.example."]}`,
				`{"name":"host.example.","type":"CNAME","values":["bad..example."]}`,

				`{"name":"host.example.","type":"TXT","values":["` + strings.Repeat("x", 256) + `"]}`,
				`{"name":"host.example.","type":"A","values":["192.0.2.2"],"ttl_seconds":-1}`,
				`{"name":"host.example.","type":"A","values":["192.0.2.2"],"ttl_seconds":4294967296}`,
				good + ` {}`, `[]`,
				`{"name":"host.example.","Name":"other.example.","type":"A","values":["192.0.2.1"]}`,
				`{"name":"host.example.","type":"A","values":["192.0.2.1"],"expires_at":null,"EXPIRES_AT":null}`, good[:len(good)-1] + `,"name":"other.example."}`,
			} {
				if code := postRecord(h, body); code != 400 {
					t.Fatalf("invalid body status=%d", code)
				}
				after, _ := h.store.Get("host.example.", dns.TypeA)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("failed write changed state")
				}
			}
			if postRecord(h, `{"name":"host.example.","type":"CNAME","values":["target.example."]}`) != 409 {
				t.Fatal("expected conflict")
			}
			if postRecord(h, `{"name":"txt.example.","type":"TXT","values":[""]}`) != 200 {
				t.Fatal("empty TXT string is valid")
			}
			if path != "" {
				h.store.Close()
				s, e := recordstore.OpenSQLite(path)
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close()
				got, _ := s.Get("host.example.", dns.TypeA)
				if !reflect.DeepEqual(before, got) {
					t.Fatal("failed write changed disk")
				}
			}
		})
	}
}
func TestAdminExactExpiryRoundTrip(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprint(durable), func(t *testing.T) {
			h, path := validationServer(t, durable)
			expiry := time.Now().UTC().Truncate(time.Second).Add(time.Hour + 123456789*time.Nanosecond)
			offset := expiry.In(time.FixedZone("offset", 8*3600)).Format(time.RFC3339Nano)
			body := fmt.Sprintf(`{"name":"host.example.","type":"A","values":["192.0.2.1"],"ttl_seconds":300,"expires_at":%q}`, offset)
			if postRecord(h, body) != 200 {
				t.Fatal("absolute write")
			}
			res := do(h, http.MethodGet, "/admin/records", testToken, "")
			var out struct {
				Records []recordJSON `json:"records"`
			}
			if e := json.Unmarshal(res.Body.Bytes(), &out); e != nil || len(out.Records) != 1 {
				t.Fatal("list")
			}
			if out.Records[0].ExpiresAt != expiry.Format(time.RFC3339Nano) {
				t.Fatal("precision/UTC lost")
			}
			echo, _ := json.Marshal(out.Records[0])
			if postRecord(h, string(echo)) != 200 {
				t.Fatal("exact echo failed")
			}
			got, _ := h.store.Get("host.example.", dns.TypeA)
			if !got.ExpiresAt.Equal(expiry) || got.TTL != 300 {
				t.Fatal("echo extended expiry")
			}
			if path != "" {
				h.store.Close()
				s, e := recordstore.OpenSQLite(path)
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close()
				got, _ = s.Get("host.example.", dns.TypeA)
				if !got.ExpiresAt.Equal(expiry) {
					t.Fatal("restart lost precision")
				}
			}
		})
	}
}
func TestAdminExpiryModesAndInvalidInputs(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprint(durable), func(t *testing.T) {
			h, _ := validationServer(t, durable)
			prefix := `{"name":"host.example.","type":"A","values":["192.0.2.1"]`
			for _, tail := range []string{`}`, `,"expires_at":null}`, `,"expires_at":""}`, `,"expires_in_seconds":null}`, `,"expires_in_seconds":0}`} {
				if postRecord(h, prefix+tail) != 200 {
					t.Fatal("permanence compatibility")
				}
				r, _ := h.store.Get("host.example.", dns.TypeA)
				if !r.ExpiresAt.IsZero() || r.TTL != 60 {
					t.Fatal("legacy defaults changed")
				}
			}
			before, _ := h.store.Get("host.example.", dns.TypeA)
			for _, tail := range []string{`,"expires_at":null,"expires_in_seconds":null}`,
				`,"EXPIRES_AT":null,"expires_in_seconds":0}`,
				`,"expires_at":null,"EXPIRES_IN_SECONDS":0}`, `,"expires_at":"","expires_in_seconds":0}`, `,"expires_at":"not-a-time"}`, `,"expires_at":7}`, `,"expires_at":"0001-01-01T00:00:00Z"}`, `,"expires_at":"2000-01-01T00:00:00Z"}`, `,"expires_at":"9999-12-31T23:59:59-23:00"}`, `,"expires_in_seconds":-1}`, `,"expires_in_seconds":9223372036854775807}`} {
				if code := postRecord(h, prefix+tail); code != 400 {
					t.Fatalf("bad expiry accepted: %d", code)
				}
				after, _ := h.store.Get("host.example.", dns.TypeA)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("bad expiry changed state")
				}
			}
			if postRecord(h, prefix+`,"expires_in_seconds":1800}`) != 200 {
				t.Fatal("relative expiry")
			}
			r, _ := h.store.Get("host.example.", dns.TypeA)
			if r.ExpiresAt.Before(time.Now().Add(1790 * time.Second)) {
				t.Fatal("relative expiry semantics")
			}
		})
	}
}

func TestAdminCanonicalStoredValues(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprint(durable), func(t *testing.T) {
			h, _ := validationServer(t, durable)
			for _, tc := range []struct {
				body, name string
				typ        uint16
				value      string
			}{
				{`{"NAME":" Alias.Example ","TYPE":"cname","VALUES":[" Target.Example "]}`, "alias.example.", dns.TypeCNAME, "target.example."},
				{`{"name":"V6.Example","type":"AAAA","values":[" 2001:0DB8:0:0::1 "]}`, "v6.example.", dns.TypeAAAA, "2001:db8::1"},
				{`{"name":"Txt.Example","type":"TXT","values":[" Keep Case "]}`, "txt.example.", dns.TypeTXT, " Keep Case "},
			} {
				if code := postRecord(h, tc.body); code != 200 {
					t.Fatalf("normalization failed %d", code)
				}
				r, ok := h.store.Get(tc.name, tc.typ)
				if !ok || r.Name != tc.name || r.Values[0] != tc.value {
					t.Fatal("stored representation not normalized")
				}
			}
		})
	}
}
func TestAdminDecoderErrorsDoNotEchoInput(t *testing.T) {
	h, _ := validationServer(t, false)
	r := do(h, http.MethodPost, "/admin/records", testToken, `{"ttl_seconds":987654321098765432109876543210}`)
	if r.Code != 400 || strings.Contains(r.Body.String(), "987654") {
		t.Fatal("decoder error reflected input")
	}
}

func TestAdminConcurrentConflict(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprint(durable), func(t *testing.T) {
			h, _ := validationServer(t, durable)
			start := make(chan struct{})
			codes := make(chan int, 2)
			for _, body := range []string{`{"name":"host.example.","type":"A","values":["192.0.2.1"]}`, `{"name":"host.example.","type":"CNAME","values":["target.example."]}`} {
				go func(body string) { <-start; codes <- postRecord(h, body) }(body)
			}
			close(start)
			first, second := <-codes, <-codes
			if !((first == 200 && second == 409) || (first == 409 && second == 200)) {
				t.Fatalf("concurrent statuses=%d,%d", first, second)
			}
			if len(h.store.RecordsForName("host.example.")) != 1 {
				t.Fatal("mixed CNAME owner")
			}
		})
	}
}

func TestAdminUnknownFieldsRemainIgnored(t *testing.T) {
	h, _ := validationServer(t, false)
	if postRecord(h, `{"name":"host.example.","type":"TXT","values":["ok"],"unknown":1,"unknown":2}`) != 200 {
		t.Fatal("unknown field compatibility changed")
	}
}
