package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/zhouchenh/secDNS/internal/importers/routeros"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

const previewSource = "/ip dns static\r\n" +
	"add name=duplicate.invalid type=A address=192.0.2.1 ttl=0 disabled=yes match-subdomain=no comment=\"<img src=x>\"\r\n" +
	"add name=duplicate.invalid address=192.0.2.2\r\n" +
	"add regexp=\"^host\\\\.invalid\\$\" type=FWD forward-to=forward.invalid ttl=1h disabled=no match-subdomain=yes\r\n"

func previewRequest(h *HTTPAdminServer, reader io.Reader, token string, headers http.Header) *httptest.ResponseRecorder {
	return previewRequestAt(h, h.basePath()+"/import/routeros/preview", reader, token, headers)
}

func previewRequestAt(h *HTTPAdminServer, target string, reader io.Reader, token string, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", target, reader)
	r.ContentLength = -1 // Exercise the streaming bound, without trusting Content-Length.
	r.Header = headers.Clone()
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	return w
}

func previewHeaders() http.Header { return http.Header{"Content-Type": {"application/octet-stream"}} }

func TestRouterOSPreviewModesRoutesAndNoMutation(t *testing.T) {
	for _, versioned := range []bool{false, true} {
		for _, base := range []string{"/admin", "/custom/admin", "/"} {
			t.Run(base+map[bool]string{true: "versioned", false: "legacy"}[versioned], func(t *testing.T) {
				h := &HTTPAdminServer{Token: testToken, Path: base}
				if versioned {
					v, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "preview", LineageID: "test"})
					if err != nil {
						t.Fatal(err)
					}
					defer v.Close()
					h.versioned = v
				}
				if w := previewRequest(h, strings.NewReader(previewSource), testToken, previewHeaders()); w.Code != 404 {
					t.Fatal("default preview exposed", w.Code)
				}
				h.UI = true
				var before []byte
				if versioned {
					before = do(h, "GET", h.basePath()+"/snapshot", testToken, "").Body.Bytes()
				}
				// Legacy store pointer is deliberately nil: a preview cannot access it.
				w := previewRequest(h, strings.NewReader(previewSource), testToken, previewHeaders())
				if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
					t.Fatal(w.Code, w.Body.String())
				}
				want, err := routeros.Parse(strings.NewReader(previewSource))
				if err != nil {
					t.Fatal(err)
				}
				var got routeros.Preview
				if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(&got, want) || got.CanApply {
					t.Fatal("parser preview changed", err, w.Body.String())
				}
				if versioned && !bytes.Equal(before, do(h, "GET", h.basePath()+"/snapshot", testToken, "").Body.Bytes()) {
					t.Fatal("preview changed snapshot/revision")
				}
				for _, path := range []string{"/", "/app.js", "/state.js"} {
					w = do(h, "GET", h.basePath()+"/ui/import-preview"+path, "", "")
					if w.Code != 200 || w.Header().Get("Content-Security-Policy") != editorCSP || strings.Contains(w.Body.String(), testToken) {
						t.Fatal("asset/auth/header", path, w.Code)
					}
				}
				if do(h, "GET", h.basePath()+"/ui/import-preview/unknown", "", "").Code != 404 || do(h, "GET", h.basePath()+"/import/routeros/preview", testToken, "").Code != 405 {
					t.Fatal("unexpected route")
				}
			})
		}
	}
}

type previewReadSpy struct{ reads int }

func (r *previewReadSpy) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("never-reflect-this-private-read-detail")
}

func TestRouterOSPreviewAuthHeadersAndReadFailures(t *testing.T) {
	h := &HTTPAdminServer{Token: testToken, UI: true}
	for _, token := range []string{"", "wrong"} {
		for _, target := range []string{h.basePath() + "/import/routeros/preview", h.basePath() + "/import/routeros/preview?profile=exact&ruleset_id=auth.test"} {
			reader := &previewReadSpy{}
			w := previewRequestAt(h, target, reader, token, previewHeaders())
			if reader.reads != 0 || token == "" && w.Code != 401 || token != "" && w.Code != 403 {
				t.Fatal("authentication read body", target, reader.reads, w.Code)
			}
		}
	}
	for _, headers := range []http.Header{
		{}, {"Content-Type": {"application/json"}}, {"Content-Type": {"application/octet-stream; charset=utf-8"}},
		{"Content-Type": {"application/octet-stream", "application/octet-stream"}},
		{"Content-Type": {"application/octet-stream, application/octet-stream"}}, {"Content-Type": {"bad;="}},
		{"Content-Type": {"application/octet-stream"}, "Content-Encoding": {"gzip"}},
		{"Content-Type": {"application/octet-stream"}, "Content-Encoding": {""}},
		{"Content-Type": {"application/octet-stream"}, "Content-Encoding": {"identity", "identity"}},
		{"Content-Type": {"application/octet-stream"}, "Content-Encoding": {"identity, identity"}},
	} {
		reader := &previewReadSpy{}
		if w := previewRequest(h, reader, testToken, headers); w.Code != 415 || reader.reads != 0 {
			t.Fatal("media ambiguity/body read", headers, w.Code, reader.reads)
		}
	}
	headers := previewHeaders()
	headers.Set("Content-Encoding", "identity")
	if w := previewRequest(h, strings.NewReader(previewSource), testToken, headers); w.Code != 200 {
		t.Fatal("identity encoding", w.Code)
	}
	w := previewRequest(h, &previewReadSpy{}, testToken, previewHeaders())
	if w.Code != 400 || strings.Contains(w.Body.String(), "never-reflect") || !strings.Contains(w.Body.String(), "routeros_preview_read_failed") {
		t.Fatal("read failure leaked", w.Code, w.Body.String())
	}
}

func TestRouterOSPreviewLimitsAndWholeParse(t *testing.T) {
	h := &HTTPAdminServer{Token: testToken, UI: true}
	prefix := "/ip dns static\n"
	exact := prefix + strings.Repeat("\n", routeros.MaxInputBytes-len(prefix))
	if w := previewRequest(h, strings.NewReader(exact), testToken, previewHeaders()); w.Code != 200 {
		t.Fatal("exact input limit", w.Code)
	}
	if w := previewRequest(h, strings.NewReader(exact+"\n"), testToken, previewHeaders()); w.Code != 413 || strings.Contains(w.Body.String(), "entries") {
		t.Fatal("streaming oversized", w.Code)
	}
	for _, source := range []string{
		prefix + "add name=valid\nadd unknown=never-reflect-this-input", prefix + "add name=$variable",
		"\xef\xbb\xbf" + prefix, prefix + "add comment=\"\xff\"", prefix + "add comment=\"\x00\"",
		prefix + strings.Repeat("add\n", routeros.MaxEntries+1), prefix + "add comment=\"" + strings.Repeat("x", routeros.MaxValueBytes+1) + "\"",
		prefix + "#" + strings.Repeat("x", routeros.MaxLogicalLineBytes+1),
	} {
		w := previewRequest(h, strings.NewReader(source), testToken, previewHeaders())
		if w.Code != 400 || !strings.Contains(w.Body.String(), "routeros_preview_parse_error") || strings.Contains(w.Body.String(), "entries") || strings.Contains(w.Body.String(), "never-reflect-this-input") {
			t.Fatal("partial preview or unsafe diagnostic", w.Code, w.Body.String())
		}
	}
	for _, source := range []string{
		prefix + strings.Repeat("add\n", routeros.MaxEntries),
		previewSource, strings.ReplaceAll(previewSource, "\r\n", "\n"),
		prefix + "add type=A name=a.invalid address=192.0.2.1 ttl=1.5s disabled=no match-subdomain=no\nadd type=NXDOMAIN\nadd type=MX mx-exchange=mail.invalid\n",
		prefix + "add type=A name=a.invalid address=192.0.2.1 ttl=4294967296s disabled=no match-subdomain=no cname=other.invalid\n",
	} {
		want, err := routeros.Parse(strings.NewReader(source))
		if err != nil {
			t.Fatal(err)
		}
		w := previewRequest(h, strings.NewReader(source), testToken, previewHeaders())
		var got routeros.Preview
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || !reflect.DeepEqual(&got, want) {
			t.Fatal("wrapper lost parser semantics", w.Code)
		}
	}
}

func TestRouterOSPreviewOutputGuard(t *testing.T) {
	p, err := routeros.Parse(strings.NewReader(previewSource))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeRouterOSPreview(p, maxPreviewResponseBytes)
	if err != nil || !json.Valid(encoded) {
		t.Fatal(err)
	}
	if _, err := encodeRouterOSPreview(p, len(encoded)-1); !errors.Is(err, errPreviewOutputLimit) {
		t.Fatal("output budget not enforced", err)
	}
	w := httptest.NewRecorder()
	writeRouterOSPreview(w, p, 10)
	if w.Code != 503 || strings.Contains(w.Body.String(), "entries") || strings.Contains(w.Body.String(), "source_sha256") {
		t.Fatal("partial output published", w.Code, w.Body.String())
	}
	b := &cappedPreviewBuffer{limit: 5}
	_, _ = b.Write([]byte("1234"))
	if _, err := b.Write([]byte("56")); err == nil || string(b.data) != "1234" || cap(b.data) > 5 {
		t.Fatal("writer allocated/published beyond budget")
	}
	// HTML-escaping expansion and diagnostic-dense entries still return full JSON.
	source := "/ip dns static\n" + strings.Repeat("add comment=\""+strings.Repeat("<", 100)+"\"\n", 4096)
	w = previewRequest(&HTTPAdminServer{Token: testToken, UI: true}, strings.NewReader(source), testToken, previewHeaders())
	if w.Code != 200 || !json.Valid(w.Body.Bytes()) || w.Body.Len() > maxPreviewResponseBytes {
		t.Fatal("bounded expanded response", w.Code, w.Body.Len())
	}
}

const exactPreviewSource = "/ip dns static\n" +
	"add name=one.invalid type=A address=192.0.2.1 ttl=0 disabled=no match-subdomain=no comment=retained\n" +
	"add name=alias.invalid type=CNAME cname=one.invalid ttl=5m disabled=no match-subdomain=no\n"

type routerOSExactResponse struct {
	Profile       string                 `json:"profile"`
	RulesetID     string                 `json:"ruleset_id"`
	Compiled      bool                   `json:"compiled"`
	CanApply      bool                   `json:"can_apply"`
	SourceSHA256  string                 `json:"source_sha256"`
	Source        *routeros.Preview      `json:"source"`
	Blockers      []routerOSExactBlocker `json:"blockers"`
	ContentSHA256 string                 `json:"content_sha256"`
	Bindings      []routerOSExactBinding `json:"bindings"`
	Content       map[string]any         `json:"content"`
}

func TestRouterOSExactPreviewSuccessRefusalAndNoMutation(t *testing.T) {
	v, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "existing", LineageID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	h := &HTTPAdminServer{Token: testToken, UI: true, versioned: v}
	before := do(h, "GET", h.basePath()+"/snapshot", testToken, "").Body.Bytes()
	target := h.basePath() + "/import/routeros/preview?profile=exact&ruleset_id=web.test"
	w := previewRequestAt(h, target, strings.NewReader(exactPreviewSource), testToken, previewHeaders())
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || !json.Valid(w.Body.Bytes()) {
		t.Fatal("exact success", w.Code, w.Body.String())
	}
	var got routerOSExactResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	compiled, err := routeros.CompileExact(strings.NewReader(exactPreviewSource), "web.test")
	if err != nil || got.Profile != routeros.ExactProfile || got.RulesetID != "web.test" || !got.Compiled || got.CanApply || got.SourceSHA256 != compiled.Preview().SourceSHA256 || !reflect.DeepEqual(got.Source, compiled.Preview()) || got.ContentSHA256 != compiled.ContentSHA256() || len(got.Blockers) != 0 || len(got.Bindings) != 2 {
		t.Fatal("exact report mismatch", err, w.Body.String())
	}
	var wantContent map[string]any
	if err := json.Unmarshal(compiled.ContentJSON(), &wantContent); err != nil || !reflect.DeepEqual(got.Content, wantContent) || strings.Contains(w.Body.String(), "compiler-validation") || strings.Contains(w.Body.String(), "revision") || strings.Contains(w.Body.String(), "lineage") {
		t.Fatal("candidate content changed or scratch identity leaked", w.Body.String())
	}
	if !bytes.Equal(before, do(h, "GET", h.basePath()+"/snapshot", testToken, "").Body.Bytes()) {
		t.Fatal("exact preview changed snapshot")
	}

	mixed := exactPreviewSource + "add regexp=\"^blocked\" type=A address=192.0.2.2 ttl=1m disabled=no match-subdomain=no\n"
	w = previewRequestAt(h, target, strings.NewReader(mixed), testToken, previewHeaders())
	if w.Code != http.StatusUnprocessableEntity || !json.Valid(w.Body.Bytes()) {
		t.Fatal("exact refusal", w.Code, w.Body.String())
	}
	got = routerOSExactResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Compiled || got.CanApply || got.Source == nil || len(got.Source.Entries) != 3 || len(got.Blockers) != 1 || got.Blockers[0].Ordinal != 3 || got.ContentSHA256 != "" || got.Bindings != nil || got.Content != nil {
		t.Fatal("refusal exposed partial candidate", err, w.Body.String())
	}
	if !bytes.Equal(before, do(h, "GET", h.basePath()+"/snapshot", testToken, "").Body.Bytes()) {
		t.Fatal("refusal changed snapshot")
	}
}

func TestRouterOSExactPreviewAdmissionAndFailures(t *testing.T) {
	h := &HTTPAdminServer{Token: testToken, UI: true}
	for _, target := range []string{
		h.basePath() + "/import/routeros/preview?profile=exact",
		h.basePath() + "/import/routeros/preview?ruleset_id=test",
		h.basePath() + "/import/routeros/preview?profile=exact&ruleset_id=",
		h.basePath() + "/import/routeros/preview?profile=other&ruleset_id=test",
		h.basePath() + "/import/routeros/preview?profile=exact&ruleset_id=a&ruleset_id=b",
		h.basePath() + "/import/routeros/preview?profile=exact&ruleset_id=test&extra=1",
		h.basePath() + "/import/routeros/preview?profile=exact;ruleset_id=test",
	} {
		reader := &previewReadSpy{}
		w := previewRequestAt(h, target, reader, testToken, previewHeaders())
		if w.Code != http.StatusBadRequest || reader.reads != 0 || !strings.Contains(w.Body.String(), "routeros_exact_options") {
			t.Fatal("options read body", target, w.Code, reader.reads, w.Body.String())
		}
	}
	reader := &previewReadSpy{}
	w := previewRequestAt(h, h.basePath()+"/import/routeros/preview?profile=exact&ruleset_id=bad%20id", reader, testToken, previewHeaders())
	if w.Code != http.StatusBadRequest || reader.reads != 0 || !strings.Contains(w.Body.String(), "routeros_exact_config") {
		t.Fatal("config read body", w.Code, reader.reads, w.Body.String())
	}

	target := h.basePath() + "/import/routeros/preview?profile=exact&ruleset_id=test"
	for _, source := range []string{"/ip dns static\nadd unknown=private-value\n", "\xff"} {
		w = previewRequestAt(h, target, strings.NewReader(source), testToken, previewHeaders())
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "private-value") || strings.Contains(w.Body.String(), "source") {
			t.Fatal("parse failure exposed report", w.Code, w.Body.String())
		}
	}
	oversized := strings.Repeat(" ", routeros.MaxInputBytes+1)
	w = previewRequestAt(h, target, strings.NewReader(oversized), testToken, previewHeaders())
	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "routeros_preview_too_large") {
		t.Fatal("exact input limit", w.Code, w.Body.String())
	}
}

func TestRouterOSExactPreviewOutputGuard(t *testing.T) {
	c, err := routeros.CompileExact(strings.NewReader(exactPreviewSource), "web.test")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeRouterOSExact(c, "web.test", maxPreviewResponseBytes)
	if err != nil || !json.Valid(encoded) {
		t.Fatal(err)
	}
	if _, err := encodeRouterOSExact(c, "web.test", len(encoded)-1); !errors.Is(err, errPreviewOutputLimit) {
		t.Fatal("exact output budget not enforced", err)
	}
	w := httptest.NewRecorder()
	writeRouterOSExact(w, c, "web.test", http.StatusOK, 10)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "content_sha256") || strings.Contains(w.Body.String(), "source_sha256") {
		t.Fatal("partial exact output published", w.Code, w.Body.String())
	}
}
