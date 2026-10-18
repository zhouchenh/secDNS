package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/zhouchenh/secDNS/internal/importers/routeros"
)

const maxPreviewResponseBytes = 32 << 20

var errPreviewOutputLimit = errors.New("preview response limit")

type routerOSExactBlocker struct {
	Ordinal        int    `json:"ordinal"`
	Line           int    `json:"line"`
	Code           string `json:"code"`
	RelatedOrdinal int    `json:"related_ordinal,omitempty"`
}

type routerOSExactBinding struct {
	Ordinal int    `json:"ordinal"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

// cappedPreviewBuffer rejects the write before growing beyond its fixed capacity.
type cappedPreviewBuffer struct {
	data  []byte
	limit int
}

func (b *cappedPreviewBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		return 0, errPreviewOutputLimit
	}
	if len(b.data)+len(p) > cap(b.data) {
		size := max(cap(b.data)*2, len(b.data)+len(p))
		if size > b.limit {
			size = b.limit
		}
		data := make([]byte, len(b.data), size)
		copy(data, b.data)
		b.data = data
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// Encode each parser-bounded entry separately. Never marshal the whole preview
// before enforcing the output budget, and never publish a partial encoded result.
func writeRouterOSPreviewJSON(w io.Writer, p *routeros.Preview) error {
	if p == nil || p.CanApply {
		return errPreviewOutputLimit
	}
	enc := json.NewEncoder(w)
	write := func(s string) error { _, err := io.WriteString(w, s); return err }
	if err := write(`{"source_sha256":`); err != nil {
		return err
	}
	if err := enc.Encode(p.SourceSHA256); err != nil {
		return err
	}
	if err := write(`,"entries":[`); err != nil {
		return err
	}
	for i, entry := range p.Entries {
		if i > 0 {
			if err := write(","); err != nil {
				return err
			}
		}
		if err := enc.Encode(entry); err != nil {
			return err
		}
	}
	if err := write("]"); err != nil {
		return err
	}
	if len(p.Diagnostics) > 0 {
		if err := write(`,"diagnostics":`); err != nil {
			return err
		}
		if err := enc.Encode(p.Diagnostics); err != nil {
			return err
		}
	}
	return write(",\"can_apply\":false}")
}

func encodeRouterOSPreview(p *routeros.Preview, limit int) ([]byte, error) {
	if p == nil || p.CanApply || limit < 0 {
		return nil, errPreviewOutputLimit
	}
	b := &cappedPreviewBuffer{limit: limit}
	if err := writeRouterOSPreviewJSON(b, p); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(b, "\n"); err != nil {
		return nil, err
	}
	return b.data, nil
}

func encodeRouterOSExact(c *routeros.ExactCompilation, rulesetID string, limit int) ([]byte, error) {
	if c == nil || c.CanApply() || c.Preview() == nil || limit < 0 {
		return nil, errPreviewOutputLimit
	}
	b := &cappedPreviewBuffer{limit: limit}
	enc := json.NewEncoder(b)
	write := func(s string) error { _, err := io.WriteString(b, s); return err }
	source := c.Preview()
	if err := write(`{"profile":`); err != nil {
		return nil, err
	}
	if err := enc.Encode(c.Profile()); err != nil {
		return nil, err
	}
	if err := write(`,"ruleset_id":`); err != nil {
		return nil, err
	}
	if err := enc.Encode(rulesetID); err != nil {
		return nil, err
	}
	if err := write(`,"compiled":` + map[bool]string{true: "true", false: "false"}[c.Compiled()] + `,"can_apply":false,"source_sha256":`); err != nil {
		return nil, err
	}
	if err := enc.Encode(source.SourceSHA256); err != nil {
		return nil, err
	}
	if err := write(`,"source":`); err != nil {
		return nil, err
	}
	if err := writeRouterOSPreviewJSON(b, source); err != nil {
		return nil, err
	}
	if blockers := c.Blockers(); len(blockers) > 0 {
		wire := make([]routerOSExactBlocker, len(blockers))
		for i, blocker := range blockers {
			wire[i] = routerOSExactBlocker{blocker.Ordinal, blocker.Line, blocker.Code, blocker.RelatedOrdinal}
		}
		if err := write(`,"blockers":`); err != nil {
			return nil, err
		}
		if err := enc.Encode(wire); err != nil {
			return nil, err
		}
	}
	if c.Compiled() {
		content := c.ContentJSON()
		if !json.Valid(content) {
			return nil, errPreviewOutputLimit
		}
		if err := write(`,"content_sha256":`); err != nil {
			return nil, err
		}
		if err := enc.Encode(c.ContentSHA256()); err != nil {
			return nil, err
		}
		bindings := c.Bindings()
		wire := make([]routerOSExactBinding, len(bindings))
		for i, binding := range bindings {
			wire[i] = routerOSExactBinding{binding.Ordinal, binding.Name, binding.Type}
		}
		if err := write(`,"bindings":`); err != nil {
			return nil, err
		}
		if err := enc.Encode(wire); err != nil {
			return nil, err
		}
		if err := write(`,"content":`); err != nil {
			return nil, err
		}
		if _, err := b.Write(content); err != nil {
			return nil, err
		}
	}
	if err := write("}\n"); err != nil {
		return nil, err
	}
	return b.data, nil
}

func writeRouterOSPreview(w http.ResponseWriter, p *routeros.Preview, limit int) {
	data, err := encodeRouterOSPreview(p, limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "routeros_preview_unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func writeRouterOSExact(w http.ResponseWriter, c *routeros.ExactCompilation, rulesetID string, status, limit int) {
	data, err := encodeRouterOSExact(c, rulesetID, limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "routeros_exact_unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func routerOSPreviewOptions(r *http.Request) (bool, string, error) {
	if r.URL.RawQuery == "" {
		return false, "", nil
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values) != 2 || len(values["profile"]) != 1 || values.Get("profile") != "exact" || len(values["ruleset_id"]) != 1 || values.Get("ruleset_id") == "" {
		return false, "", errors.New("invalid exact preview options")
	}
	return true, values.Get("ruleset_id"), nil
}

func (h *HTTPAdminServer) handleRouterOSPreview(w http.ResponseWriter, r *http.Request) {
	exact, rulesetID, optionsErr := routerOSPreviewOptions(r)
	if optionsErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "routeros_exact_options"})
		return
	}
	contentTypes := r.Header.Values("Content-Type")
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if len(contentTypes) != 1 || err != nil || media != "application/octet-stream" || len(params) != 0 {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "routeros_preview_media_type"})
		return
	}
	encodings := r.Header.Values("Content-Encoding")
	if len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "routeros_preview_encoding"})
		return
	}
	if exact {
		compilation, compileErr := routeros.CompileExact(http.MaxBytesReader(w, r.Body, routeros.MaxInputBytes+1), rulesetID)
		if compilation == nil {
			if errors.Is(compileErr, routeros.ErrExactConfig) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "routeros_exact_config"})
				return
			}
			var parse *routeros.ParseError
			if errors.As(compileErr, &parse) {
				if parse.Code == "input_limit" {
					writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "routeros_preview_too_large"})
				} else if parse.Code == "input_read_failed" {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "routeros_preview_read_failed"})
				} else {
					writeJSON(w, http.StatusBadRequest, struct {
						Error      string              `json:"error"`
						Diagnostic routeros.Diagnostic `json:"diagnostic"`
					}{"routeros_preview_parse_error", parse.Diagnostic})
				}
				return
			}
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "routeros_exact_unavailable"})
			return
		}
		switch {
		case compileErr == nil:
			writeRouterOSExact(w, compilation, rulesetID, http.StatusOK, maxPreviewResponseBytes)
		case errors.Is(compileErr, routeros.ErrNotExact), errors.Is(compileErr, routeros.ErrExactLimit):
			writeRouterOSExact(w, compilation, rulesetID, http.StatusUnprocessableEntity, maxPreviewResponseBytes)
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "routeros_exact_unavailable"})
		}
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, routeros.MaxInputBytes))
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "routeros_preview_too_large"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "routeros_preview_read_failed"})
		}
		return
	}
	p, err := routeros.Parse(bytes.NewReader(raw))
	if err != nil {
		var parse *routeros.ParseError
		if errors.As(err, &parse) {
			writeJSON(w, http.StatusBadRequest, struct {
				Error      string              `json:"error"`
				Diagnostic routeros.Diagnostic `json:"diagnostic"`
			}{"routeros_preview_parse_error", parse.Diagnostic})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "routeros_preview_unavailable"})
		}
		return
	}
	writeRouterOSPreview(w, p, maxPreviewResponseBytes)
}

func (h *HTTPAdminServer) routerOSPreviewRoutes(mux *http.ServeMux, base string) {
	authenticated := h.withScopes(h.handleRouterOSPreview, false, adminauth.RouterOSPreview)
	mux.HandleFunc("POST "+base+"/import/routeros/preview", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		authenticated(w, r)
	})
	mux.HandleFunc("GET "+base+"/ui/import-preview", func(w http.ResponseWriter, r *http.Request) {
		editorHeaders(w)
		http.Redirect(w, r, base+"/ui/import-preview/", http.StatusSeeOther)
	})
	for _, asset := range []struct{ route, file, contentType string }{
		{"/{$}", "index.html", "text/html; charset=utf-8"},
		{"/app.js", "app.js", "text/javascript; charset=utf-8"},
		{"/state.js", "state.js", "text/javascript; charset=utf-8"},
		{"/style.css", "style.css", "text/css; charset=utf-8"},
	} {
		data, err := editorAssets.ReadFile("preview_ui/" + asset.file)
		if err != nil {
			panic(err)
		}
		mux.HandleFunc("GET "+base+"/ui/import-preview"+asset.route, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", asset.contentType)
			_, _ = w.Write(data)
		})
	}
}
