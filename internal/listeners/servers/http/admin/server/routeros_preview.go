package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/zhouchenh/secDNS/internal/importers/routeros"
)

const maxPreviewResponseBytes = 32 << 20

var errPreviewOutputLimit = errors.New("preview response limit")

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
func encodeRouterOSPreview(p *routeros.Preview, limit int) ([]byte, error) {
	if p == nil || p.CanApply || limit < 0 {
		return nil, errPreviewOutputLimit
	}
	b := &cappedPreviewBuffer{limit: limit}
	enc := json.NewEncoder(b)
	write := func(s string) error { _, err := io.WriteString(b, s); return err }
	if err := write(`{"source_sha256":`); err != nil {
		return nil, err
	}
	if err := enc.Encode(p.SourceSHA256); err != nil {
		return nil, err
	}
	if err := write(`,"entries":[`); err != nil {
		return nil, err
	}
	for i, entry := range p.Entries {
		if i > 0 {
			if err := write(","); err != nil {
				return nil, err
			}
		}
		if err := enc.Encode(entry); err != nil {
			return nil, err
		}
	}
	if err := write("]"); err != nil {
		return nil, err
	}
	if len(p.Diagnostics) > 0 {
		if err := write(`,"diagnostics":`); err != nil {
			return nil, err
		}
		if err := enc.Encode(p.Diagnostics); err != nil {
			return nil, err
		}
	}
	if err := write(",\"can_apply\":false}\n"); err != nil {
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

func (h *HTTPAdminServer) handleRouterOSPreview(w http.ResponseWriter, r *http.Request) {
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
	authenticated := h.auth(h.handleRouterOSPreview)
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
