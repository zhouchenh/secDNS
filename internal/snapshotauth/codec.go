package snapshotauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var (
	errJSONSyntax  = errors.New("json syntax")
	errJSONProfile = errors.New("json profile")
)

func compactParts(compact []byte) (header, payload, signature, signingInput []byte, err error) {
	if len(compact) > MaxCompactBytes {
		return nil, nil, nil, nil, ErrLimit
	}
	first := bytes.IndexByte(compact, '.')
	if first <= 0 {
		return nil, nil, nil, nil, ErrMalformed
	}
	rest := compact[first+1:]
	secondRelative := bytes.IndexByte(rest, '.')
	if secondRelative <= 0 {
		return nil, nil, nil, nil, ErrMalformed
	}
	second := first + 1 + secondRelative
	if second == len(compact)-1 || bytes.IndexByte(compact[second+1:], '.') >= 0 {
		return nil, nil, nil, nil, ErrMalformed
	}
	header, err = decodeSegment(compact[:first], MaxHeaderBytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	payload, err = decodeSegment(compact[first+1:second], MaxPayloadBytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	signature, err = decodeSegment(compact[second+1:], 64)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(signature) != 64 {
		return nil, nil, nil, nil, ErrMalformed
	}
	return header, payload, signature, compact[:second], nil
}

func decodeSegment(segment []byte, maxDecoded int) ([]byte, error) {
	if len(segment) == 0 {
		return nil, ErrMalformed
	}
	if len(segment) > base64.RawURLEncoding.EncodedLen(maxDecoded) {
		return nil, ErrLimit
	}
	for _, c := range segment {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, ErrMalformed
		}
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(segment)))
	n, err := base64.RawURLEncoding.Strict().Decode(decoded, segment)
	if err != nil || n == 0 {
		return nil, ErrMalformed
	}
	decoded = decoded[:n]
	if len(decoded) > maxDecoded {
		return nil, ErrLimit
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(decoded)))
	base64.RawURLEncoding.Encode(encoded, decoded)
	if !bytes.Equal(encoded, segment) {
		return nil, ErrMalformed
	}
	return decoded, nil
}

func strictObject(raw []byte, required []string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) || !validUnicodeEscapes(raw) {
		return nil, errJSONSyntax
	}
	allowed := make(map[string]struct{}, len(required))
	for _, field := range required {
		allowed[field] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errJSONSyntax
	}
	fields := make(map[string]json.RawMessage, len(required))
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, errJSONSyntax
		}
		name, ok := token.(string)
		if !ok {
			return nil, errJSONSyntax
		}
		if _, ok = allowed[name]; !ok {
			return nil, errJSONProfile
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, errJSONProfile
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, errJSONSyntax
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errJSONProfile
		}
		fields[name] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return nil, errJSONSyntax
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errJSONSyntax
	}
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			return nil, errJSONProfile
		}
	}
	return fields, nil
}

// encoding/json replaces isolated UTF-16 surrogate escapes with U+FFFD. Keep
// the signed bytes distinguishable by rejecting lossy escapes before decoding.
func validUnicodeEscapes(raw []byte) bool {
	quoted := false
	hex4 := func(input []byte) (uint16, bool) {
		var value uint16
		for _, c := range input {
			value <<= 4
			switch {
			case c >= '0' && c <= '9':
				value += uint16(c - '0')
			case c >= 'a' && c <= 'f':
				value += uint16(c-'a') + 10
			case c >= 'A' && c <= 'F':
				value += uint16(c-'A') + 10
			default:
				return 0, false
			}
		}
		return value, true
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		value, ok := hex4(raw[i+1 : i+5])
		if !ok {
			return false
		}
		i += 4
		if value >= 0xDC00 && value <= 0xDFFF {
			return false
		}
		if value >= 0xD800 && value <= 0xDBFF {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, valid := hex4(raw[i+3 : i+7])
			if !valid || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}
