package server

import "errors"

var (
	// ErrMissingToken makes the admin listener fail closed: it refuses to serve without a
	// configured bearer token, so the mutating API can never run unauthenticated.
	ErrMissingToken = errors.New("listeners/servers/http/admin/server: no bearer token configured; refusing to serve")

	errMissingBearer = errors.New("missing or malformed Authorization: Bearer header")
	errInvalidBearer = errors.New("invalid bearer token")
	errBadType       = errors.New("unsupported record type (allowed: TXT, A, AAAA, CNAME)")
	errBadName       = errors.New("name is not a valid DNS name")
	errEmptyValues   = errors.New("values must be a non-empty array")
	errBadIP         = errors.New("values must be valid IP addresses for an A/AAAA record")
	errBadExpiry     = errors.New("expires_in_seconds must not be negative")
)
