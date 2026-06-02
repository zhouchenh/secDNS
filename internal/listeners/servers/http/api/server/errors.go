package server

import "errors"

var (
	ErrNilHandler        = errors.New("listeners/servers/http/api/server: nil handler")
	ErrMissingName       = errors.New("listeners/servers/http/api/server: missing name parameter")
	ErrNameTooLong       = errors.New("listeners/servers/http/api/server: name exceeds 255 octets")
	ErrUnsupportedMethod = errors.New("listeners/servers/http/api/server: unsupported method")
	errNilReply          = errors.New("listeners/servers/http/api/server: nil reply from handler")
)
