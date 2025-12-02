package server

import "errors"

var (
	ErrNilHandler        = errors.New("listeners/servers/http/api/server: nil handler")
	ErrMissingName       = errors.New("listeners/servers/http/api/server: missing name parameter")
	ErrUnsupportedMethod = errors.New("listeners/servers/http/api/server: unsupported method")
	errNilReply          = errors.New("listeners/servers/http/api/server: nil reply from handler")
)
