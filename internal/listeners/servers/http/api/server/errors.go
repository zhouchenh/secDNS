package server

import "errors"

var (
	ErrNilHandler        = errors.New("listeners/http: nil handler")
	ErrMissingName       = errors.New("listeners/http: missing name parameter")
	ErrUnsupportedMethod = errors.New("listeners/http: unsupported method")
	errNilReply          = errors.New("listeners/http: nil reply from handler")
)
