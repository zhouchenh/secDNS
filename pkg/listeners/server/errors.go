package server

import "errors"

var (
	ErrPeerUnavailable   = errors.New("listeners/server: client peer unavailable")
	ErrResolverSelection = errors.New("listeners/server: resolver selection unavailable")
)

type NotRegistrableError string

func (e NotRegistrableError) Error() string {
	return "listeners/server: Server " + string(e) + " not registrable"
}

type AlreadyRegisteredError string

func (e AlreadyRegisteredError) Error() string {
	return "listeners/server: Server with type " + string(e) + " already registered"
}
