package doh

import "errors"

var ErrResolverNotReady = errors.New("upstream/resolvers/doh: Resolver not ready")

type UnknownHostError string

func (e UnknownHostError) Error() string {
	return "upstream/resolvers/doh: Cannot resolve " + string(e)
}
