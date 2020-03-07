package list

import "errors"

var (
	ErrNilNameServer         = NilPointerError("name server")
	ErrNoAvailableNameServer = errors.New("upstream/resolvers/concurrent/nameserver/list: No available name server")
)

type NilPointerError string

func (e NilPointerError) Error() string {
	return "upstream/resolvers/concurrent/nameserver/list: Nil " + string(e)
}
