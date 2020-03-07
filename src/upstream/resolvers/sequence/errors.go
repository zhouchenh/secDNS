package sequence

import "errors"

var (
	ErrNilResolver         = NilPointerError("resolver")
	ErrNoAvailableResolver = errors.New("upstream/resolvers/sequence: No available resolver")
)

type NilPointerError string

func (e NilPointerError) Error() string {
	return "upstream/resolvers/sequence: Nil " + string(e)
}
