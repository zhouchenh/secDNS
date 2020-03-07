package core

import "errors"

var (
	ErrNilErrorMsgHandler = NilPointerError("error message handler")
	ErrNilDefaultResolver = NilPointerError("default resolver")
	ErrInvalidDomainName  = errors.New("core: Invalid domain name")
)

type NilPointerError string

func (e NilPointerError) Error() string {
	return "core: Nil " + string(e)
}
