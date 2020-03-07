package server

var ErrNilHandler = NilPointerError("handler")

type NilPointerError string

func (e NilPointerError) Error() string {
	return "listeners/servers/dns/server: Nil " + string(e)
}
