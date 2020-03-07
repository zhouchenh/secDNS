package resolver

var ErrNilNameRegistry = NilPointerError("name registry")

type NilPointerError string

func (e NilPointerError) Error() string {
	return "config/named/resolver: Nil " + string(e)
}

type NotFoundError string

func (e NotFoundError) Error() string {
	return "config/named/resolver: Resolver named " + string(e) + " not found"
}

type AlreadyExistedError string

func (e AlreadyExistedError) Error() string {
	return "config/named/resolver: Resolver named " + string(e) + " already existed"
}
