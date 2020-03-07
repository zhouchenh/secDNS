package server

type NotRegistrableError string

func (e NotRegistrableError) Error() string {
	return "listeners/server: Server " + string(e) + " not registrable"
}

type AlreadyRegisteredError string

func (e AlreadyRegisteredError) Error() string {
	return "listeners/server: Server with type " + string(e) + " already registered"
}
