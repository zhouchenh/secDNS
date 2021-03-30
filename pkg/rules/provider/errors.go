package provider

type NotRegistrableError string

func (e NotRegistrableError) Error() string {
	return "rules/provider: Provider " + string(e) + " not registrable"
}

type AlreadyRegisteredError string

func (e AlreadyRegisteredError) Error() string {
	return "rules/provider: Provider with type " + string(e) + " already registered"
}
