package doh

type UnknownHostError string

func (e UnknownHostError) Error() string {
	return "upstream/resolvers/doh: Cannot resolve " + string(e)
}
