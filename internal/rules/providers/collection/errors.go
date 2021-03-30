package collection

type InvalidDomainNameError string

func (e InvalidDomainNameError) Error() string {
	return "rules/providers/collection: Domain name " + string(e) + " invalid"
}
