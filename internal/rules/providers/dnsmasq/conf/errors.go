package conf

type InvalidDomainNameError string

func (e InvalidDomainNameError) Error() string {
	return "rules/providers/dnsmasq/conf: Domain name " + string(e) + " invalid"
}

type OpenFileError struct {
	filePath string
	err      error
}

func (e OpenFileError) Error() string {
	return "rules/providers/dnsmasq/conf: Failed to open dnsmasq conf file \"" + e.filePath + "\" " + e.err.Error()
}

type ReadFileError struct {
	filePath string
	err      error
}

func (e ReadFileError) Error() string {
	return "rules/providers/dnsmasq/conf: An error occurred while reading dnsmasq conf file \"" + e.filePath + "\" " + e.err.Error()
}

type NilResolverError string

func (e NilResolverError) Error() string {
	if e == "" {
		return "rules/providers/dnsmasq/conf: Resolver is nil"
	}
	return "rules/providers/dnsmasq/conf: Resolver is nil for file \"" + string(e) + "\""
}
