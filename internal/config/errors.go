package config

import "errors"

var (
	ErrBadConfig                    = errors.New("config: Bad config")
	ErrUnexpectedBadConfig          = UnexpectedError("while loading the configuration")
	ErrMissingListenersConfig       = MissingRequiredConfigError("listeners")
	ErrMissingDefaultResolverConfig = MissingRequiredConfigError("default resolver")
)

type UnexpectedError string

func (e UnexpectedError) Error() string {
	return "config: An unexpected error occurred " + string(e)
}

type MissingRequiredConfigError string

func (e MissingRequiredConfigError) Error() string {
	return "config: Missing required config for " + string(e)
}

type UnsupportedConfigTypeError string

func (e UnsupportedConfigTypeError) Error() string {
	return "config: Type of config for " + string(e) + " not supported"
}
