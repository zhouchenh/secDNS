package resolver

import "errors"

var (
	ErrNilQuery             = errors.New("upstream/resolver: Nil query")
	ErrTooManyQuestions     = errors.New("upstream/resolver: Too many questions")
	ErrNotSupportedQuestion = errors.New("upstream/resolver: Not supported question")
	ErrLoopDetected         = errors.New("upstream/resolver: Possible endless loop detected")
)

type NotRegistrableError string

func (e NotRegistrableError) Error() string {
	return "upstream/resolver: Resolver " + string(e) + " not registrable"
}

type AlreadyRegisteredError string

func (e AlreadyRegisteredError) Error() string {
	return "upstream/resolver: Resolver with type " + string(e) + " already registered"
}
