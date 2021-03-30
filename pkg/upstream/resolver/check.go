package resolver

import "github.com/miekg/dns"

func QueryCheck(query *dns.Msg) error {
	if query == nil {
		return ErrNilQuery
	}
	if len(query.Question) != 1 {
		return ErrTooManyQuestions
	}
	if query.Question[0].Qclass != dns.ClassINET {
		return ErrNotSupportedQuestion
	}
	return nil
}
