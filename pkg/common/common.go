package common

import (
	"fmt"
	"github.com/miekg/dns"
	"os"
	"reflect"
	"strings"
)

var ClientErrorMessageHandler = func(query *dns.Msg) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetRcode(query, dns.RcodeFormatError)
	return msg
}

var ServerErrorMessageHandler = func(query *dns.Msg) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetRcode(query, dns.RcodeServerFailure)
	return msg
}

var ErrOutputErrorHandler = func(err error) {
	ErrOutput(err.Error())
}

func Output(a ...interface{}) {
	_, _ = fmt.Fprintln(os.Stdout, a...)
}

func ErrOutput(a ...interface{}) {
	_, _ = fmt.Fprintln(os.Stderr, a...)
}

func IsDomainName(name string) (ok bool) {
	if hasPrefixAndSuffix(name, "\"", "\"") {
		_, ok = dns.IsDomainName(trimPrefixAndSuffix(name, "\"", "\""))
		return
	}
	_, ok = dns.IsDomainName(name)
	return
}

func EnsureFQDN(name string) string {
	if hasPrefixAndSuffix(name, "\"", "\"") {
		return "\"" + ensureFQDN(trimPrefixAndSuffix(name, "\"", "\"")) + "\""
	}
	return ensureFQDN(name)
}

func ensureFQDN(name string) string {
	if dns.IsFqdn(name) {
		return name
	}
	return name + "."
}

func hasPrefixAndSuffix(s, prefix, suffix string) bool {
	return strings.HasPrefix(s, prefix) && strings.HasSuffix(s, suffix)
}

func trimPrefixAndSuffix(s, prefix, suffix string) string {
	s = strings.TrimPrefix(s, prefix)
	s = strings.TrimSuffix(s, suffix)
	return s
}

func Concatenate(a ...interface{}) string {
	builder := strings.Builder{}
	for _, value := range a {
		builder.WriteString(fmt.Sprint(value))
	}
	return builder.String()
}

func SnakeCaseConcatenate(a ...interface{}) string {
	builder := strings.Builder{}
	for _, value := range a {
		str := fmt.Sprint(value)
		if str == "" {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteString("_")
		}
		builder.WriteString(str)
	}
	return builder.String()
}

func UpperString(s string) string {
	return strings.ToUpper(s)
}

func TypeString(i interface{}) string {
	if t := reflect.TypeOf(i); t != nil {
		return t.String()
	}
	return "<nil>"
}
