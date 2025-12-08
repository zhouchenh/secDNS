package common

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/logger"
	"net"
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
	ErrOutput(err)
}

func Output(a ...interface{}) {
	_, _ = fmt.Fprintln(logger.Output(), a...)
}

func ErrOutput(a ...interface{}) {
	logger.Error().Msg(fmt.Sprint(a...))
}

func ParseIPv4v6(str string) (ip net.IP) {
	ip = net.ParseIP(str)
	if ip == nil {
		return
	}
	if ipv4Addr := ip.To4(); ipv4Addr != nil {
		return ipv4Addr
	}
	return
}

func IsDomainName(name string) (ok bool) {
	if hasPrefixAndSuffix(name, "\"", "\"") {
		_, ok = dns.IsDomainName(trimPrefixAndSuffix(name, "\"", "\""))
		return
	}
	_, ok = dns.IsDomainName(name)
	return
}

// CanonicalName lowercases and fqdn-normalizes a domain name, preserving literal-match quotes.
func CanonicalName(name string) string {
	if name == "" {
		return ""
	}
	if hasPrefixAndSuffix(name, "\"", "\"") {
		inner := dns.CanonicalName(trimPrefixAndSuffix(name, "\"", "\""))
		if inner == "" {
			return ""
		}
		return "\"" + ensureFQDN(inner) + "\""
	}
	canonical := dns.CanonicalName(name)
	if canonical == "" {
		return ""
	}
	return ensureFQDN(canonical)
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

func FilterResourceRecords(records []dns.RR, predicate func(rr dns.RR) bool) (result []dns.RR) {
	for _, record := range records {
		if predicate(record) {
			result = append(result, record)
		}
	}
	return
}
