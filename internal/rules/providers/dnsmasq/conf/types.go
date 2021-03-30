package conf

import (
	"bufio"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/core"
	"github.com/zhouchenh/secDNS/pkg/common"
	"github.com/zhouchenh/secDNS/pkg/rules/provider"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"regexp"
	"strings"
)

type DnsmasqConf struct {
	FilePath    string
	Resolver    resolver.Resolver
	fileContent []string
	index       int
}

var typeOfDnsmasqConf = descriptor.TypeOfNew(new(*DnsmasqConf))
var commentRegEx = regexp.MustCompile("#.*$")

func (d *DnsmasqConf) Type() descriptor.Type {
	return typeOfDnsmasqConf
}

func (d *DnsmasqConf) TypeName() string {
	return "dnsmasqConf"
}

func (d *DnsmasqConf) Provide(receive func(name string, r resolver.Resolver), receiveError func(err error)) (more bool) {
	if d == nil || receive == nil {
		return false
	}
	canReceiveError := receiveError != nil
	if d.fileContent == nil {
		file, err := core.OpenFile(d.FilePath)
		if err != nil {
			if canReceiveError {
				receiveError(OpenFileError{
					filePath: d.FilePath,
					err:      err,
				})
			}
			return false
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			d.fileContent = append(d.fileContent, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			if canReceiveError {
				receiveError(OpenFileError{
					filePath: d.FilePath,
					err:      err,
				})
			}
		}
		if len(d.fileContent) < 1 {
			return false
		}
	}
	for d.index < len(d.fileContent) {
		line := commentRegEx.ReplaceAllString(d.fileContent[d.index], "")
		s := strings.Split(line, "/")
		if len(s) < 2 {
			d.index++
			continue
		}
		name := s[1]
		if !common.IsDomainName(name) {
			if canReceiveError {
				receiveError(InvalidDomainNameError(name))
			}
			d.index++
			continue
		}
		receive(common.EnsureFQDN(name), d.Resolver)
		d.index++
		break
	}
	return d.index < len(d.fileContent)
}

func init() {
	if err := provider.RegisterProvider(&descriptor.Descriptor{
		Type: typeOfDnsmasqConf,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"FilePath"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath:     descriptor.Path{"filePath"},
					AssignableKind: descriptor.KindString,
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Resolver"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"resolver"},
					AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
						object, s, f := resolver.Descriptor().Describe(i)
						ok = s > 0 && f < 1
						return
					}),
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}
