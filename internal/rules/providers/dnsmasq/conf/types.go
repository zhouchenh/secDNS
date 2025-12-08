package conf

import (
	"bufio"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/core"
	"github.com/zhouchenh/secDNS/pkg/rules/provider"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"strings"
)

type DnsmasqConf struct {
	FilePath string
	Resolver resolver.Resolver
	entries  []string
	index    int
}

var typeOfDnsmasqConf = descriptor.TypeOfNew(new(*DnsmasqConf))

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
	if d.Resolver == nil {
		if canReceiveError {
			receiveError(NilResolverError(d.FilePath))
		}
		return false
	}
	if !d.ensureEntries(canReceiveError, receiveError) {
		return false
	}
	if d.index >= len(d.entries) {
		return false
	}
	receive(d.entries[d.index], d.Resolver)
	d.index++
	return d.index < len(d.entries)
}

// Reset makes the provider reusable from the start of the file.
func (d *DnsmasqConf) Reset() {
	d.index = 0
}

func (d *DnsmasqConf) ensureEntries(canReceiveError bool, receiveError func(err error)) bool {
	if d.entries != nil {
		return len(d.entries) > 0
	}
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
	defer func() { _ = file.Close() }()

	var entries []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "/")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		if strings.ContainsAny(name, " \t") || !common.IsDomainName(name) {
			if canReceiveError {
				receiveError(InvalidDomainNameError(name))
			}
			continue
		}
		canonical := common.CanonicalName(name)
		if canonical == "" {
			if canReceiveError {
				receiveError(InvalidDomainNameError(name))
			}
			continue
		}
		entries = append(entries, canonical)
	}
	if err := scanner.Err(); err != nil {
		if canReceiveError {
			receiveError(ReadFileError{
				filePath: d.FilePath,
				err:      err,
			})
		}
	}
	if len(entries) == 0 {
		return false
	}
	d.entries = entries
	d.index = 0
	return true
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
