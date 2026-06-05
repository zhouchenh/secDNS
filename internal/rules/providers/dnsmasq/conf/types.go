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

// maxLineBytes bounds a single config line. The default bufio.Scanner token limit is
// 64 KiB, at which a longer line aborts the entire scan (ErrTooLong) and silently
// drops every remaining entry; raise it so a long-but-valid line is tolerated, while
// still bounding per-line memory.
const maxLineBytes = 1 << 20 // 1 MiB

// maxEntries is a runaway backstop set far above any real adblock/dnsmasq list (the
// largest aggregated lists run ~1–2M entries). It bounds memory if the configured
// path points at the wrong (e.g. multi-gigabyte) file. Reaching it is reported via
// TruncatedError, not silent. It is a var only so a test can lower it.
var maxEntries = 1 << 22 // 4,194,304

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
	truncated := false
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
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
		if len(entries) >= maxEntries {
			truncated = true
			break
		}
	}
	if truncated {
		if canReceiveError {
			receiveError(TruncatedError{filePath: d.FilePath, limit: maxEntries})
		}
	} else if err := scanner.Err(); err != nil {
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
