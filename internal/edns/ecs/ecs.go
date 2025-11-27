package ecs

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strconv"
	"strings"
)

// Mode represents the ECS (EDNS Client Subnet) handling mode
type Mode string

const (
	// ModePassthrough does not modify ECS options in queries (default)
	ModePassthrough Mode = "passthrough"
	// ModeAdd adds ECS if the client didn't send one
	ModeAdd Mode = "add"
	// ModeOverride always replaces ECS with the configured value
	ModeOverride Mode = "override"
)

// Config holds the ECS configuration
type Config struct {
	Mode         Mode
	ClientSubnet string // e.g., "192.168.1.0/24" or "2001:db8::/32"
	subnet       *net.IPNet
	family       uint16
	netmask      uint8
}

// ParseConfig parses and validates an ECS configuration
func ParseConfig(mode string, clientSubnet string) (*Config, error) {
	cfg := &Config{}

	// Parse mode
	switch Mode(mode) {
	case ModePassthrough, ModeAdd, ModeOverride:
		cfg.Mode = Mode(mode)
	case "":
		cfg.Mode = ModePassthrough
	default:
		return nil, fmt.Errorf("invalid ECS mode: %s (must be 'passthrough', 'add', or 'override')", mode)
	}

	// If mode is passthrough, client subnet is not required
	if cfg.Mode == ModePassthrough {
		return cfg, nil
	}

	// Parse client subnet
	if clientSubnet == "" {
		return nil, fmt.Errorf("ecsClientSubnet is required when ecsMode is '%s'", mode)
	}

	cfg.ClientSubnet = clientSubnet

	// Parse CIDR notation
	ip, ipNet, err := net.ParseCIDR(clientSubnet)
	if err != nil {
		return nil, fmt.Errorf("invalid client subnet '%s': %v", clientSubnet, err)
	}

	cfg.subnet = ipNet

	// Determine family and netmask
	if ip.To4() != nil {
		cfg.family = 1 // IPv4
		ones, _ := ipNet.Mask.Size()
		cfg.netmask = uint8(ones)
	} else {
		cfg.family = 2 // IPv6
		ones, _ := ipNet.Mask.Size()
		cfg.netmask = uint8(ones)
	}

	return cfg, nil
}

// ApplyToQuery applies ECS configuration to a DNS query based on the configured mode
func (c *Config) ApplyToQuery(query *dns.Msg) error {
	if c == nil || c.Mode == ModePassthrough {
		return nil
	}

	// Get or create OPT record
	opt := query.IsEdns0()
	if opt == nil {
		query.SetEdns0(4096, false)
		opt = query.IsEdns0()
	}

	// Find existing ECS option
	var existingECS *dns.EDNS0_SUBNET
	ecsIndex := -1
	for i, option := range opt.Option {
		if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
			existingECS = ecs
			ecsIndex = i
			break
		}
	}

	// Determine if we should add/replace ECS
	shouldSetECS := false
	switch c.Mode {
	case ModeAdd:
		// Only add if not present
		if existingECS == nil {
			shouldSetECS = true
		}
	case ModeOverride:
		// Always replace
		shouldSetECS = true
	}

	if !shouldSetECS {
		return nil
	}

	// Create new ECS option
	newECS := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        c.family,
		SourceNetmask: c.netmask,
		SourceScope:   0,
		Address:       c.subnet.IP,
	}

	// Replace or add
	if ecsIndex >= 0 {
		opt.Option[ecsIndex] = newECS
	} else {
		opt.Option = append(opt.Option, newECS)
	}

	return nil
}

// ValidateMode checks if a mode string is valid
func ValidateMode(mode string) bool {
	if mode == "" {
		return true // Empty defaults to passthrough
	}
	m := Mode(mode)
	return m == ModePassthrough || m == ModeAdd || m == ModeOverride
}

// ParseClientSubnet parses a client subnet string in CIDR notation
// Returns IP, prefix length, and error
func ParseClientSubnet(subnet string) (net.IP, uint8, error) {
	if subnet == "" {
		return nil, 0, fmt.Errorf("subnet cannot be empty")
	}

	// Handle CIDR notation
	if strings.Contains(subnet, "/") {
		ip, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, 0, err
		}
		ones, _ := ipNet.Mask.Size()
		return ip, uint8(ones), nil
	}

	// Handle single IP (assume full prefix)
	ip := net.ParseIP(subnet)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid IP address: %s", subnet)
	}

	if ip.To4() != nil {
		return ip, 32, nil
	}
	return ip, 128, nil
}

// FormatClientSubnet formats an IP and prefix length into CIDR notation
func FormatClientSubnet(ip net.IP, prefixLen uint8) string {
	if ip == nil {
		return ""
	}
	return ip.String() + "/" + strconv.Itoa(int(prefixLen))
}
