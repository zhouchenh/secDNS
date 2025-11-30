package ecs

import (
	"github.com/miekg/dns"
	"net"
	"testing"
)

func TestParseConfig_Passthrough(t *testing.T) {
	cfg, err := ParseConfig("passthrough", "")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if cfg.Mode != ModePassthrough {
		t.Errorf("Expected mode %s, got %s", ModePassthrough, cfg.Mode)
	}
}

func TestParseConfig_Add_IPv4(t *testing.T) {
	cfg, err := ParseConfig("add", "192.168.1.0/24")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if cfg.Mode != ModeAdd {
		t.Errorf("Expected mode %s, got %s", ModeAdd, cfg.Mode)
	}
	if cfg.family != 1 {
		t.Errorf("Expected family 1 (IPv4), got %d", cfg.family)
	}
	if cfg.netmask != 24 {
		t.Errorf("Expected netmask 24, got %d", cfg.netmask)
	}
}

func TestParseConfig_Add_IPv6(t *testing.T) {
	cfg, err := ParseConfig("add", "2001:db8::/32")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if cfg.Mode != ModeAdd {
		t.Errorf("Expected mode %s, got %s", ModeAdd, cfg.Mode)
	}
	if cfg.family != 2 {
		t.Errorf("Expected family 2 (IPv6), got %d", cfg.family)
	}
	if cfg.netmask != 32 {
		t.Errorf("Expected netmask 32, got %d", cfg.netmask)
	}
}

func TestParseConfig_Override(t *testing.T) {
	cfg, err := ParseConfig("override", "10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if cfg.Mode != ModeOverride {
		t.Errorf("Expected mode %s, got %s", ModeOverride, cfg.Mode)
	}
	if cfg.family != 1 {
		t.Errorf("Expected family 1 (IPv4), got %d", cfg.family)
	}
	if cfg.netmask != 8 {
		t.Errorf("Expected netmask 8, got %d", cfg.netmask)
	}
}

func TestParseConfig_InvalidMode(t *testing.T) {
	_, err := ParseConfig("invalid", "192.168.1.0/24")
	if err == nil {
		t.Error("Expected error for invalid mode, got nil")
	}
}

func TestParseConfig_MissingSubnet(t *testing.T) {
	_, err := ParseConfig("add", "")
	if err == nil {
		t.Error("Expected error for missing subnet in 'add' mode, got nil")
	}
}

func TestParseConfig_InvalidSubnet(t *testing.T) {
	_, err := ParseConfig("add", "not-a-subnet")
	if err == nil {
		t.Error("Expected error for invalid subnet, got nil")
	}
}

func TestApplyToQuery_Passthrough(t *testing.T) {
	cfg, _ := ParseConfig("passthrough", "")

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	err := cfg.ApplyToQuery(query)
	if err != nil {
		t.Fatalf("ApplyToQuery failed: %v", err)
	}

	// Should not add ECS in passthrough mode
	opt := query.IsEdns0()
	if opt != nil {
		for _, option := range opt.Option {
			if _, ok := option.(*dns.EDNS0_SUBNET); ok {
				t.Error("ECS should not be added in passthrough mode")
			}
		}
	}
}

func TestApplyToQuery_Add_NoExisting(t *testing.T) {
	cfg, _ := ParseConfig("add", "192.168.1.0/24")

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	err := cfg.ApplyToQuery(query)
	if err != nil {
		t.Fatalf("ApplyToQuery failed: %v", err)
	}

	// Should add ECS when not present
	opt := query.IsEdns0()
	if opt == nil {
		t.Fatal("Expected EDNS0 to be added")
	}

	found := false
	for _, option := range opt.Option {
		if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
			found = true
			if ecs.Family != 1 {
				t.Errorf("Expected family 1, got %d", ecs.Family)
			}
			if ecs.SourceNetmask != 24 {
				t.Errorf("Expected netmask 24, got %d", ecs.SourceNetmask)
			}
			expectedIP := net.ParseIP("192.168.1.0")
			if !ecs.Address.Equal(expectedIP) {
				t.Errorf("Expected IP %v, got %v", expectedIP, ecs.Address)
			}
		}
	}

	if !found {
		t.Error("ECS option not found after applying 'add' mode")
	}
}

func TestApplyToQuery_Add_ExistingPreserved(t *testing.T) {
	cfg, _ := ParseConfig("add", "192.168.1.0/24")

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.SetEdns0(4096, false)

	// Add existing ECS
	opt := query.IsEdns0()
	existingECS := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 16,
		Address:       net.ParseIP("10.0.0.0"),
	}
	opt.Option = append(opt.Option, existingECS)

	err := cfg.ApplyToQuery(query)
	if err != nil {
		t.Fatalf("ApplyToQuery failed: %v", err)
	}

	// Should NOT replace existing ECS in 'add' mode
	opt = query.IsEdns0()
	for _, option := range opt.Option {
		if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
			if ecs.SourceNetmask != 16 {
				t.Errorf("Expected existing netmask 16 to be preserved, got %d", ecs.SourceNetmask)
			}
		}
	}
}

func TestApplyToQuery_Override(t *testing.T) {
	cfg, _ := ParseConfig("override", "172.16.0.0/12")

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.SetEdns0(4096, false)

	// Add existing ECS
	opt := query.IsEdns0()
	existingECS := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 16,
		Address:       net.ParseIP("10.0.0.0"),
	}
	opt.Option = append(opt.Option, existingECS)

	err := cfg.ApplyToQuery(query)
	if err != nil {
		t.Fatalf("ApplyToQuery failed: %v", err)
	}

	// Should replace existing ECS in 'override' mode
	opt = query.IsEdns0()
	found := false
	for _, option := range opt.Option {
		if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
			found = true
			if ecs.SourceNetmask != 12 {
				t.Errorf("Expected netmask 12, got %d", ecs.SourceNetmask)
			}
			expectedIP := net.ParseIP("172.16.0.0")
			if !ecs.Address.Equal(expectedIP) {
				t.Errorf("Expected IP %v, got %v", expectedIP, ecs.Address)
			}
		}
	}

	if !found {
		t.Error("ECS option not found after applying 'override' mode")
	}
}

func TestValidateMode(t *testing.T) {
	tests := []struct {
		mode  string
		valid bool
	}{
		{"passthrough", true},
		{"add", true},
		{"override", true},
		{"strip", true},
		{"", true}, // Empty defaults to passthrough
		{"invalid", false},
		{"PASSTHROUGH", false}, // Case-sensitive
	}

	for _, tt := range tests {
		result := ValidateMode(tt.mode)
		if result != tt.valid {
			t.Errorf("ValidateMode(%q) = %v, expected %v", tt.mode, result, tt.valid)
		}
	}
}

func TestParseClientSubnet(t *testing.T) {
	tests := []struct {
		subnet         string
		expectedIP     string
		expectedPrefix uint8
		shouldError    bool
	}{
		{"192.168.1.0/24", "192.168.1.0", 24, false},
		{"10.0.0.0/8", "10.0.0.0", 8, false},
		{"2001:db8::/32", "2001:db8::", 32, false},
		{"192.168.1.1", "192.168.1.1", 32, false},
		{"2001:db8::1", "2001:db8::1", 128, false},
		{"", "", 0, true},
		{"not-an-ip", "", 0, true},
	}

	for _, tt := range tests {
		ip, prefix, err := ParseClientSubnet(tt.subnet)
		if tt.shouldError {
			if err == nil {
				t.Errorf("ParseClientSubnet(%q) expected error, got nil", tt.subnet)
			}
		} else {
			if err != nil {
				t.Errorf("ParseClientSubnet(%q) unexpected error: %v", tt.subnet, err)
				continue
			}
			expectedIP := net.ParseIP(tt.expectedIP)
			if !ip.Equal(expectedIP) {
				t.Errorf("ParseClientSubnet(%q) IP = %v, expected %v", tt.subnet, ip, expectedIP)
			}
			if prefix != tt.expectedPrefix {
				t.Errorf("ParseClientSubnet(%q) prefix = %d, expected %d", tt.subnet, prefix, tt.expectedPrefix)
			}
		}
	}
}
