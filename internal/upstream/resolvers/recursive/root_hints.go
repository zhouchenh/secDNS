package recursive

import "net"

// RootServer defines a single root nameserver endpoint.
type RootServer struct {
	Host      string
	Addresses []net.IP
}

// defaultRootHints returns the built-in IANA root server set (A–M) with IPv4/IPv6 addresses.
func defaultRootHints() []RootServer {
	return []RootServer{
		{
			Host: "a.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("198.41.0.4"),
				net.ParseIP("2001:503:ba3e::2:30"),
			},
		},
		{
			Host: "b.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("170.247.170.2"),
				net.ParseIP("2801:1b8:10::b"),
			},
		},
		{
			Host: "c.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("192.33.4.12"),
				net.ParseIP("2001:500:2::c"),
			},
		},
		{
			Host: "d.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("199.7.91.13"),
				net.ParseIP("2001:500:2d::d"),
			},
		},
		{
			Host: "e.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("192.203.230.10"),
				net.ParseIP("2001:500:a8::e"),
			},
		},
		{
			Host: "f.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("192.5.5.241"),
				net.ParseIP("2001:500:2f::f"),
			},
		},
		{
			Host: "g.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("192.112.36.4"),
				net.ParseIP("2001:500:12::d0d"),
			},
		},
		{
			Host: "h.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("198.97.190.53"),
				net.ParseIP("2001:500:1::53"),
			},
		},
		{
			Host: "i.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("192.36.148.17"),
				net.ParseIP("2001:7fe::53"),
			},
		},
		{
			Host: "j.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("192.58.128.30"),
				net.ParseIP("2001:503:c27::2:30"),
			},
		},
		{
			Host: "k.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("193.0.14.129"),
				net.ParseIP("2001:7fd::1"),
			},
		},
		{
			Host: "l.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("199.7.83.42"),
				net.ParseIP("2001:500:9f::42"),
			},
		},
		{
			Host: "m.root-servers.net",
			Addresses: []net.IP{
				net.ParseIP("202.12.27.33"),
				net.ParseIP("2001:dc3::35"),
			},
		},
	}
}
