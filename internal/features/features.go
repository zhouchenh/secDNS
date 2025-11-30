package features

import (
	_ "github.com/zhouchenh/secDNS/internal/config/server"
	_ "github.com/zhouchenh/secDNS/internal/config/typed/server"

	_ "github.com/zhouchenh/secDNS/internal/config/named/resolver"
	_ "github.com/zhouchenh/secDNS/internal/config/resolver"
	_ "github.com/zhouchenh/secDNS/internal/config/typed/resolver"

	_ "github.com/zhouchenh/secDNS/internal/config/provider"
	_ "github.com/zhouchenh/secDNS/internal/config/typed/provider"

	_ "github.com/zhouchenh/secDNS/internal/listeners/servers/dns/server"
	_ "github.com/zhouchenh/secDNS/internal/listeners/servers/http/server"

	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/address"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/alias"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/concurrent/nameserver/list"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/dns64"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/doh"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/ecs"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/filter/out/a"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/filter/out/a/if/aaaa/presents"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/filter/out/aaaa"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/filter/out/aaaa/if/a/presents"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/nameserver"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/no/answer/resolver"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/not/exist/resolver"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/recursive"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/sequence"

	_ "github.com/zhouchenh/secDNS/internal/rules/providers/collection"
	_ "github.com/zhouchenh/secDNS/internal/rules/providers/dnsmasq/conf"
)
