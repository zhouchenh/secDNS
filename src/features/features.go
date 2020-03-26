package features

import (
	_ "config/server"
	_ "config/typed/server"

	_ "config/named/resolver"
	_ "config/resolver"
	_ "config/typed/resolver"

	_ "config/provider"
	_ "config/typed/provider"

	_ "listeners/servers/dns/server"

	_ "upstream/resolvers/address"
	_ "upstream/resolvers/alias"
	_ "upstream/resolvers/concurrent/nameserver/list"
	_ "upstream/resolvers/dns64"
	_ "upstream/resolvers/doh"
	_ "upstream/resolvers/nameserver"
	_ "upstream/resolvers/no/answer/resolver"
	_ "upstream/resolvers/not/exist/resolver"
	_ "upstream/resolvers/sequence"

	_ "rules/providers/collection"
	_ "rules/providers/dnsmasq/conf"
)
