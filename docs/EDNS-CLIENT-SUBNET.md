# EDNS Client Subnet (ECS) Support

## Overview

secDNS now supports EDNS Client Subnet (ECS) as defined in [RFC 7871](https://tools.ietf.org/html/rfc7871). ECS allows DNS resolvers to include the client's subnet information in DNS queries, enabling authoritative nameservers to provide geographically optimized responses.

## Supported Resolver Types

ECS is supported on the following resolver types:
- `nameServer` - Standard DNS protocol (UDP/TCP/DoT)
- `doh` - DNS over HTTPS

## Configuration

ECS behavior is controlled by two configuration parameters:

### `ecsMode`

Specifies how ECS options should be handled in DNS queries. Valid values:

- **`passthrough`** (default): Do not modify ECS options. If the client sends an ECS option, it is passed through unchanged. If the client doesn't send an ECS option, none is added.

- **`add`**: Add an ECS option if the client didn't send one. If the client already included an ECS option, preserve it unchanged.

- **`override`**: Always replace the ECS option with the configured value, regardless of whether the client sent one.

### `ecsClientSubnet`

The client subnet to use in CIDR notation. Required when `ecsMode` is `add` or `override`.

**Examples:**
- IPv4: `"192.168.1.0/24"`, `"10.0.0.0/8"`, `"172.16.0.0/12"`
- IPv6: `"2001:db8::/32"`, `"2001:0db8:85a3::/48"`

## Configuration Examples

### Example 1: Passthrough Mode (Default)

No ECS configuration needed. The resolver will not modify any ECS options:

```json
{
  "resolvers": {
    "nameServer": {
      "Cloudflare": {
        "address": "1.1.1.1"
      }
    }
  }
}
```

### Example 2: Add ECS if Not Present

Add ECS with subnet `192.168.1.0/24` only when the client doesn't send one:

```json
{
  "resolvers": {
    "nameServer": {
      "Cloudflare-ECS": {
        "address": "1.1.1.1",
        "ecsMode": "add",
        "ecsClientSubnet": "192.168.1.0/24"
      }
    }
  }
}
```

### Example 3: Override ECS

Always replace ECS with `10.0.0.0/8`, even if the client sends a different value:

```json
{
  "resolvers": {
    "nameServer": {
      "Google-Override": {
        "address": "8.8.8.8",
        "ecsMode": "override",
        "ecsClientSubnet": "10.0.0.0/8"
      }
    }
  }
}
```

### Example 4: DoH with ECS

ECS works the same way with DNS over HTTPS:

```json
{
  "resolvers": {
    "doh": {
      "Cloudflare-DoH-ECS": {
        "url": "https://cloudflare-dns.com/dns-query",
        "ecsMode": "add",
        "ecsClientSubnet": "192.168.0.0/16"
      }
    }
  }
}
```

### Example 5: IPv6 ECS

Use an IPv6 subnet for ECS:

```json
{
  "resolvers": {
    "nameServer": {
      "Google-IPv6": {
        "address": "2001:4860:4860::8888",
        "ecsMode": "add",
        "ecsClientSubnet": "2001:db8::/32"
      }
    }
  }
}
```

## Use Cases

### Geographic Load Balancing

Many CDNs and large-scale services use ECS to direct clients to the nearest server:

```json
{
  "resolvers": {
    "nameServer": {
      "CDN-Resolver": {
        "address": "1.1.1.1",
        "ecsMode": "add",
        "ecsClientSubnet": "203.0.113.0/24"
      }
    }
  }
}
```

### Privacy Protection

Override client ECS to mask the actual client location:

```json
{
  "resolvers": {
    "nameServer": {
      "Privacy-Resolver": {
        "address": "1.1.1.1",
        "ecsMode": "override",
        "ecsClientSubnet": "0.0.0.0/0"
      }
    }
  }
}
```

### Network Policy Enforcement

Add ECS based on your internal network structure:

```json
{
  "resolvers": {
    "nameServer": {
      "Internal-Resolver": {
        "address": "192.168.1.1",
        "ecsMode": "add",
        "ecsClientSubnet": "10.0.0.0/8"
      }
    }
  }
}
```

## Technical Details

### Implementation

- ECS options are handled using the `EDNS0_SUBNET` extension from the miekg/dns library
- The implementation follows RFC 7871 specifications
- Source Scope is always set to 0 in queries (as per RFC 7871)
- Family is automatically determined from the subnet (1 for IPv4, 2 for IPv6)
- Source Netmask is derived from the CIDR prefix length

### Query Processing

1. When a query arrives, the resolver checks the ECS configuration
2. Based on `ecsMode`:
   - **passthrough**: No modification
   - **add**: If no ECS present, add the configured ECS
   - **override**: Replace any existing ECS with the configured value
3. The modified query is sent to the upstream resolver
4. The response is returned to the client unchanged

### Performance Considerations

- Query copying is only performed when ECS configuration is active and modifications are needed
- ECS processing adds minimal overhead (typically < 1ms)
- Original queries are never modified; a copy is created when changes are needed

## Troubleshooting

### ECS not being added

Check that:
1. `ecsMode` is set to `add` or `override`
2. `ecsClientSubnet` is specified in valid CIDR notation
3. The resolver type supports ECS (nameServer or doh)

### Invalid subnet errors

Ensure the subnet is in proper CIDR notation:
- Correct: `"192.168.1.0/24"`
- Incorrect: `"192.168.1.0"` (missing prefix), `"192.168.1.0/24.0"` (invalid format)

### Unexpected ECS behavior

- In `add` mode, existing client ECS is preserved
- In `override` mode, client ECS is always replaced
- In `passthrough` mode (default), no ECS modification occurs

## References

- [RFC 7871: Client Subnet in DNS Queries](https://tools.ietf.org/html/rfc7871)
- [EDNS0 (RFC 6891)](https://tools.ietf.org/html/rfc6891)
- [miekg/dns EDNS0_SUBNET documentation](https://pkg.go.dev/github.com/miekg/dns#EDNS0_SUBNET)
