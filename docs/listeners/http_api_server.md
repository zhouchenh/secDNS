# httpAPIServer

* Type: `httpAPIServer`

_Available in secDNS v1.2.1 and later._

The `httpAPIServer` listener exposes an HTTP endpoint that accepts DNS questions over HTTP(S) (GET or POST, form or JSON) and returns answers encoded as JSON.

## ListenerConfigObject

```json
{
  "listen": "127.0.0.1",
  "port": 8080,
  "path": "/resolve"
}
```

> `listen`: String _(Optional)_

IP address to bind. Default: `127.0.0.1`.

> `port`: Number | String _(Optional)_

HTTP port to listen on. Accepts a number or numeric string. Default: `8080`.

> `path`: String _(Optional)_

Endpoint path. A leading slash is added if omitted. Default: `/resolve`.

## Request Parameters

Accepted via query string, form body, or JSON (`Content-Type: application/json`):

> `name`: String _(Required)_

Domain name to resolve.

> `type`: String | Number _(Optional)_

RR type (mnemonic such as `A`, `AAAA`, `MX`, or numeric). Default: `A`.

> `class`: String | Number _(Optional)_

RR class (mnemonic or numeric). Default: `IN`.

> `ecs` | `edns_client_subnet`: String _(Optional)_

CIDR to send as EDNS Client Subnet, e.g., `203.0.113.7/32` or `2001:db8::/48`.

> `raw`: Boolean _(Optional)_

(secDNS v1.3.1+) Include raw RR strings in the `data` field. Booleans parse `true`/`1`/`yes`/`on` (case-insensitive) as true; anything else is false.

Default: `false`

> `simple`: Boolean _(Optional)_

(secDNS v1.3.1+) Return a flat JSON array of answer values only. Parsed the same way as `raw`.

Default: `false`

### Request Examples

**GET**
```
GET /resolve?name=example.com&type=AAAA HTTP/1.1
Host: 127.0.0.1:8080
```

**POST form**
```
POST /resolve HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=example.com&type=TXT
```

**POST JSON**
```
POST /resolve HTTP/1.1
Content-Type: application/json

{
  "name": "example.com",
  "type": "MX",
  "ecs": "203.0.113.7/32",
  "raw": true
}
```

## Response Formats

### Standard (default)

```json
{
  "id": 12345,
  "rcode": "NOERROR",
  "question": [
    {"name": "example.com.", "type": "A", "class": "IN"}
  ],
  "answer": [
    {"name": "example.com.", "type": "A", "class": "IN", "ttl": 299, "value": "203.0.113.10"}
  ],
  "authority": [],
  "additional": []
}
```

`value` is parsed when possible (e.g., IP for A/AAAA, target for CNAME/NS, preference/host for MX). When `raw` is false and a record has no parsed value, the raw RR string is supplied in `data` for that record.

### Raw (`raw=1`)

Adds raw RR strings in `data`:

```json
{
  "id": 12345,
  "rcode": "NOERROR",
  "question": [
    {"name": "example.com.", "type": "A", "class": "IN"}
  ],
  "answer": [
    {
      "name": "example.com.",
      "type": "A",
      "class": "IN",
      "ttl": 299,
      "value": "203.0.113.10",
      "data": "example.com.\t299\tIN\tA\t203.0.113.10"
    }
  ],
  "authority": [],
  "additional": []
}
```

### Simple (`simple=1`)

Returns a flat array of answer values filtered to the queried type (A/AAAA as IPs, others fall back to RR strings):

```json
[
  "2001:db8::1234"
]
```

### Errors

Errors return an HTTP status (e.g., 400/502) and a JSON body:

```json
{"error": "listeners/http: missing name parameter"}
```
