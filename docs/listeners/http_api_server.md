# httpAPIServer

_Available in secDNS v1.2.1 and later._  
Raw/simple response options available in secDNS v1.3.1+.

* Type: `httpAPIServer`

The `httpAPIServer` listener exposes an HTTP endpoint that accepts DNS queries via HTTP GET or POST and returns JSON-formatted DNS responses. This is useful for integrating secDNS with web applications, monitoring systems, or custom tooling without speaking the DNS wire protocol.

## ListenerConfigObject

```json
{
  "type": "httpAPIServer",
  "config": {
    "listen": "127.0.0.1",
    "port": 8080,
    "path": "/resolve"
  }
}
```

> `listen`: String

IP address to bind. Defaults to `127.0.0.1`.

> `port`: Number | String _(Optional)_

HTTP listen port. Defaults to `8080`.

> `path`: String _(Optional)_

URL path for the resolve endpoint. Defaults to `/resolve`. A leading `/` is added automatically if omitted.

## Request Format

Two simple parameters are supported:

* `name` – domain name to resolve (required)
* `type` – DNS record type (optional, default `A`). Accepts standard mnemonics (A, AAAA, TXT, …) or numeric values.
* `class` – DNS class (optional, default `IN`)
* `ecs` / `edns_client_subnet` – Optional EDNS Client Subnet in CIDR (e.g., `203.0.113.7/32`, `2001:db8::/48`). Adds an
  ECS option to the DNS query.
* `raw` – Optional (`true`/`1`/`yes`). When set, include raw RR strings in the response `data` field. Default: omitted
  (v1.3.1+).
* `simple` – Optional (`true`/`1`/`yes`). When set, return a compact JSON array of answer values only; A/AAAA as IPs,
  other types fall back to RR strings. Default: false (v1.3.1+).

### GET Example

```
GET /resolve?name=example.com&type=AAAA HTTP/1.1
Host: 127.0.0.1:8080
```

### POST (form) Example

```
POST /resolve HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=example.com&type=TXT
```

### POST (JSON) Example

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

JSON bodies are used whenever the request `Content-Type` includes `application/json`; otherwise form values are parsed.

### Simple Response Example

```
GET /resolve?name=example.com&type=AAAA&simple=1 HTTP/1.1
Host: 127.0.0.1:8080
```

Response:
```json
[
  "2606:2800:220:1:248:1893:25c8:1946"
]
```

> Simple mode returns a flat array. For A/AAAA answers it lists the IPs; for other record types it falls back to the RR string (e.g., MX preference/host, CNAME target).

## Response Format

Successful responses are returned as JSON with question and answer sections mirroring the DNS message structure:

```json
{
  "id": 12345,
  "rcode": "NOERROR",
  "question": [
    {"name": "example.com.", "type": "A", "class": "IN"}
  ],
  "answer": [
    {"name": "example.com.", "type": "A", "class": "IN", "ttl": 299, "value": "93.184.216.34"}
  ],
  "authority": [],
  "additional": []
}
```

Errors are reported with an HTTP status code (e.g., `400 Bad Request`) and a JSON payload:

```json
{"error": "listeners/http: missing name parameter"}
```

## Notes

* The listener translates each HTTP request into a standard DNS query using recursion desired.
* Responses include both structured fields and a `data` string representation of each RR for convenience.
* `cacheControlEnabled` in the cache resolver pairs well with this listener when upstream services need HTTP-friendly DNS answers.
