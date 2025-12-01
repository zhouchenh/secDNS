# httpAPIServer

_Available in secDNS v1.2.1 and later._  
Raw/simple response options are available in secDNS v1.3.1+.

* Type: `httpAPIServer`

The `httpAPIServer` listener exposes an HTTP endpoint (GET/POST) to resolve DNS names and return JSON.

## Config

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

* `listen`: IP to bind. Default: `127.0.0.1`.
* `port`: HTTP port. Default: `8080`.
* `path`: Endpoint path. Default: `/resolve` (leading slash added if omitted).

## Request Parameters

Accepted via query string, form body, or JSON (`Content-Type: application/json`):

* `name` (required) – Domain to resolve.
* `type` (optional) – RR type, default `A` (mnemonics or numeric).
* `class` (optional) – RR class, default `IN`.
* `ecs` / `edns_client_subnet` (optional) – CIDR to send as ECS (e.g., `203.0.113.7/32`, `2001:db8::/48`).
* `raw` (secDNS v1.3.1+) (optional) – Include raw RR strings in `data`. Default: false.
* `simple` (secDNS v1.3.1+) (optional) – Return a flat JSON array of answer values; A/AAAA as IPs, others fall back to RR strings. Default: false.

Boolean parsing for `raw` and `simple`: accepts `true`/`1`/`yes` (case-insensitive) as true; any other value is treated as false.

### Examples

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
    {"name": "example.com.", "type": "A", "class": "IN", "ttl": 299, "value": "93.184.216.34"}
  ],
  "authority": [],
  "additional": []
}
```

* `value` is a parsed field (e.g., IP for A/AAAA, target for CNAME/NS, preference/host for MX).
* `data` is only present when `raw=true` (example: `{"name":"example.com.","type":"A",...,"value":"93.184.216.34","data":"example.com.\t299\tIN\tA\t93.184.216.34"}`).

### Raw (`raw=1`)
Same as standard but includes raw RR strings in `data`:
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
      "value": "93.184.216.34",
      "data": "example.com.\t299\tIN\tA\t93.184.216.34"
    }
  ],
  "authority": [],
  "additional": []
}
```

### Simple (`simple=1`)
Flat JSON array of the answer values:
```json
[
  "2606:2800:220:1:248:1893:25c8:1946"
]
```
For non-A/AAAA answers, entries fall back to RR strings.

### Errors

Errors return an HTTP status (e.g., 400/502) with a JSON payload:
```json
{"error": "listeners/http: missing name parameter"}
```
