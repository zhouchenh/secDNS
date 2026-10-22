package diagnostics

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"github.com/miekg/dns"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var diagnosticName = regexp.MustCompile(`^secdnshealth[0-9a-f]{24}\.1-1-1-1\.(sslip\.io|traefik\.me)\.$`)

// CorrelationToken is disabled unless a fresh 256-bit shared diagnostic salt is
// configured. It logs neither the salt nor names. Synthetic nonce names make
// repeated DNS IDs distinct; this is not unique lineage for arbitrary traffic.
func CorrelationToken(q *dns.Msg) string {
	until, err := strconv.ParseInt(os.Getenv("SECDNS_QUERY_TRACE_UNTIL"), 10, 64)
	remaining := time.Until(time.Unix(until, 0))
	if err != nil || remaining <= 0 || remaining > 180*time.Second {
		return ""
	}
	key, err := hex.DecodeString(os.Getenv("SECDNS_QUERY_TRACE_SALT"))
	if err != nil || len(key) != 32 || q == nil || len(q.Question) != 1 {
		return ""
	}
	name := strings.ToLower(dns.Fqdn(q.Question[0].Name))
	if !diagnosticName.MatchString(name) {
		return ""
	}
	h := hmac.New(sha256.New, key)
	var b [6]byte
	binary.BigEndian.PutUint16(b[0:2], q.Id)
	binary.BigEndian.PutUint16(b[2:4], q.Question[0].Qtype)
	binary.BigEndian.PutUint16(b[4:6], q.Question[0].Qclass)
	h.Write(b[:])
	h.Write([]byte(name))
	return hex.EncodeToString(h.Sum(nil))
}
