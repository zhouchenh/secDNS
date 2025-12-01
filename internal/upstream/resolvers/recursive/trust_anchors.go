package recursive

import "github.com/miekg/dns"

// Root trust anchors (ICANN root KSK 20326). This should be refreshed periodically; RFC 5011 handling to be added.
var rootTrustAnchorRecords = []string{
	". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU= ; key id = 20326",
}

func parseTrustAnchors() []dns.RR {
	var anchors []dns.RR
	for _, rr := range rootTrustAnchorRecords {
		if rec, err := dns.NewRR(rr); err == nil {
			anchors = append(anchors, rec)
		}
	}
	return anchors
}

func defaultTrustAnchors() []dns.RR {
	return parseTrustAnchors()
}
