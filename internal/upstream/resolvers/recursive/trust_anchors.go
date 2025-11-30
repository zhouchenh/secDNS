package recursive

import "github.com/miekg/dns"

// Root trust anchors (ICANN root KSK 20326). This should be refreshed periodically; RFC 5011 handling to be added.
var rootTrustAnchorRecords = []string{
	". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+yD7j/3Gzdhvj1X8Gf4dg2rXZKXf3iO98Gk2r2FiLz6FzeL+F8EoS7ZISuGNzcRCjSc5MiNmi8R7S3fp+4mcuN3aIaB83s4p8R271GhqDsod3LXYy3LwWoc8= ; key id = 20326",
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
