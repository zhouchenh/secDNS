package server

import (
	"errors"
	"regexp"
)

// Transport authority is read from root enrollment by the fixed node adapter.
// Requests contain references and policy subsets, never transport addresses.
type nodeExternalPeer struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Enabled   *bool    `json:"enabled"`
	AFIs      []int    `json:"afis"`
	Keepalive int      `json:"keepalive_seconds"`
	Hold      int      `json:"hold_seconds"`
	Exports   []string `json:"exports"`
}
type nodeExternalEnrollment struct {
	ID              string   `json:"id"`
	Address         string   `json:"address"`
	TransportFamily int      `json:"transport_family"`
	LocalSource     string   `json:"local_source"`
	LocalASN        uint32   `json:"local_asn"`
	RemoteASN       uint32   `json:"remote_asn"`
	Port            int      `json:"port"`
	AllowedAFIs     []int    `json:"allowed_afis"`
	AllowedExports  []string `json:"allowed_exports"`
}
type nodeExternalPolicy struct {
	Schema int                      `json:"schema"`
	Node   string                   `json:"node"`
	Peers  []nodeExternalEnrollment `json:"peers"`
}
type nodeExternalObservation struct {
	RuntimeVerified bool     `json:"runtime_verified"`
	ID              string   `json:"id"`
	Family          int      `json:"family"`
	State           string   `json:"state"`
	Prefixes        []string `json:"prefixes"`
	Observed        bool     `json:"observed"`
}

var externalID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var externalName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:@-]{0,95}$`)

func validateExternalPeers(peers []nodeExternalPeer) error {
	if len(peers) > 8 {
		return errors.New("external_peer_limit")
	}
	seen := map[string]bool{}
	prefixes := map[string]int{"203.0.113.53/32": 4, "203.0.113.64/32": 4, "2001:db8:53::53/128": 6, "2001:db8:53::64/128": 6}
	for _, p := range peers {
		if !externalID.MatchString(p.ID) || !externalName.MatchString(p.Name) || seen[p.ID] || p.Enabled == nil || p.Keepalive < 1 || p.Keepalive > 30 || p.Hold < 3 || p.Hold > 90 || p.Hold < 3*p.Keepalive {
			return errors.New("invalid_external_peer")
		}
		seen[p.ID] = true
		afis := map[int]bool{}
		if len(p.AFIs) < 1 || len(p.AFIs) > 2 {
			return errors.New("invalid_external_afi")
		}
		for _, f := range p.AFIs {
			if (f != 4 && f != 6) || afis[f] {
				return errors.New("invalid_external_afi")
			}
			afis[f] = true
		}
		exports := map[string]bool{}
		for _, prefix := range p.Exports {
			if !afis[prefixes[prefix]] || exports[prefix] {
				return errors.New("invalid_external_export")
			}
			exports[prefix] = true
		}
	}
	return nil
}

func authorizeExternalPeers(entries []nodeExternalPeer, policy *nodeExternalPolicy) error {
	if len(entries) == 0 {
		return nil
	}
	if policy == nil || policy.Schema != 1 {
		return errors.New("no enrollment")
	}
	for _, entry := range entries {
		var allowed *nodeExternalEnrollment
		for i := range policy.Peers {
			if policy.Peers[i].ID == entry.ID {
				allowed = &policy.Peers[i]
				break
			}
		}
		if allowed == nil {
			return errors.New("unknown enrollment")
		}
		for _, afi := range entry.AFIs {
			found := false
			for _, f := range allowed.AllowedAFIs {
				if f == afi {
					found = true
				}
			}
			if !found {
				return errors.New("AFI not enrolled")
			}
		}
		for _, prefix := range entry.Exports {
			found := false
			for _, p := range allowed.AllowedExports {
				if p == prefix {
					found = true
				}
			}
			if !found {
				return errors.New("export not enrolled")
			}
		}
	}
	return nil
}
