package config

import (
	"encoding/json"
	"errors"
	admin "github.com/zhouchenh/secDNS/internal/listeners/servers/http/admin/server"
	"github.com/zhouchenh/secDNS/internal/snapshotfollower"
)

var errFollowerStatus = errors.New("config: invalid local follower status binding")

type followerStatusBinding struct {
	server *admin.HTTPAdminServer
	names  []string
}

// The allowlist belongs to the listener, not to request parameters. This parser
// is syntax-only and does not open stores or contact authorities.
func parseFollowerStatusBindings(raw []byte, c *Config) ([]followerStatusBinding, error) {
	root, e := authObject(raw, map[string]bool{"listeners": true})
	if e != nil {
		return nil, e
	}
	var listeners []json.RawMessage
	if json.Unmarshal(root["listeners"], &listeners) != nil {
		return nil, errFollowerStatus
	}
	var followers map[string]json.RawMessage
	if v, ok := root["followerRecordStores"]; ok && json.Unmarshal(v, &followers) != nil {
		return nil, errFollowerStatus
	}
	var result []followerStatusBinding
	for index, rawListener := range listeners {
		fields, e := authObject(rawListener, map[string]bool{"followerStatusStores": true})
		if e != nil {
			return nil, errFollowerStatus
		}
		v, present := fields["followerStatusStores"]
		if !present {
			continue
		}
		var names []string
		if json.Unmarshal(v, &names) != nil || len(names) < 1 || len(names) > 64 || index >= len(c.Listeners) {
			return nil, errFollowerStatus
		}
		h, ok := c.Listeners[index].(*admin.HTTPAdminServer)
		if !ok {
			return nil, errFollowerStatus
		}
		seen := map[string]bool{}
		for _, name := range names {
			if _, ok := followers[name]; !ok || seen[name] {
				return nil, errFollowerStatus
			}
			seen[name] = true
		}
		h.ConfigureFollowerStatus(names)
		result = append(result, followerStatusBinding{h, append([]string(nil), names...)})
	}
	return result, nil
}

// BindFollowerStatus runs once before any listener or worker starts. Resolve all
// names first so a failed startup cannot publish partial status bindings.
func (i *authInstance) BindFollowerStatus(workers map[string]*snapshotfollower.Worker) error {
	for _, b := range i.followerStatus {
		for _, name := range b.names {
			if workers[name] == nil {
				return errFollowerStatus
			}
		}
	}
	for _, b := range i.followerStatus {
		readers := make(map[string]func() snapshotfollower.Status, len(b.names))
		for _, name := range b.names {
			readers[name] = workers[name].Status
		}
		if e := b.server.BindFollowerStatus(readers); e != nil {
			return errFollowerStatus
		}
	}
	return nil
}
