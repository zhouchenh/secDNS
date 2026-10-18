package adminauth

import (
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

type Definition struct {
	Path        string `json:"path"`
	KeyPath     string `json:"keyPath"`
	RealmID     string `json:"realmID"`
	NodeID      string `json:"nodeID"`
	DisplayName string `json:"displayName"`
}

func (d Definition) Identity() Identity { return Identity{d.RealmID, d.NodeID, d.DisplayName} }
func (d Definition) Validate() error {
	if !d.Identity().valid() || !filepath.IsAbs(d.Path) || !filepath.IsAbs(d.KeyPath) || filepath.Clean(d.Path) != d.Path || filepath.Clean(d.KeyPath) != d.KeyPath || strings.EqualFold(d.Path, d.KeyPath) {
		return ErrInvalid
	}
	return nil
}

// ValidateOrigin validates configured identity only, never request headers.
func ValidateOrigin(origin string) error {
	if origin == "" {
		return nil
	}
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || u.RawFragment != "" || u.String() != origin || strings.ToLower(u.Host) != u.Host {
		return ErrInvalid
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return ErrInvalid
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return ErrInvalid
	}

	return nil
}
