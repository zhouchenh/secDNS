// Package adminauth implements node-local administrative identity storage.
// It is not registered with any listener or configuration constructor.
package adminauth

import (
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid     = errors.New("invalid auth input")
	ErrDenied      = errors.New("authentication denied")
	ErrUnavailable = errors.New("authentication unavailable")
	ErrExists      = errors.New("authentication store already exists")
)

type Scope string

const (
	UIView              Scope = "ui:view"
	RecordsRead         Scope = "records:read"
	RecordsWrite        Scope = "records:write"
	SnapshotEvents      Scope = "snapshot:events"
	RouterOSPreview     Scope = "routeros:preview"
	SourcePolicyExplain Scope = "source-policy:explain"
	AuditRead           Scope = "audit:read"
)

var allScopes = []Scope{UIView, RecordsRead, RecordsWrite, SnapshotEvents, RouterOSPreview, SourcePolicyExplain, AuditRead}

// Identity is immutable after creation. Authentication realms are node-local.
type Identity struct{ RealmID, NodeID, DisplayName string }

func (i Identity) valid() bool {
	return identifier(i.RealmID) && identifier(i.NodeID) && label(i.DisplayName, 128)
}
func identifier(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func label(s string, n int) bool {
	if len(s) < 1 || len(s) > n || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func scopes(in []Scope) ([]Scope, error) {
	if len(in) < 1 || len(in) > len(allScopes) {
		return nil, ErrInvalid
	}
	out := append([]Scope(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	for i, s := range out {
		known := false
		for _, allowed := range allScopes {
			if s == allowed {
				known = true
			}
		}
		if !known || (i > 0 && out[i-1] == s) {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func subset(a, b []Scope) bool {
	for _, s := range a {
		found := false
		for _, t := range b {
			if s == t {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Actor cannot be constructed by callers with authority. Copies share no mutable
// scopes with the verifier; authorization uses the private verified fields.
type Actor struct {
	id, realm, node, name string
	permissions           []Scope
}

func (a Actor) ID() string          { return a.id }
func (a Actor) RealmID() string     { return a.realm }
func (a Actor) NodeID() string      { return a.node }
func (a Actor) DisplayName() string { return a.name }
func (a Actor) Kind() string {
	if a.id == "" {
		return ""
	}
	return "agent"
}
func (a Actor) Scopes() []Scope     { return append([]Scope(nil), a.permissions...) }
func (a Actor) Allows(s Scope) bool { return a.id != "" && subset([]Scope{s}, a.permissions) }

type CredentialRequest struct {
	Name, Purpose string
	Scopes        []Scope
	ExpiresAt     time.Time
}
type Credential struct {
	ID, Name, Purpose                           string
	Scopes                                      []Scope
	CreatedAt, ExpiresAt, LastUsedAt, RevokedAt time.Time
}
type AuditEvent struct {
	Sequence             int64
	At                   time.Time
	Action, CredentialID string
}

// BootstrapEnvelope is local operator authority, not a remotely supplied actor.
// A bootstrap grant can issue exactly one credential within this fixed envelope.
type BootstrapEnvelope struct {
	Scopes              []Scope
	CredentialExpiresAt time.Time
}
