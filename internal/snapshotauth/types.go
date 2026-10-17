// Package snapshotauth verifies a bounded, fixed-profile Compact JWS carrying
// one canonical exact-record snapshot. It performs no I/O or state mutation.
package snapshotauth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

const (
	Schema          = "secdns.signed-snapshot-generation.v1"
	ProtectedType   = "application/vnd.secdns.snapshot-generation.v1+jws"
	Algorithm       = "Ed25519"
	MaxCompactBytes = 6 << 20
	MaxHeaderBytes  = 1 << 10
	MaxPayloadBytes = recordset.MaxBytes + 4<<10
	MaxTrustedKeys  = 2
)

var (
	ErrLimit      = errors.New("snapshot authentication limit exceeded")
	ErrMalformed  = errors.New("malformed snapshot authentication input")
	ErrProfile    = errors.New("unsupported snapshot authentication profile")
	ErrTrust      = errors.New("snapshot authentication trust rejected")
	ErrSignature  = errors.New("snapshot signature verification failed")
	ErrEnrollment = errors.New("snapshot enrollment mismatch")
	ErrTime       = errors.New("snapshot authentication time rejected")
	ErrSnapshot   = errors.New("signed snapshot rejected")
)

// ClockStatus is closed: only ClockTrusted permits verification.
type ClockStatus uint8

const (
	ClockUnknown ClockStatus = iota
	ClockTrusted
)

// Clock is an explicit caller-supplied verification instant. Verifier never
// falls back to the process clock.
type Clock struct {
	Now    time.Time
	Status ClockStatus
}

// TimePolicy is required input. The package supplies no operational default;
// deployments must separately select finite freshness policy.
type TimePolicy struct {
	MaxTrustValidity       time.Duration
	MaxAttestationLifetime time.Duration
	FutureIssuanceSkew     time.Duration
}

// TrustedKey is authorized by inclusion in a TrustSnapshot. A revoked or
// disabled key is omitted rather than represented by a permissive flag.
type TrustedKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
}

// TrustSnapshot is already-trusted caller input. It is neither loaded nor
// updated by this package.
type TrustSnapshot struct {
	Enrollment recordstore.FollowerEnrollment
	Generation uint64
	NotBefore  time.Time
	NotAfter   time.Time
	Keys       []TrustedKey
}

// Config binds the caller's expected enrollment independently to the
// enrollment pinned by Trust.
type Config struct {
	ExpectedEnrollment recordstore.FollowerEnrollment
	Trust              TrustSnapshot
	TimePolicy         TimePolicy
}

type trustedKey struct {
	id        string
	publicKey ed25519.PublicKey
	notBefore time.Time
	notAfter  time.Time
}

// Verifier is immutable after construction and safe for concurrent use.
type Verifier struct {
	enrollment      recordstore.FollowerEnrollment
	trustGeneration uint64
	trustNotBefore  time.Time
	trustNotAfter   time.Time
	keys            []trustedKey
	policy          TimePolicy
}

// VerifiedGeneration is copy-safe evidence from one verification under the
// captured trust and clock. It is not a durable authorization capability.
type VerifiedGeneration struct {
	enrollment      recordstore.FollowerEnrollment
	metadata        recordset.Metadata
	envelope        []byte
	keyID           string
	trustGeneration uint64
	verifiedAt      time.Time
	issuedAt        time.Time
	expiresAt       time.Time
}

func (v VerifiedGeneration) Enrollment() recordstore.FollowerEnrollment { return v.enrollment }
func (v VerifiedGeneration) Metadata() recordset.Metadata               { return v.metadata }
func (v VerifiedGeneration) EnvelopeJSON() []byte                       { return append([]byte(nil), v.envelope...) }
func (v VerifiedGeneration) KeyID() string                              { return v.keyID }
func (v VerifiedGeneration) TrustGeneration() uint64                    { return v.trustGeneration }
func (v VerifiedGeneration) VerifiedAt() time.Time                      { return v.verifiedAt }
func (v VerifiedGeneration) IssuedAt() time.Time                        { return v.issuedAt }
func (v VerifiedGeneration) ExpiresAt() time.Time                       { return v.expiresAt }

// NewVerifier validates and copies all caller-owned trust material.
func NewVerifier(config Config) (*Verifier, error) {
	if !validEnrollment(config.ExpectedEnrollment) || !validEnrollment(config.Trust.Enrollment) || config.ExpectedEnrollment != config.Trust.Enrollment {
		return nil, ErrEnrollment
	}
	if config.Trust.Generation == 0 || len(config.Trust.Keys) == 0 || len(config.Trust.Keys) > MaxTrustedKeys {
		return nil, ErrTrust
	}
	if config.TimePolicy.MaxTrustValidity <= 0 || config.TimePolicy.MaxAttestationLifetime <= 0 || config.TimePolicy.FutureIssuanceSkew < 0 {
		return nil, ErrTime
	}
	trustStart, trustEnd, ok := interval(config.Trust.NotBefore, config.Trust.NotAfter)
	if !ok || !withinDuration(trustStart, trustEnd, config.TimePolicy.MaxTrustValidity) {
		return nil, ErrTime
	}

	v := &Verifier{
		enrollment:      config.ExpectedEnrollment,
		trustGeneration: config.Trust.Generation,
		trustNotBefore:  trustStart,
		trustNotAfter:   trustEnd,
		policy:          config.TimePolicy,
		keys:            make([]trustedKey, 0, len(config.Trust.Keys)),
	}
	seenIDs := make(map[string]struct{}, len(config.Trust.Keys))
	for _, input := range config.Trust.Keys {
		if !validID(input.KeyID) || len(input.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrTrust
		}
		if _, exists := seenIDs[input.KeyID]; exists {
			return nil, ErrTrust
		}
		start, end, valid := interval(input.NotBefore, input.NotAfter)
		if !valid {
			return nil, ErrTime
		}
		for _, existing := range v.keys {
			if bytes.Equal(existing.publicKey, input.PublicKey) {
				return nil, ErrTrust
			}
		}
		seenIDs[input.KeyID] = struct{}{}
		v.keys = append(v.keys, trustedKey{
			id: input.KeyID, publicKey: append(ed25519.PublicKey(nil), input.PublicKey...),
			notBefore: start, notAfter: end,
		})
	}
	return v, nil
}

func validEnrollment(e recordstore.FollowerEnrollment) bool {
	return e.Kind == recordstore.FollowerExactRecords && validID(e.ClusterID) && validID(e.RulesetID) && validID(e.LineageID) && validID(e.AuthorityEpoch)
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func interval(start, end time.Time) (time.Time, time.Time, bool) {
	start, okStart := trustedTime(start, true)
	end, okEnd := trustedTime(end, true)
	return start, end, okStart && okEnd && start.Before(end)
}

func withinDuration(start, end time.Time, maximum time.Duration) bool {
	return maximum > 0 && start.Before(end) && !end.After(start.Add(maximum))
}

func trustedTime(value time.Time, wholeSecond bool) (time.Time, bool) {
	if value.IsZero() || value.Year() < 1 || value.Year() > 9999 || wholeSecond && value.Nanosecond() != 0 {
		return time.Time{}, false
	}
	_, offset := value.Zone()
	if offset != 0 {
		return time.Time{}, false
	}
	return value.UTC(), true
}
