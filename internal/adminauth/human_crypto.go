package adminauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// One expensive derivation per process, with no unbounded queue or input retention.
var passwordSlot = make(chan struct{}, 1)

const phcPrefix = "$argon2id$v=19$m=65536,t=3,p=4$"

func validPassword(password, username string) bool {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 15 || utf8.RuneCountInString(password) > 256 {
		return false
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return false
		}
	}
	lower := strings.ToLower(password)
	// Local embedded denylist. No password or digest is sent to an external service.
	for _, bad := range []string{"passwordpassword", "password123456789", "123456789012345", "1234567890123456", "qwertyuiopasdfgh", "letmeinletmeinletmein", "correct horse battery staple", "secdnssecdnssecdns", "aircloudaircloudaircloud", "administratoradministrator"} {
		if lower == bad {
			return false
		}
	}
	return lower != strings.ToLower(username) && !strings.HasPrefix(lower, "secdns")
}

func derive(password string, salt []byte) ([]byte, error) {
	select {
	case passwordSlot <- struct{}{}:
	default:
		return nil, ErrUnavailable
	}
	defer func() { <-passwordSlot }()
	input := []byte(password)
	defer clear(input)
	return argon2.IDKey(input, salt, 3, 64*1024, 4, 32), nil
}
func passwordHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", ErrUnavailable
	}
	key, e := derive(password, salt)
	if e != nil {
		return "", e
	}
	defer clear(key)
	return phcPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}
func parsePHC(phc string) ([]byte, []byte, error) {
	if len(phc) > 160 || !strings.HasPrefix(phc, phcPrefix) {
		return nil, nil, ErrInvalid
	}
	p := strings.Split(strings.TrimPrefix(phc, phcPrefix), "$")
	if len(p) != 2 {
		return nil, nil, ErrInvalid
	}
	s, e := base64.RawStdEncoding.Strict().DecodeString(p[0])
	if e != nil || len(s) != 16 {
		return nil, nil, ErrInvalid
	}
	h, e := base64.RawStdEncoding.Strict().DecodeString(p[1])
	if e != nil || len(h) != 32 {
		return nil, nil, ErrInvalid
	}
	return s, h, nil
}
func passwordVerify(password, phc string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) > 256 || len(password) > 1024 {
		return ErrDenied
	}
	s, h, e := parsePHC(phc)
	if e != nil {
		return ErrUnavailable
	}
	defer clear(h)
	got, e := derive(password, s)
	if e != nil {
		return e
	}
	defer clear(got)
	if subtle.ConstantTimeCompare(got, h) != 1 {
		return ErrDenied
	}
	return nil
}
func (s *Store) seedAEAD() (cipher.AEAD, error) {
	k := s.digest("human-totp-encryption-v1")
	defer clear(k[:])
	b, e := aes.NewCipher(k[:])
	if e != nil {
		return nil, ErrUnavailable
	}
	return cipher.NewGCM(b)
}
func (s *Store) encryptSeed(seed []byte) ([]byte, error) {
	a, e := s.seedAEAD()
	if e != nil {
		return nil, e
	}
	n := make([]byte, a.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, ErrUnavailable
	}
	return a.Seal(n, n, seed, []byte(s.identity.RealmID+"\x00"+s.identity.NodeID)), nil
}
func (s *Store) decryptSeed(enc []byte) ([]byte, error) {
	a, e := s.seedAEAD()
	if e != nil || len(enc) != 12+20+16 {
		return nil, ErrUnavailable
	}
	p, e := a.Open(nil, enc[:a.NonceSize()], enc[a.NonceSize():], []byte(s.identity.RealmID+"\x00"+s.identity.NodeID))
	if e != nil {
		return nil, ErrUnavailable
	}
	return p, nil
}
func otp(seed []byte, counter int64) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(counter))
	h := hmac.New(sha1.New, seed)
	h.Write(b)
	v := h.Sum(nil)
	at := v[len(v)-1] & 15
	n := (binary.BigEndian.Uint32(v[at:at+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", n)
}
func acceptedOTP(seed []byte, code string, now, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	// Test all allowed counters before returning; choose the highest matching one.
	match := int64(-1)
	for _, n := range []int64{now/30 - 1, now / 30, now/30 + 1} {
		if n > last && n >= 0 && subtle.ConstantTimeCompare([]byte(otp(seed, n)), []byte(code)) == 1 {
			match = n
		}
	}
	return match, match >= 0
}
func newSeed() ([]byte, string, error) {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		return nil, "", ErrUnavailable
	}
	return b, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
