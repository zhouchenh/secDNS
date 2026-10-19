package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"sync"
	"time"
)

// HumanAuth holds bounded, five-minute ceremonies. Passwords and root grants
// are never retained. Pending enrollment never replaces an existing factor.
type HumanAuth struct {
	mu       sync.Mutex
	store    *Store
	sessions *Sessions
	closed   bool
	pending  map[[32]byte]*humanCeremony
}
type humanCeremony struct {
	purpose, user, name, phc, id, source string
	seed                                 []byte
	grant                                [32]byte
	epoch                                int64
	recoveryID                           int
	recoveryHash                         string
	expires                              time.Time
	attempts                             int
}
type Enrollment struct {
	Challenge string    `json:"challenge"`
	Secret    string    `json:"secret"`
	ExpiresAt time.Time `json:"expires_at"`
}
type HumanResult struct {
	Token         string
	Session       SessionInfo
	RecoveryCodes []string
}

func (Enrollment) String() string    { return "adminauth.Enrollment[redacted]" }
func (Enrollment) GoString() string  { return "adminauth.Enrollment[redacted]" }
func (HumanResult) String() string   { return "adminauth.HumanResult[redacted]" }
func (HumanResult) GoString() string { return "adminauth.HumanResult[redacted]" }

func (*HumanAuth) String() string   { return "adminauth.HumanAuth[redacted]" }
func (*HumanAuth) GoString() string { return "adminauth.HumanAuth[redacted]" }
func NewHumanAuth(s *Store, sessions *Sessions) *HumanAuth {
	return &HumanAuth{store: s, sessions: sessions, pending: map[[32]byte]*humanCeremony{}}
}
func (h *HumanAuth) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for _, p := range h.pending {
		clear(p.seed)
	}
	clear(h.pending)
}
func (h *HumanAuth) digest(value string) [32]byte {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	return h.store.digest("human-ceremony:" + value)
}
func (h *HumanAuth) add(p *humanCeremony, now time.Time) (string, error) {
	if e := h.store.mfaEligible(p.source, now); e != nil {
		return "", e
	}
	for k, v := range h.pending {
		if !now.Before(v.expires) {
			clear(v.seed)
			delete(h.pending, k)
		}
	}
	if len(h.pending) >= 32 {
		return "", ErrUnavailable
	}
	t, _, e := secret("sdnp")
	if e != nil {
		return "", e
	}
	d := h.digest(t)
	if _, ok := h.pending[d]; ok {
		return "", ErrUnavailable
	}
	p.expires = now.Add(5 * time.Minute)
	h.pending[d] = p
	return t, nil
}
func (h *HumanAuth) ceremony(token, source string, now time.Time) ([32]byte, *humanCeremony, error) {
	d := h.digest(token)
	p := h.pending[d]
	if len(token) != 102 || p == nil || p.source != source || !now.Before(p.expires) || now.Before(p.expires.Add(-5*time.Minute)) {
		return d, nil, ErrDenied
	}
	p.attempts++
	if p.attempts > 5 {
		clear(p.seed)
		delete(h.pending, d)
		return d, nil, ErrDenied
	}
	return d, p, nil
}

// BeginEnrollment requires an exact one-use local grant. Recovery always forces
// a new password and TOTP; it never reveals or discards an existing method here.
func (h *HumanAuth) BeginEnrollment(grant, user, name, password, source string, recovery bool, now time.Time) (Enrollment, error) {
	if !identifier(user) || !label(name, 128) || !validPassword(password, user) {
		return Enrollment{}, ErrDenied
	}
	if !h.mu.TryLock() {
		return Enrollment{}, ErrUnavailable
	}
	defer h.mu.Unlock()
	if h.closed {
		return Enrollment{}, ErrUnavailable
	}
	if e := h.store.rateAttempt(source, now); e != nil {
		return Enrollment{}, e
	}
	purpose := "setup"
	if recovery {
		purpose = "recover"
	}
	s := h.store
	s.mu.Lock()
	if !s.healthy() || s.version < 3 {
		s.mu.Unlock()
		return Enrollment{}, ErrUnavailable
	}
	e := s.grantSQL(s.db, grant, purpose, now)
	gd := s.digest(grant)
	s.mu.Unlock()
	if e != nil {
		return Enrollment{}, e
	}
	phc, e := passwordHash(password)
	if e != nil {
		return Enrollment{}, e
	}
	seed, encoded, e := newSeed()
	if e != nil {
		return Enrollment{}, e
	}
	p := &humanCeremony{purpose: purpose, user: user, name: name, phc: phc, seed: seed, grant: gd, source: source}
	token, e := h.add(p, now)
	if e != nil {
		clear(seed)
		return Enrollment{}, e
	}
	return Enrollment{token, encoded, p.expires}, nil
}
func (h *HumanAuth) PasswordLogin(user, password, source string, now time.Time) (string, error) {
	if !h.mu.TryLock() {
		return "", ErrUnavailable
	}
	defer h.mu.Unlock()
	if h.closed {
		return "", ErrUnavailable
	}
	if e := h.store.rateAttempt(source, now); e != nil {
		return "", e
	}
	p, e := h.checkPassword(user, password)
	if e != nil {
		return "", e
	}
	p.purpose = "login"
	p.source = source
	return h.add(p, now)
}
func (h *HumanAuth) checkPassword(user, password string) (*humanCeremony, error) {
	if len(password) > 1024 {
		return nil, ErrDenied
	}
	s := h.store
	s.mu.Lock()
	if !s.healthy() || s.version < 3 {
		s.mu.Unlock()
		return nil, ErrUnavailable
	}
	p := &humanCeremony{}
	var storedUser, phc string
	e := s.db.QueryRow("SELECT id,username,name,password,epoch FROM human WHERE singleton=1").Scan(&p.id, &storedUser, &p.name, &phc, &p.epoch)
	s.mu.Unlock()
	if e != nil && e != sql.ErrNoRows {
		return nil, ErrUnavailable
	}
	if e == sql.ErrNoRows { // Same expensive work for a nonexistent owner.
		_, err := derive(password, make([]byte, 16))
		if err != nil {
			return nil, err
		}
		return nil, ErrDenied
	}
	e = passwordVerify(password, phc)
	if e != nil {
		return nil, e
	}
	if user != storedUser {
		return nil, ErrDenied
	}
	p.user = storedUser
	p.phc = phc
	return p, nil
}

// BeginCodeRecovery proves the password and one saved recovery code. The code
// is consumed atomically only when replacement MFA is confirmed; it never gives
// a normal session or bypasses replacement enrollment.
func (h *HumanAuth) BeginCodeRecovery(user, password, code, source string, now time.Time) (Enrollment, error) {
	if len(code) != 32 {
		return Enrollment{}, ErrDenied
	}
	if !h.mu.TryLock() {
		return Enrollment{}, ErrUnavailable
	}
	defer h.mu.Unlock()
	if h.closed {
		return Enrollment{}, ErrUnavailable
	}
	if e := h.store.rateAttempt(source, now); e != nil {
		return Enrollment{}, e
	}
	p, e := h.checkPassword(user, password)
	if e != nil {
		return Enrollment{}, e
	}
	s := h.store
	s.mu.Lock()
	if !s.healthy() {
		s.mu.Unlock()
		return Enrollment{}, ErrUnavailable
	}
	rows, e := s.db.Query("SELECT id,verifier FROM recovery_codes ORDER BY id")
	if e != nil {
		s.mu.Unlock()
		return Enrollment{}, ErrUnavailable
	}
	type row struct {
		id   int
		hash string
	}
	list := []row{}
	for rows.Next() {
		var v row
		if rows.Scan(&v.id, &v.hash) != nil {
			rows.Close()
			s.mu.Unlock()
			return Enrollment{}, ErrUnavailable
		}
		list = append(list, v)
	}
	e = rows.Err()
	rows.Close()
	s.mu.Unlock()
	if e != nil {
		return Enrollment{}, ErrUnavailable
	}
	for _, v := range list {
		e = passwordVerify(code, v.hash)
		if e == nil {
			p.recoveryID = v.id
			p.recoveryHash = v.hash
		}
		if e != nil && e != ErrDenied {
			return Enrollment{}, e
		}
	}
	if p.recoveryID == 0 {
		return Enrollment{}, ErrDenied
	}
	seed, encoded, e := newSeed()
	if e != nil {
		return Enrollment{}, e
	}
	p.seed = seed
	p.purpose = "code-recover"
	p.source = source
	token, e := h.add(p, now)
	if e != nil {
		clear(seed)
		return Enrollment{}, e
	}
	return Enrollment{token, encoded, p.expires}, nil
}
func recoveryCodes() ([]string, []string, error) {
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		b := make([]byte, 16)
		if _, e := rand.Read(b); e != nil {
			return nil, nil, ErrUnavailable
		}
		codes[i] = hex.EncodeToString(b)
		clear(b)
		var e error
		hashes[i], e = passwordHash(codes[i])
		if e != nil {
			return nil, nil, e
		}
	}
	return codes, hashes, nil
}

func (h *HumanAuth) Confirm(challenge, code, source string, now time.Time) (HumanResult, error) {
	return h.confirm(challenge, code, source, now, nil)
}
func (h *HumanAuth) confirm(challenge, code, source string, now time.Time, recent *Actor) (HumanResult, error) {
	if !h.mu.TryLock() {
		return HumanResult{}, ErrUnavailable
	}
	defer h.mu.Unlock()
	if h.closed {
		return HumanResult{}, ErrUnavailable
	}
	if e := h.store.rateAttemptMFA(source, now); e != nil {
		return HumanResult{}, e
	}
	d, p, e := h.ceremony(challenge, source, now)
	if e != nil {
		return HumanResult{}, e
	}
	if p.purpose == "replace" && (recent == nil || recent.id != p.id || recent.humanEpoch != p.epoch) {
		return HumanResult{}, ErrDenied
	}
	if p.purpose == "login" {
		return h.confirmLogin(d, p, code, now)
	}
	counter, ok := acceptedOTP(p.seed, code, now.Unix(), -1)
	if !ok {
		return HumanResult{}, ErrDenied
	}
	codes, hashes, e := recoveryCodes()
	if e != nil {
		return HumanResult{}, e
	}
	s := h.store
	s.mu.Lock()
	var a Actor
	e = s.write(func(tx *sql.Tx) error {
		var oldID string
		var epoch int64
		er := tx.QueryRow("SELECT id,epoch FROM human WHERE singleton=1").Scan(&oldID, &epoch)
		if er != nil && er != sql.ErrNoRows {
			return ErrUnavailable
		}
		if p.purpose == "code-recover" || p.purpose == "replace" {
			if er != nil || oldID != p.id || epoch != p.epoch {
				return ErrDenied
			}
			var hash string
			if p.purpose == "code-recover" {
				if tx.QueryRow("SELECT verifier FROM recovery_codes WHERE id=?", p.recoveryID).Scan(&hash) != nil || hash != p.recoveryHash {
					return ErrDenied
				}
			}
		} else {
			var gd []byte
			var purpose string
			var expiry int64
			if tx.QueryRow("SELECT digest,purpose,expires FROM human_grant WHERE singleton=1").Scan(&gd, &purpose, &expiry) != nil || purpose != p.purpose || now.Unix() >= expiry || now.Unix() < expiry-600 || !hmac.Equal(gd, p.grant[:]) {
				return ErrDenied
			}
			if (p.purpose == "setup" && er != sql.ErrNoRows) || (p.purpose == "recover" && er != nil) {
				return ErrDenied
			}
			if _, e := tx.Exec("DELETE FROM human_grant"); e != nil {
				return ErrUnavailable
			}
		}
		if epoch >= int64(^uint64(0)>>1) {
			return ErrUnavailable
		}
		epoch++
		id := oldID
		if id == "" {
			_, id, e = secret("sdni")
			if e != nil {
				return e
			}
		}
		enc, e := s.encryptSeed(p.seed)
		if e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT INTO human VALUES(1,?,?,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET username=excluded.username,name=excluded.name,password=excluded.password,seed=excluded.seed,counter=excluded.counter,epoch=excluded.epoch", id, p.user, p.name, p.phc, enc, counter, epoch, now.Unix()); e != nil {
			return ErrUnavailable
		}
		if s.version == 4 && (p.purpose == "recover" || p.purpose == "code-recover") {
			if _, e = tx.Exec("DELETE FROM passkeys"); e != nil {
				return ErrUnavailable
			}
		}
		if _, e = tx.Exec("DELETE FROM recovery_codes"); e != nil {
			return ErrUnavailable
		}
		for i, v := range hashes {
			if _, e = tx.Exec("INSERT INTO recovery_codes VALUES(?,?)", i+1, v); e != nil {
				return ErrUnavailable
			}
		}
		if e = s.clearRateSQL(tx, source); e != nil {
			return e
		}
		action := "human_recovered"
		if p.purpose == "setup" {
			action = "human_setup"
		}
		if e = audit(tx, now, action, id); e != nil {
			return e
		}
		permissions, _ := scopes(allScopes)
		a = Actor{id: id, realm: s.identity.RealmID, node: s.identity.NodeID, name: p.name, permissions: permissions, humanEpoch: epoch}
		return nil
	})
	s.mu.Unlock()
	if e != nil {
		return HumanResult{}, e
	}
	clear(p.seed)
	delete(h.pending, d)
	token, i, e := h.sessions.issueHuman(a, now)
	if e != nil {
		return HumanResult{}, e
	}
	return HumanResult{token, i, codes}, nil
}
func (h *HumanAuth) confirmLogin(d [32]byte, p *humanCeremony, code string, now time.Time, replace ...string) (HumanResult, error) {
	s := h.store
	action, old := "human_login", ""
	if len(replace) == 1 {
		action, old = "human_reauth", replace[0]
	}
	token, i, e := h.sessions.issueHumanCommit(Actor{}, now, now, action, func(tx *sql.Tx) (Actor, error) {
		var id, name string
		var epoch, last, created int64
		var enc []byte
		if tx.QueryRow("SELECT id,name,epoch,counter,seed,created FROM human WHERE singleton=1").Scan(&id, &name, &epoch, &last, &enc, &created) != nil {
			return Actor{}, ErrUnavailable
		}
		if id != p.id || epoch != p.epoch || now.Unix() < created {
			return Actor{}, ErrDenied
		}
		seed, e := s.decryptSeed(enc)
		if e != nil {
			return Actor{}, e
		}
		defer clear(seed)
		counter, ok := acceptedOTP(seed, code, now.Unix(), last)
		if !ok {
			return Actor{}, ErrDenied
		}
		if _, e = tx.Exec("UPDATE human SET counter=? WHERE singleton=1", counter); e != nil {
			return Actor{}, ErrUnavailable
		}
		if e = s.clearRateSQL(tx, p.source); e != nil {
			return Actor{}, e
		}
		permissions, _ := scopes(allScopes)
		return Actor{id: id, realm: s.identity.RealmID, node: s.identity.NodeID, name: name, permissions: permissions, humanEpoch: epoch}, nil
	}, old)
	if e != nil {
		return HumanResult{}, e
	}
	delete(h.pending, d)
	return HumanResult{Token: token, Session: i}, nil
}
