package accounts

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// argon2id parameters (4.2): RFC 9106, second recommended setting. Constants, stored in each hash, so
// raising them rehashes at the next sign-in.
const (
	argonMemoryKiB = 64 * 1024 // m = 64 MiB
	argonTime      = 3         // t
	argonThreads   = 4         // p
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// Hard bounds on what a stored hash may ask of the server when it is verified: the memory of one slot
// (a hash that asks for more is corrupt, and would let three slots use more than their 192 MiB), and a
// small number of passes and lanes. A hash beyond them is refused as corrupt, never run.
const (
	maxArgonMemoryKiB = argonMemoryKiB
	maxArgonTime      = 6
	maxArgonThreads   = 8
)

type argonParams struct {
	m uint32
	t uint32
	p uint8
}

// current is what new hashes use. It is a variable only so that tests can run many hashes cheaply.
var current = argonParams{m: argonMemoryKiB, t: argonTime, p: argonThreads}

// Password length rules (4.2).
const (
	MinPasswordLenDefault = 12
	MinPasswordLenBound   = 64 // the setting runs from 12 to 64
	MaxPasswordLen        = 128
)

// normalise is NFKC (4.2): the password the person typed, as one canonical string.
func normalise(pw string) string { return norm.NFKC.String(pw) }

func encodePHC(p argonParams, salt, sum []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.m, p.t, p.p, b64.EncodeToString(salt), b64.EncodeToString(sum))
}

type phc struct {
	argonParams
	salt, sum []byte
}

var errBadPHC = errors.New("not an argon2id hash this version can verify")

func parsePHC(s string) (phc, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return phc{}, errBadPHC
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return phc{}, errBadPHC
	}
	var h phc
	var p uint
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.m, &h.t, &p); err != nil || p == 0 || p > maxArgonThreads {
		return phc{}, errBadPHC
	}
	h.p = uint8(p)
	if h.m < 8*uint32(h.p) || h.m > maxArgonMemoryKiB || h.t == 0 || h.t > maxArgonTime {
		return phc{}, errBadPHC
	}
	b64 := base64.RawStdEncoding
	var err1, err2 error
	h.salt, err1 = b64.DecodeString(parts[4])
	h.sum, err2 = b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(h.salt) < 8 || len(h.sum) < 16 {
		return phc{}, errBadPHC
	}
	return h, nil
}

// NeedsRehash says whether a stored hash is under older or different parameters than the current
// constants, so the next successful sign-in should store a new one.
func NeedsRehash(stored string) bool {
	h, err := parsePHC(stored)
	return err != nil || h.argonParams != current || len(h.salt) != argonSaltLen || len(h.sum) != argonKeyLen
}

// Hash returns the PHC string of the NFKC-normalised password with a fresh 16-byte salt. It runs
// outside the slots: sign-in code goes through Hasher.
func hashPassword(pw string) (string, error) { return hashWith(current, pw) }

func hashWith(p argonParams, pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(normalise(pw)), salt, p.t, p.m, p.p, argonKeyLen)
	return encodePHC(p, salt, sum), nil
}

// verifyPassword checks pw against a stored PHC string with a constant-time comparison of the tag.
// A stored hash that cannot be parsed is a failure, never a pass.
func verifyPassword(pw, stored string) bool {
	h, err := parsePHC(stored)
	if err != nil {
		return false
	}
	sum := argon2.IDKey([]byte(normalise(pw)), h.salt, h.t, h.m, h.p, uint32(len(h.sum)))
	return subtle.ConstantTimeCompare(sum, h.sum) == 1
}

var dummySalt = []byte("rackbook-dummy-1")

// burn runs one argon2id at the current parameters on a fixed salt and discards the result: the
// dummy check of 5.6 step 5.
func burn(pw string) { burnWith(current, pw) }

func burnWith(p argonParams, pw string) {
	sum := argon2.IDKey([]byte(normalise(pw)), dummySalt, p.t, p.m, p.p, argonKeyLen)
	_ = sum
}

// ---- hashing slots (8.7)

// Class says who is asking for a slot.
type Class int

const (
	// ClassNormal is an ordinary sign-in attempt.
	ClassNormal Class = iota
	// ClassPriority is a re-authentication or an attempt from a known network; it may use the reserved slot.
	ClassPriority
)

// ErrBusy is a hashing request that waited its whole queue time: 503 busy.
var ErrBusy = errors.New("busy: no hashing slot became free in time")

// Default slots: three of 64 MiB each (192 MiB peak), one reserved, a 5-second queue.
const (
	DefaultSlots = 3
	DefaultQueue = 5 * time.Second
)

// Slots bounds the argon2id runs in flight, and so the memory they use.
type Slots struct {
	general  chan struct{}
	reserved chan struct{}
	queue    time.Duration
}

// NewSlots makes n slots (at least 2), one of them reserved for ClassPriority.
func NewSlots(n int, queue time.Duration) *Slots {
	n = max(n, 2)
	return &Slots{general: make(chan struct{}, n-1), reserved: make(chan struct{}, 1), queue: queue}
}

func (s *Slots) acquire(ctx context.Context, c Class) (func(), error) {
	relG := func() { <-s.general }
	relR := func() { <-s.reserved }
	select { // never wait while a slot the caller may use is free
	case s.general <- struct{}{}:
		return relG, nil
	default:
	}
	if c == ClassPriority {
		select {
		case s.reserved <- struct{}{}:
			return relR, nil
		default:
		}
	}
	t := time.NewTimer(s.queue)
	defer t.Stop()
	var res chan struct{} // nil blocks forever: ClassNormal never waits for the reserved slot
	if c == ClassPriority {
		res = s.reserved
	}
	select {
	case s.general <- struct{}{}:
		return relG, nil
	case res <- struct{}{}:
		return relR, nil
	case <-t.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Hasher runs argon2id in the slots.
type Hasher struct {
	slots  *Slots
	params argonParams
	custom bool // params were given by NewHasherCost; otherwise the constants of 4.2 are read at each use
}

// NewHasher uses the default slots and the parameters of 4.2.
func NewHasher() *Hasher { return &Hasher{slots: NewSlots(DefaultSlots, DefaultQueue)} }

// NewHasherWith uses the given slots and the parameters of 4.2.
func NewHasherWith(s *Slots) *Hasher { return &Hasher{slots: s} }

// NewHasherCost is a hasher whose new hashes use the given cost instead of the constants of 4.2. The server
// never calls it: it exists so that tests which sign in many times do not run 64 MiB hashes. Verification
// always uses the parameters stored in the hash.
func NewHasherCost(s *Slots, memKiB, passes uint32, lanes uint8) *Hasher {
	return &Hasher{slots: s, params: argonParams{m: memKiB, t: passes, p: lanes}, custom: true}
}

func (h *Hasher) p() argonParams {
	if h.custom {
		return h.params
	}
	return current
}

// Hash hashes a new password. It does not check the rules (CheckPassword does).
func (h *Hasher) Hash(ctx context.Context, c Class, pw string) (string, error) {
	rel, err := h.slots.acquire(ctx, c)
	if err != nil {
		return "", err
	}
	defer rel()
	return hashWith(h.p(), pw)
}

// Verify checks pw against a stored hash. rehash says the stored hash is under old parameters.
func (h *Hasher) Verify(ctx context.Context, c Class, pw, stored string) (ok, rehash bool, err error) {
	ok, rehash, _, err = h.VerifyTimed(ctx, c, pw, stored)
	return ok, rehash, err
}

// VerifyTimed is Verify that also returns how long the argon2id run took inside its slot, the queue not counted:
// the hash-only sample of the dummy-hash budget (8.6).
func (h *Hasher) VerifyTimed(ctx context.Context, c Class, pw, stored string) (ok, rehash bool, took time.Duration, err error) {
	rel, err := h.slots.acquire(ctx, c)
	if err != nil {
		return false, false, 0, err
	}
	defer rel()
	start := time.Now()
	ok = verifyPassword(pw, stored)
	took = time.Since(start)
	return ok, ok && h.needsRehash(stored), took, nil
}

func (h *Hasher) needsRehash(stored string) bool {
	p, err := parsePHC(stored)
	return err != nil || p.argonParams != h.p() || len(p.salt) != argonSaltLen || len(p.sum) != argonKeyLen
}

// Dummy runs one argon2id for an account that cannot sign in, so the answer takes as long (5.6).
func (h *Hasher) Dummy(ctx context.Context, c Class, pw string) error {
	_, err := h.DummyTimed(ctx, c, pw)
	return err
}

// DummyTimed is Dummy that also returns the time of the run inside its slot.
func (h *Hasher) DummyTimed(ctx context.Context, c Class, pw string) (time.Duration, error) {
	rel, err := h.slots.acquire(ctx, c)
	if err != nil {
		return 0, err
	}
	defer rel()
	start := time.Now()
	burnWith(h.p(), pw)
	return time.Since(start), nil
}

// Wait joins the slot queue as a real check does and releases the slot at once: the wait of this
// moment, without a hash (the sleeper of the dummy-hash budget, 8.6).
func (h *Hasher) Wait(ctx context.Context, c Class) error {
	rel, err := h.slots.acquire(ctx, c)
	if err != nil {
		return err
	}
	rel()
	return nil
}

// ---- password rules (4.2)

// PasswordRules are the inputs of the rules besides the password.
type PasswordRules struct {
	// MinLen is the setting password_min_length, 12 to 64; 0 means 12.
	MinLen   int
	Username string
	// Host is the host name of --base-url.
	Host string
}

// Password rule codes.
const (
	PwTooShort         = "too_short"
	PwTooLong          = "too_long"
	PwCommon           = "common"
	PwContainsUsername = "contains_username"
	PwContainsHost     = "contains_host"
)

// PasswordError says which rule a password broke.
type PasswordError struct {
	Code string
	Min  int
}

func (e *PasswordError) Error() string {
	switch e.Code {
	case PwTooShort:
		return fmt.Sprintf("the password must have at least %d characters", e.Min)
	case PwTooLong:
		return fmt.Sprintf("the password must have at most %d characters", MaxPasswordLen)
	case PwCommon:
		return "that password is on a list of common passwords"
	case PwContainsUsername:
		return "the password must not contain the username"
	}
	return "the password must not contain the host name"
}

//go:embed commonpasswords.txt
var commonRaw string

var (
	commonOnce sync.Once
	commonSet  map[string]bool
)

var folder = cases.Fold()

func fold(s string) string { return folder.String(norm.NFKC.String(s)) }

func common() map[string]bool {
	commonOnce.Do(func() {
		commonSet = map[string]bool{}
		sc := bufio.NewScanner(strings.NewReader(commonRaw))
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l != "" && !strings.HasPrefix(l, "#") {
				commonSet[fold(l)] = true
			}
		}
	})
	return commonSet
}

// repeatedUnit says the password is one to four characters repeated ("aaaaaaaaaaaa", "abababababab").
func repeatedUnit(s string) bool {
	r := []rune(s)
	for k := 1; k <= 4 && k <= len(r)/2; k++ {
		ok := true
		for i := k; i < len(r); i++ {
			if r[i] != r[i-k] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// CheckPassword applies the rules of NIST SP 800-63B as the design states them: NFKC-normalised, at
// least MinLen (12 to 64) and at most 128 characters, no composition rules and no expiry; refused
// if it is on the embedded list of common passwords, or contains the username or the host name.
func CheckPassword(pw string, r PasswordRules) error {
	min := r.MinLen
	if min == 0 {
		min = MinPasswordLenDefault
	}
	if min < MinPasswordLenDefault || min > MinPasswordLenBound {
		return fmt.Errorf("password_min_length must be %d to %d", MinPasswordLenDefault, MinPasswordLenBound)
	}
	n := norm.NFKC.String(pw)
	// NFKC can make a short input long (U+FDFA is one character and 18 after folding): the minimum counts
	// the smaller of the two lengths, the maximum the larger
	raw, folded := utf8.RuneCountInString(pw), utf8.RuneCountInString(n)
	switch {
	case min > raw || min > folded:
		return &PasswordError{Code: PwTooShort, Min: min}
	case raw > MaxPasswordLen || folded > MaxPasswordLen:
		return &PasswordError{Code: PwTooLong}
	}
	f := folder.String(n)
	if common()[f] || repeatedUnit(f) {
		return &PasswordError{Code: PwCommon}
	}
	if u := fold(r.Username); len(u) >= minContained && strings.Contains(f, u) {
		return &PasswordError{Code: PwContainsUsername}
	}
	if h := fold(hostOnly(r.Host)); len(h) >= minContained && strings.Contains(f, h) {
		return &PasswordError{Code: PwContainsHost}
	}
	return nil
}

// minContained is the shortest username or host name the "contains" rules apply to: a one or two
// letter name would be in almost every password.
const minContained = 3

func hostOnly(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[:i], ":") {
		h = h[:i]
	}
	return h
}
