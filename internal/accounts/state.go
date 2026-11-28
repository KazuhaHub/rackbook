// Package accounts is the encrypted state of local accounts: the account store with its single
// writer and start sequence, secrets.enc, the username records, argon2id with its slots, the
// password rules and TOTP (docs/design-local-accounts.md, sections 4, 5.4 and 9.3). Nothing in it
// is reachable from HTTP yet.
package accounts

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"
)

// Account states (4.2).
const (
	StateInvited      = "invited"
	StateActive       = "active"
	StateRestricted   = "restricted"
	StatePasskeyOnly  = "passkey_only"
	StateResetPending = "reset_pending"
	StateDisabled     = "disabled"
	StateRemoved      = "removed" // a tombstone
)

// Reset scopes (5.8).
const (
	ScopePassword     = "password"
	ScopeSecondFactor = "second_factor"
	ScopeAll          = "all"
)

// MaxPasskeys is the most passkeys one account holds.
const MaxPasskeys = 10

// Meta is the part of every encrypted document the writer maintains: the id of its last
// audited change, and the seq and month of the audit event of that change.
type Meta struct {
	Change     string `json:"change"`
	AuditSeq   int64  `json:"audit_seq"`
	AuditMonth string `json:"audit_month"`
}

// State is the decrypted content of accounts.enc.
type State struct {
	V int `json:"v"`
	Meta
	// Usernames is the store's own copy of every username ever used (4.5).
	Usernames []string            `json:"usernames"`
	Accounts  map[string]*Account `json:"accounts"`
}

func (s *State) meta() *Meta { return &s.Meta }

func newState() *State {
	return &State{V: 1, Accounts: map[string]*Account{}}
}

// Account is one local account (4.2). The role is not here: it comes from auth.roles.
type Account struct {
	// ID is a random id made with the account and never changed: an account that is replaced by a
	// new one under the same name (a reuse of the name, 4.5) is caught by it.
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by,omitempty"`
	// Password is a PHC string: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>.
	Password string    `json:"password,omitempty"`
	TOTP     *TOTP     `json:"totp,omitempty"`
	Passkeys []Passkey `json:"passkeys,omitempty"`
	// SID and SessionSecret are renewed together; renewing them ends every session.
	SID           string `json:"sid"`
	SessionSecret []byte `json:"session_secret"`

	ConsecutiveFailures int `json:"consecutive_failures,omitempty"`
	TOTPFailures        int `json:"totp_failures,omitempty"`
	PasskeyPathFailures int `json:"passkey_path_failures,omitempty"`
	ReauthFailures      int `json:"reauth_failures,omitempty"`
	// TOTPWindowStart is when the current 24-hour window of TOTPFailures began.
	TOTPWindowStart    time.Time    `json:"totp_window_start,omitzero"`
	PasskeyWindowStart time.Time    `json:"passkey_window_start,omitzero"`
	Locks              []Lock       `json:"locks,omitempty"`
	GoodBuckets        []GoodBucket `json:"good_buckets,omitempty"`

	Pending            *Pending    `json:"pending,omitempty"`
	PendingRevocations Revocations `json:"pending_revocations,omitzero"`

	LastLogin               *Seen    `json:"last_login,omitempty"`
	LastSecondFactorFailure *Seen    `json:"last_second_factor_failure,omitempty"`
	Notices                 []Notice `json:"notices,omitempty"`
}

// TOTP is the enrolled authenticator (5.4): a 20-byte secret and the last step accepted.
type TOTP struct {
	Secret   []byte    `json:"secret"`
	LastStep int64     `json:"last_step"`
	Added    time.Time `json:"added"`
}

// Passkey is one WebAuthn credential (5.5).
type Passkey struct {
	ID             []byte    `json:"id"`
	PublicKey      []byte    `json:"public_key"`
	UserHandle     []byte    `json:"user_handle"`
	Name           string    `json:"name"`
	Added          time.Time `json:"added"`
	BackupEligible bool      `json:"backup_eligible"`
	AAGUID         string    `json:"aaguid,omitempty"`
}

// Lock is an active lock of scope account (8.3).
type Lock struct {
	Scope string    `json:"scope"`
	Until time.Time `json:"until"`
}

// GoodBucket is an address bucket with a successful sign-in in the last 30 days.
type GoodBucket struct {
	Bucket string    `json:"bucket"`
	Last   time.Time `json:"last"`
}

// Pending is an invite or a reset awaiting its link (5.1, 5.8). TokenHash is the SHA-256 of the
// 32-byte token; it is empty while no link has been issued yet (a reset the offline CLI made).
type Pending struct {
	Kind      string    `json:"kind"` // invite | reset
	Scope     string    `json:"scope,omitempty"`
	TokenHash []byte    `json:"token_hash,omitempty"`
	Expires   time.Time `json:"expires,omitzero"`
	IssuedBy  string    `json:"issued_by,omitempty"`
	HeldUntil time.Time `json:"held_until,omitzero"`
	HeldBy    string    `json:"held_by,omitempty"`
}

// Revocations are the API token names and OAuth grant ids still to revoke (5.11).
type Revocations struct {
	Tokens []string `json:"tokens,omitempty"`
	Grants []string `json:"grants,omitempty"`
}

// Empty says nothing is pending.
func (r Revocations) Empty() bool { return len(r.Tokens) == 0 && len(r.Grants) == 0 }

// Seen is a time and an address.
type Seen struct {
	Time time.Time `json:"time"`
	Addr string    `json:"addr,omitempty"`
}

// Notice is an administrator's action on the account that the holder has not seen yet.
type Notice struct {
	Time time.Time `json:"time"`
	Kind string    `json:"kind"`
	By   string    `json:"by,omitempty"`
}

var usernameRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)

// ValidUsername says whether name is a possible username (5.1).
func ValidUsername(name string) bool { return usernameRe.MatchString(name) }

// ErrUsernameUsed is returned when a change would create an account under a name that was
// used before (4.5), including after the account was removed.
var ErrUsernameUsed = errors.New("that username has been used before and cannot be used again")

// ErrAccountReplaced is returned when a change would replace an existing account by a new one under
// the same name, or bring a removed account back.
var ErrAccountReplaced = errors.New("an existing account cannot be replaced, and a removed account stays removed")

// ErrAccountDropped is returned when a change would delete an account. Accounts are never
// deleted: removing leaves a tombstone, so the name stays used.
var ErrAccountDropped = errors.New("an account cannot be deleted from the store; remove leaves a tombstone")

// Account returns a copy of the account, or nil.
func (s *State) Account(username string) *Account {
	a := s.Accounts[username]
	if a == nil {
		return nil
	}
	b, _ := json.Marshal(a)
	var c Account
	_ = json.Unmarshal(b, &c)
	return &c
}

// Names returns the usernames of the accounts, sorted.
func (s *State) Names() []string {
	out := make([]string, 0, len(s.Accounts))
	for n := range s.Accounts {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// NewAccount makes an invited account with a fresh session id and secret. It is not stored
// until a change adds it to State.Accounts.
func NewAccount(username, name, createdBy string, now time.Time) (*Account, error) {
	if !ValidUsername(username) {
		return nil, errors.New("usernames match ^[a-z][a-z0-9._-]{0,31}$")
	}
	a := &Account{ID: newChangeID(), Username: username, Name: name, State: StateInvited, Created: now.UTC(), CreatedBy: createdBy}
	if err := a.RenewSessions(); err != nil {
		return nil, err
	}
	return a, nil
}

func marshal(v any) ([]byte, error) { return json.Marshal(v) }
