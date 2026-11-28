package login

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/roles"
	"net/http"
	"os"
	"strings"
	"time"
)

// Cookie names. The __Host- prefix makes browsers require Secure, Path=/ and
// no Domain, so a sibling subdomain cannot plant them.
const (
	SessionCookie = "__Host-rackbook_session"
	LoginCookie   = "__Host-rackbook_login"

	// refreshEvery bounds how often the cookie is re-issued for activity.
	refreshEvery = 5 * time.Minute
	// enrolWindow is how recent an OIDC login must be to add a passkey.
	enrolWindow = 10 * time.Minute

	// maxCookieBytes is the longest session cookie value the server reads.
	maxCookieBytes = 4096
)

// maxSetCookieBytes bounds the whole Set-Cookie header (name, value and attributes) the
// server sends: browsers keep a cookie of at most 4096 bytes. A variable for the tests.
var maxSetCookieBytes = 4096

// errCookieTooLarge says a session does not fit one cookie even without its groups and roles.
var errCookieTooLarge = errors.New("the session does not fit a cookie")

var (
	// errNoSSO: single sign-on is not configured, this service is local accounts alone.
	errNoSSO     = errors.New("single sign-on is not configured")
	errNoSession = errors.New("no session")
	errBadCookie = errors.New("invalid session cookie")
	errExpired   = errors.New("session expired")
	errRevoked   = errors.New("session credential revoked")
	// errUnavailable is a transient failure to check a passkey session: the
	// credential file could not be read, which is not revocation.
	errUnavailable = errors.New("passkey file unavailable")
)

// boundGroups is boundClaim for the groups claim.
func boundGroups(in []string) (out []string, truncated bool) { return roles.BoundClaim(in, true) }

// boundAppRoles is boundClaim for the roles claim.
func boundAppRoles(in []string) (out []string, truncated bool) { return roles.BoundClaim(in, false) }

// session is the signed payload of the session cookie. It holds no role: the
// role is evaluated from auth.roles on every request.
type session struct {
	V      int      `json:"v"`
	ID     string   `json:"id"`
	Name   string   `json:"name,omitempty"`
	Method string   `json:"m"`
	Issued int64    `json:"iat"`
	Seen   int64    `json:"seen"`
	OIDCAt int64    `json:"oidc,omitempty"` // when the user last logged in with OIDC (passkey enrolment)
	Iss    string   `json:"iss,omitempty"`  // oidc sessions: the issuer that authenticated the login; a session from another issuer is refused
	Clm    string   `json:"clm,omitempty"`  // oidc sessions: the claim the identity came from ("sub" for a subject identity); checked by /infra
	Tid    string   `json:"tid,omitempty"`  // oidc sessions: the ID token's tenant (tid), lower case; checked by /infra
	Cli    string   `json:"cli,omitempty"`  // oidc sessions: the client ID of that login (checked by /infra, which pins it)
	Groups []string `json:"grp,omitempty"`  // oidc sessions: the ID token's groups claim (bounded), for group: role entries
	Roles  []string `json:"rol,omitempty"`  // oidc sessions: the ID token's roles claim (bounded), for app-role: role entries
	Cred   string   `json:"cred,omitempty"` // passkey sessions: the credential id used, so deleting it ends the session
	// Local sessions (docs/design-local-accounts.md, 6): the account's session id, when the person last fully
	// authenticated (the re-authentication window of piece 7 reads it) and the factor that was used.
	Sid    string `json:"sid,omitempty"`
	AuthAt int64  `json:"aat,omitempty"`
	Factor string `json:"fac,omitempty"`
}

// LocalSessions is what the codec asks of the store of local accounts to sign and verify a local
// session: the session id and the session secret of the account, while the account can hold sessions.
type LocalSessions interface {
	LiveSession(username string) (sid string, secret []byte, ok bool)
}

type codec struct {
	key   []byte
	local LocalSessions // nil: local accounts are not available and no local session is valid
}

func (c codec) mac(payload string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte("rackbook.session.v1\x00"))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// localKey is the MAC key of the sessions of one account: HKDF-SHA256 with the session key as the
// input keying material, the account's session secret as the salt and "rackbook.session.local.v1"
// followed by the session id as the info. Renewing the secret and the id of the account (a reset, a
// disable or remove that does so, a rekey of the account) changes the key, so the old cookies stop
// verifying; the key of one account is no use for another's.
func (c codec) localKey(secret []byte, sid string) ([]byte, error) {
	return hkdf.Key(sha256.New, c.key, secret, "rackbook.session.local.v1"+sid, 32)
}

func localMAC(key []byte, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("rackbook.session.local.v1\x00"))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// localAccountOf is the username of a local session's identity.
func localAccountOf(id string) (string, bool) {
	n, ok := roles.LocalUsername(id)
	return n, ok && id == roles.LocalPrefix+n // the identity is stored folded
}

// sealLocal signs a local session with the key of its account. The session must carry the account's
// current session id.
func (c codec) sealLocal(p string, s session) (string, error) {
	name, ok := localAccountOf(s.ID)
	if !ok || c.local == nil || s.Sid == "" {
		return "", errBadCookie
	}
	sid, secret, live := c.local.LiveSession(name)
	if !live || sid != s.Sid {
		return "", errRevoked
	}
	key, err := c.localKey(secret, sid)
	clear(secret)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(localMAC(key, p)), nil
}

func (c codec) seal(s session) (string, error) {
	s.V = 1
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // & < > stay one byte; only quotes and backslashes grow
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	b := bytes.TrimRight(buf.Bytes(), "\n")
	p := base64.RawURLEncoding.EncodeToString(b)
	if s.Method == auth.MethodLocal {
		sig, err := c.sealLocal(p, s)
		if err != nil {
			return "", err
		}
		return p + "." + sig, nil
	}
	return p + "." + base64.RawURLEncoding.EncodeToString(c.mac(p)), nil
}

func (c codec) open(v string) (session, error) {
	var s session
	if len(v) > maxCookieBytes {
		return s, errBadCookie
	}
	p, sig, ok := strings.Cut(v, ".")
	if !ok || strings.Contains(sig, ".") {
		return s, errBadCookie
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return s, errBadCookie
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return s, errBadCookie
	}
	// Which key checks the signature depends on the method the payload claims, and nothing in it is
	// believed before the signature is: a payload that says "local" is checked with its account's key
	// alone, one that says anything else with the session key alone, so neither can borrow the other.
	var head struct {
		Method string `json:"m"`
		ID     string `json:"id"`
		Sid    string `json:"sid"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return s, errBadCookie
	}
	if head.Method == auth.MethodLocal {
		name, ok := localAccountOf(head.ID)
		if !ok || c.local == nil || head.Sid == "" {
			return session{}, errBadCookie
		}
		sid, secret, live := c.local.LiveSession(name)
		if !live || sid != head.Sid {
			// verified below only for a session that still has a live account with this id; a forgery
			// and a session of an account that was reset, disabled or removed are told apart by nobody
			return session{}, errRevoked
		}
		key, err := c.localKey(secret, sid)
		clear(secret)
		if err != nil || !hmac.Equal(want, localMAC(key, p)) {
			return session{}, errBadCookie
		}
	} else if !hmac.Equal(want, c.mac(p)) {
		return s, errBadCookie
	}
	if json.Unmarshal(raw, &s) != nil || s.V != 1 || s.ID == "" {
		return session{}, errBadCookie
	}
	switch s.Method {
	case auth.MethodOIDC, auth.MethodPasskey:
	case auth.MethodLocal:
		if _, ok := localAccountOf(s.ID); !ok || s.Sid == "" {
			return session{}, errBadCookie
		}
	default:
		return session{}, errBadCookie
	}
	return s, nil
}

// absoluteLimit is the absolute lifetime of a session: claimsAbsolute when claims
// contribute to its role (Service.claimsLimited decides, on every request), if that
// is shorter than the normal limit.
func absoluteLimit(absolute, claimsAbsolute time.Duration, claims bool) time.Duration {
	if claims && claimsAbsolute > 0 && claimsAbsolute < absolute {
		return claimsAbsolute
	}
	return absolute
}

// check applies the idle and absolute limits.
func (s session) check(now time.Time, idle, absolute time.Duration) error {
	issued, seen := time.Unix(s.Issued, 0), time.Unix(s.Seen, 0)
	if issued.After(now.Add(time.Minute)) || seen.Before(issued) {
		return errBadCookie
	}
	if !now.Before(issued.Add(absolute)) || !now.Before(seen.Add(idle)) {
		return errExpired
	}
	return nil
}

// LoadSessionKey decodes the session signing key from its base64 text (the
// value of RACKBOOK_SESSION_KEY) or reads it from file. Exactly one source
// may be given; the key must be at least 32 bytes.
func LoadSessionKey(env, file string) ([]byte, error) {
	env, file = strings.TrimSpace(env), strings.TrimSpace(file)
	switch {
	case env != "" && file != "":
		return nil, errors.New("set only one of RACKBOOK_SESSION_KEY and --session-key-file")
	case env == "" && file == "":
		return nil, errors.New("--auth login needs a session signing key: set RACKBOOK_SESSION_KEY (base64, 32 or more random bytes, e.g. `openssl rand -base64 32`) or pass --session-key-file")
	}
	src := "RACKBOOK_SESSION_KEY"
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("--session-key-file: %w", err)
		}
		env, src = strings.TrimSpace(string(b)), "--session-key-file"
	}
	var key []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err = enc.DecodeString(env); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64", src)
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("%s decodes to %d bytes, need at least 32", src, len(key))
	}
	return key, nil
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) { setCookie(w, name, "", -1) }
