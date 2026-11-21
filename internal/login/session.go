package login

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
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

	maxCookieBytes = 2048
)

var (
	errNoSession = errors.New("no session")
	errBadCookie = errors.New("invalid session cookie")
	errExpired   = errors.New("session expired")
	errRevoked   = errors.New("session credential revoked")
	// errUnavailable is a transient failure to check a passkey session: the
	// credential file could not be read, which is not revocation.
	errUnavailable = errors.New("passkey file unavailable")
)

// Bounds on the groups kept in the session cookie, which must stay small.
const (
	maxSessionGroups     = 40
	maxSessionGroupBytes = 700 // total
)

// boundGroups keeps the first groups that fit the cookie. truncated says some were dropped.
func boundGroups(in []string) (out []string, truncated bool) {
	total := 0
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" || len(g) > 128 || !utf8.ValidString(g) {
			continue
		}
		if len(out) >= maxSessionGroups || total+len(g) > maxSessionGroupBytes {
			return out, true
		}
		total += len(g)
		out = append(out, g)
	}
	return out, false
}

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
	Cli    string   `json:"cli,omitempty"`  // oidc sessions: the client ID of that login (checked by /infra, which pins it)
	Groups []string `json:"grp,omitempty"`  // oidc sessions: the ID token's groups claim (bounded), for group: role entries
	Cred   string   `json:"cred,omitempty"` // passkey sessions: the credential id used, so deleting it ends the session
}

type codec struct {
	key []byte
}

func (c codec) mac(payload string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte("rackbook.session.v1\x00"))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

func (c codec) seal(s session) (string, error) {
	s.V = 1
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(b)
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
	if err != nil || !hmac.Equal(want, c.mac(p)) {
		return s, errBadCookie
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || json.Unmarshal(raw, &s) != nil || s.V != 1 || s.ID == "" {
		return session{}, errBadCookie
	}
	if s.Method != "oidc" && s.Method != "passkey" {
		return session{}, errBadCookie
	}
	return s, nil
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
		return nil, errors.New("--auth oidc needs a session signing key: set RACKBOOK_SESSION_KEY (base64, 32 or more random bytes, e.g. `openssl rand -base64 32`) or pass --session-key-file")
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
