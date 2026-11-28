package login

import (
	"errors"
	"net/http"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// The one path that issues a local session (docs/design-local-accounts.md, 5.6 and 6). It is not a route: the
// sign-in service of local accounts (internal/localauth) calls it after it has verified a password and a second
// factor, and nothing else may. Service.issue still refuses the method.

// LocalGrant is a verified sign-in of a local account.
type LocalGrant struct {
	Username string
	Name     string
	// Factor is totp or passkey, the factor that was verified.
	Factor string
}

// LocalInfo is what a valid local session says about its holder.
type LocalInfo struct {
	Username string
	Name     string
	// AuthAt is when the person last fully authenticated (sign-in or re-authentication).
	AuthAt time.Time
	Factor string
}

// LocalRole is the role the local account has now, by the same evaluation as every request.
func (s *Service) LocalRole(username string) roles.Role {
	return s.roleOf(&auth.Identity{ID: roles.LocalPrefix + username, Method: auth.MethodLocal})
}

// ErrLocalSessionRefused is returned by IssueLocal for an account that is not live.
var ErrLocalSessionRefused = errors.New("the account cannot hold a session")

// IssueLocal starts a session for a verified local sign-in or re-authentication: the cookie is signed under the
// account's own key with its current session id, and carries when the person fully authenticated. It returns the
// role the account has. An account with no role gets no session (role none, nil error). The caller has written
// the login event.
func (s *Service) IssueLocal(w http.ResponseWriter, r *http.Request, g LocalGrant) (roles.Role, error) {
	id := &auth.Identity{ID: roles.LocalPrefix + g.Username, Name: g.Name, Method: auth.MethodLocal}
	ev := s.evaluate(id)
	role := ev.EffectiveRole()
	if role == roles.None {
		s.observeRole(r, ev, audit.CauseSignIn, false)
		return roles.None, nil
	}
	if s.o.Local == nil {
		return roles.None, ErrLocalSessionRefused
	}
	sid, secret, ok := s.o.Local.LiveSession(g.Username)
	clear(secret)
	if !ok {
		return roles.None, ErrLocalSessionRefused
	}
	now := s.now()
	sess := session{ID: id.ID, Name: g.Name, Method: auth.MethodLocal, Issued: now.Unix(), Seen: now.Unix(), Sid: sid, AuthAt: now.Unix(), Factor: g.Factor}
	sent, _, _, err := s.setSession(w, sess)
	if err != nil {
		return roles.None, err
	}
	s.users.touch(id.ID, g.Name, auth.MethodLocal, nil, nil, now)
	s.observeRole(r, ev, audit.CauseSignIn, true)
	s.markObserved(sent)
	return role, nil
}

// LocalSession returns who the request's session is when it is a valid local one.
func (s *Service) LocalSession(r *http.Request) (LocalInfo, bool) {
	sess, err := s.readSession(r)
	if err != nil || sess.Method != auth.MethodLocal {
		return LocalInfo{}, false
	}
	name, ok := localAccountOf(sess.ID)
	if !ok {
		return LocalInfo{}, false
	}
	return LocalInfo{Username: name, Name: sess.Name, AuthAt: time.Unix(sess.AuthAt, 0), Factor: sess.Factor}, true
}

// RecentAuth says the request's local session fully authenticated within window (design 6, re-authentication).
// It is false for every other session and for a request with none.
func (s *Service) RecentAuth(r *http.Request, window time.Duration) bool {
	info, ok := s.LocalSession(r)
	if !ok || info.AuthAt.IsZero() {
		return false
	}
	age := s.now().Sub(info.AuthAt)
	return age >= -time.Minute && age < window
}

// ClearSession ends the browser's session cookie.
func (s *Service) ClearSession(w http.ResponseWriter) { clearCookie(w, SessionCookie) }

// Origin is the https origin of the console.
func (s *Service) Origin() string { return s.base.String() }

// Host is the host name of --base-url: the passkey relying-party ID and what a password must not contain.
func (s *Service) Host() string { return s.base.Hostname() }

// SSOAvailable says single sign-on is configured: an OIDC provider exists in the settings. It never means the
// provider is healthy (design 2.1).
func (s *Service) SSOAvailable() bool { return s.sso }
