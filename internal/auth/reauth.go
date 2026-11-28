package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Re-authentication (docs/design-local-accounts.md, 6): a sensitive action needs a person who fully authenticated recently.
// The session service answers whether a request's session did (login.Service.RecentAuth); the window is
// auth.local.reauth_window. Only local accounts are asked here: a person who signed in through single sign-on
// re-authenticates at the provider, and every other credential is not a person's session.

type recentAuther interface {
	RecentAuth(r *http.Request, window time.Duration) bool
}

// ReauthPath is the page that asks a local account for its password and second factor again.
const ReauthPath = "/auth/local/reauth"

// NeedsReauth says id is a local account's session whose last full authentication is older than the window, so that the
// sensitive action it asks for must wait for a re-authentication.
func (a *Authenticator) NeedsReauth(r *http.Request, id *Identity) bool {
	if id == nil || id.Method != MethodLocal {
		return false
	}
	ra, ok := a.cfg.Sessions.(recentAuther)
	if !ok {
		return true // a local session that cannot say when it authenticated is not recent
	}
	window := 10 * time.Minute
	if a.cfg.Config != nil {
		if c := a.cfg.Config(); c != nil {
			window = c.Auth.SignInSettings().ReauthWindow
		}
	}
	return !ra.RecentAuth(r, window)
}

// RequireRecentAuth answers 403 reauth_required, with the page to go to and to come back from, and returns true when the
// request is a local session that must re-authenticate first. The console opens the page and returns.
func (a *Authenticator) RequireRecentAuth(w http.ResponseWriter, r *http.Request) bool {
	if a == nil {
		return false
	}
	id := FromContext(r.Context())
	if !a.NeedsReauth(r, id) {
		return false
	}
	back := "/"
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil && strings.EqualFold(u.Host, r.Host) && strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, "//") && !strings.HasPrefix(u.Path, "/auth/") {
			back = u.RequestURI()
		}
	}
	b, _ := json.Marshal(map[string]string{
		"error":   "reauth_required",
		"message": "confirm it is you with your password and second factor, then try again",
		"reauth":  ReauthPath + "?return=" + url.QueryEscape(back),
	})
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(append(b, '\n'))
	return true
}
