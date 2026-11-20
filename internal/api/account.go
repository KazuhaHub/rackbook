package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/prefs"
)

func (s *server) accountRoutes(mux *http.ServeMux) {
	mux.HandleFunc("PUT /api/account/preferences", s.putPreferences)
}

// personal reports a credential that is a person (a browser login or a
// Cloudflare Access identity), as opposed to an API token or OAuth bearer.
func personal(id *auth.Identity) bool {
	if id == nil || id.ID == "" {
		return false
	}
	switch id.Method {
	case auth.MethodToken, auth.MethodOAuth, auth.MethodMCPHub:
		return false
	}
	return true
}

// putPreferences stores the caller's console preferences: {"locale":"en-US"}
// sets the language, {"locale":""} clears it. It is not a ledger write, so
// --read-only does not block it: the file is Rackbook's own state (in
// --state-dir), never the data repository. Same-origin and JSON checks are
// the guard's, as for every other mutating /api route.
func (s *server) putPreferences(w http.ResponseWriter, r *http.Request) {
	id := s.who(r)
	if id != nil && !personal(id) && id.ID != "" {
		writeError(w, http.StatusForbidden, "forbidden", "this endpoint is for signed-in people, not API tokens")
		return
	}
	if !personal(id) {
		// --auth none without --editor: everyone shares one anonymous identity,
		// so a preference would apply to all of them.
		writeError(w, http.StatusConflict, "no_identity", "preferences are saved per person; this server does not identify you (use --auth oidc or cloudflare-access, or --editor)")
		return
	}
	var body struct {
		Locale *string `json:"locale"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	if err := dec.Decode(&body); err != nil || body.Locale == nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"locale": "<locale>"}`)
		return
	}
	got, err := s.o.Prefs.SetLocale(id.ID, *body.Locale)
	switch {
	case errors.Is(err, prefs.ErrInvalidLocale):
		writeError(w, http.StatusBadRequest, "invalid_locale", "locale must be one of zh-CN, zh-TW, en-US (or empty to clear)")
	case errors.Is(err, prefs.ErrFull):
		writeError(w, http.StatusInsufficientStorage, "too_many_users", "too many saved preferences")
	case err != nil:
		s.internal(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"locale": got})
	}
}
