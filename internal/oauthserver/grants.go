package oauthserver

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/roles"
)

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

type grantOut struct {
	ID         string   `json:"id"`
	ClientID   string   `json:"clientId"`
	ClientName string   `json:"clientName"`
	Scopes     []string `json:"scopes"`
	// CanWrite says the grant carries the write scope (what the role allows is another matter).
	CanWrite bool      `json:"canWrite"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed"`
	// Admin list only: whose grant it is.
	User     string `json:"user,omitempty"`
	UserName string `json:"userName,omitempty"`
}

func (s *Server) live(g *Grant) bool {
	return s.now().Sub(g.LastUsed) <= s.cfg().IdleExpiryOrDefault()
}

func (s *Server) list(w http.ResponseWriter, keep func(*Grant) bool, admin bool) {
	out := []grantOut{}
	for _, g := range s.store.grants(func(g *Grant) bool { return keep(g) && s.live(g) }) {
		o := grantOut{ID: g.ID, ClientID: g.ClientID, ClientName: g.ClientName, Scopes: g.Scopes, Created: g.Created, LastUsed: g.LastUsed}
		o.CanWrite = s.canWrite(s.effective(&g), g.Scopes)
		if o.Scopes == nil {
			o.Scopes = []string{}
		}
		if admin {
			o.User, o.UserName = g.Subject.ID, g.Subject.Name
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": out})
}

// accountGrants lists the caller's own grants.
func (s *Server) accountGrants(w http.ResponseWriter, r *http.Request) {
	who, ok := humanSubject(r)
	if !ok {
		apiError(w, http.StatusForbidden, "forbidden", "this endpoint is for signed-in people")
		return
	}
	s.list(w, func(g *Grant) bool { return g.Subject.ID == who.ID }, false)
}

// revokeOwn ends one of the caller's own grants.
func (s *Server) revokeOwn(w http.ResponseWriter, r *http.Request) {
	who, ok := humanSubject(r)
	if !ok {
		apiError(w, http.StatusForbidden, "forbidden", "this endpoint is for signed-in people")
		return
	}
	g := s.store.grant(r.PathValue("id"))
	if g == nil || g.Subject.ID != who.ID {
		apiError(w, http.StatusNotFound, "not_found", "no such grant")
		return
	}
	if _, err := s.revoke(g.ID, "revoked by "+who.ID); err != nil {
		apiError(w, http.StatusInternalServerError, "internal", "the grant could not be revoked because the state file could not be written; it is still active")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) (Subject, bool) {
	who, ok := humanSubject(r)
	if !ok || !auth.Can(r.Context(), roles.Manage) {
		apiError(w, http.StatusForbidden, "forbidden", "only administrators may manage everyone's grants")
		return Subject{}, false
	}
	return who, true
}

func (s *Server) adminGrants(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.admin(w, r); !ok {
		return
	}
	s.list(w, func(*Grant) bool { return true }, true)
}

func (s *Server) revokeAny(w http.ResponseWriter, r *http.Request) {
	who, ok := s.admin(w, r)
	if !ok {
		return
	}
	found, err := s.revoke(r.PathValue("id"), "revoked by admin "+who.ID)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal", "the grant could not be revoked because the state file could not be written; it is still active")
		return
	}
	if !found {
		apiError(w, http.StatusNotFound, "not_found", "no such grant")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
