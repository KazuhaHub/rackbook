package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/apierr"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

// Admin endpoints for Rackbook API tokens (docs/api.md). A token can never
// reach them: managing tokens needs the admin role of a signed-in user.

func (s *server) tokenRoutes(mux *routeMux) {
	mux.HandleFunc("GET /api/admin/tokens", s.listTokens)
	mux.HandleFunc("POST /api/admin/tokens", s.createToken)
	mux.HandleFunc("DELETE /api/admin/tokens/{name}", s.revokeToken)
}

func (s *server) tokenAdmin(w http.ResponseWriter, r *http.Request, write bool) bool {
	if s.o.Tokens == nil {
		writeError(w, http.StatusNotFound, "not_found", "API tokens are not enabled on this server")
		return false
	}
	if write && s.o.ReadOnly {
		writeError(w, http.StatusForbidden, "read_only", "the ledger is read-only")
		return false
	}
	id := s.who(r)
	if id == nil || id.Method == auth.MethodToken || !auth.Can(r.Context(), roles.Manage) {
		writeError(w, http.StatusForbidden, "forbidden", "only administrators may manage API tokens")
		return false
	}
	return true
}

type tokenOut struct {
	tokens.Token
	Status      string `json:"status"` // active, revoked, expired
	LastUsed    string `json:"lastUsed,omitempty"`
	CreatorRole string `json:"creatorRole"`
	// CreatorAuditor: the creator is on auth.auditors now, so the token reads the audit areas too.
	CreatorAuditor bool `json:"creatorAuditor,omitempty"`
	// Module is the module (modules: in rackbook.yml) that uses this token.
	Module   string   `json:"module,omitempty"`
	Warnings []string `json:"warnings"`
}

func (s *server) describe(t tokens.Token) tokenOut {
	out := tokenOut{Token: t, Status: "active", Warnings: []string{}}
	now := time.Now()
	switch {
	case t.Revoked != "":
		out.Status = "revoked"
	case !t.Active(now):
		out.Status = "expired"
	}
	if lu, ok := s.o.Tokens.LastUsed(t.Name); ok {
		out.LastUsed = lu.UTC().Format(time.RFC3339)
	}
	if name, _ := s.o.Store.Config().ModuleForToken(t.Name); name != "" {
		out.Module = name
	}
	role, auditor := s.o.Auth.CapabilitiesForVia(t.CreatedBy, t.SubjectMethod())
	out.CreatorRole, out.CreatorAuditor = role.String(), auditor
	want := roles.Viewer
	if t.Scope == tokens.ScopeWrite {
		want = roles.Editor
	}
	if out.Status == "active" {
		switch {
		case role == roles.None:
			out.Warnings = append(out.Warnings, "creator_no_role")
		case role < want:
			out.Warnings = append(out.Warnings, "limited_by_creator")
		}
		if t.WriteMode == tokens.ModePush && role != roles.Admin {
			out.Warnings = append(out.Warnings, "push_needs_admin")
		}
	}
	return out
}

func (s *server) listTokens(w http.ResponseWriter, r *http.Request) {
	if !s.tokenAdmin(w, r, false) {
		return
	}
	ts, err := s.o.Tokens.List()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "tokens_unreadable", err.Error())
		return
	}
	out := []tokenOut{}
	for _, t := range tokens.Sorted(ts) {
		out = append(out, s.describe(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out, "mcpUrl": s.baseURL(r) + "/mcp"})
}

type createTokenBody struct {
	Name        string   `json:"name"`
	Scope       string   `json:"scope"`
	Collections []string `json:"collections"`
	Actions     []string `json:"actions"`
	WriteMode   string   `json:"writeMode"`
	ExpiresDays int      `json:"expiresDays"`
}

func (s *server) createToken(w http.ResponseWriter, r *http.Request) {
	if !s.tokenAdmin(w, r, true) {
		return
	}
	var b createTokenBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return
	}
	// A token keeps working only through a role its creator holds by identity (an
	// exact entry, *@domain or oidc:), because it is evaluated for the creator on
	// every request and the creator's groups and app roles are not kept. A creator
	// whose role (for what this token is to do) comes only from those would hand
	// out a token that has no role, or less than it says.
	if who := s.who(r); who != nil {
		want := roles.Viewer
		if b.Scope == tokens.ScopeWrite {
			want = roles.Editor
			if b.WriteMode == tokens.ModePush {
				want = roles.Admin // a push token only counts while its creator is an admin by identity
			}
		}
		if role, _ := s.o.Auth.CapabilitiesForVia(who.ID, who.Method); role < want && who.EffectiveRole() >= want {
			writeError(w, http.StatusForbidden, "creator_role_from_claims",
				"your role comes from a group or an app role, which an API token cannot inherit: ask an administrator to list you by name (or *@domain) in auth.roles, then create the token")
			return
		}
	}
	if b.ExpiresDays < 0 || b.ExpiresDays > 3650 {
		writeError(w, http.StatusBadRequest, "bad_request", "expiresDays must be between 0 (never) and 3650")
		return
	}
	c, err := s.o.Tokens.Create(r.Context(), tokens.CreateParams{
		Name: strings.TrimSpace(b.Name), Scope: b.Scope, Collections: b.Collections, Actions: b.Actions,
		WriteMode: b.WriteMode, ExpiresDays: b.ExpiresDays,
	}, s.who(r))
	switch {
	case err == nil:
	case errors.Is(err, tokens.ErrExists):
		writeError(w, http.StatusConflict, "exists", err.Error())
		return
	case errors.Is(err, tokens.ErrInvalid):
		writeError(w, http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), tokens.ErrInvalid.Error()+": "))
		return
	default:
		if info := apierr.Classify(err); info.Status != http.StatusInternalServerError {
			extra := make([]any, 0, 2*len(info.Extra))
			for k, v := range info.Extra {
				extra = append(extra, k, v)
			}
			writeError(w, info.Status, info.Code, info.Message, extra...)
		} else {
			s.internal(w, err)
		}
		return
	}
	s.log.Info("api token created", "name", c.Token.Name, "scope", c.Token.Scope, "by", s.who(r).ID)
	mcpURL := s.baseURL(r) + "/mcp"
	resp := map[string]any{
		"token": s.describe(c.Token), "secret": c.Secret, "commit": c.Result.Commit, "pullRequest": c.Result.PullRequest,
		"snippet":    map[string]any{"type": "streamable-http", "url": mcpURL, "headers": map[string]string{"Authorization": "Bearer " + c.Secret}},
		"claudeCode": fmt.Sprintf("claude mcp add --transport http rackbook %s --header \"Authorization: Bearer %s\"", mcpURL, c.Secret),
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, resp)
}

func (s *server) revokeToken(w http.ResponseWriter, r *http.Request) {
	if !s.tokenAdmin(w, r, true) {
		return
	}
	name := r.PathValue("name")
	res, err := s.o.Tokens.Revoke(r.Context(), name, s.who(r))
	switch {
	case err == nil:
		s.log.Info("api token revoked", "name", name, "by", s.who(r).ID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "commit": res.Commit, "pullRequest": res.PullRequest})
	case errors.Is(err, tokens.ErrMissing):
		writeError(w, http.StatusNotFound, "not_found", "no such token")
	default:
		if info := apierr.Classify(err); info.Status != http.StatusInternalServerError {
			extra := make([]any, 0, 2*len(info.Extra))
			for k, v := range info.Extra {
				extra = append(extra, k, v)
			}
			writeError(w, info.Status, info.Code, info.Message, extra...)
		} else {
			s.internal(w, err)
		}
	}
}
