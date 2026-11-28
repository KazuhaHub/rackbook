package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/rolesedit"
)

// The role editor (docs/design-audit.md, section 4): the lists of auth.roles and
// auth.auditors, read and saved by administrators. A save is one commit to
// rackbook.yml through the normal write path (direct push or pull request, the
// Edited-by and Edited-via trailers, the audit commit event), made with yamledit
// so comments and layout stay.
//
// Who may reach it: an administrator signed in on the console. An API token never
// may (the token layer only reaches a short list of paths, and this handler
// refuses a token identity as well), and neither may an OAuth or MCPHub access
// token. An auditor without the admin role is refused like any other non-admin.

func (s *server) rolesAdminRoutes(mux *routeMux) {
	mux.HandleFunc("GET /api/admin/roles", s.rolesGet)
	mux.HandleFunc("POST /api/admin/roles/preview", s.rolesPreview)
	mux.HandleFunc("POST /api/admin/roles", s.rolesSave)
}

// rolesAdmin answers 403 unless the caller is an administrator on a person's
// session, not on a credential of any kind.
func (s *server) rolesAdmin(w http.ResponseWriter, r *http.Request) bool {
	id := s.who(r)
	if id == nil || !auth.Can(r.Context(), roles.Manage) || humanOnly(id) != nil {
		writeError(w, http.StatusForbidden, "forbidden", "only administrators signed in on the console may edit roles")
		return false
	}
	return true
}

// humanOnly is nil for a person's session and an error for an API token or an
// OAuth or MCPHub access token.
func humanOnly(id *auth.Identity) error {
	switch id.Method {
	case auth.MethodToken, auth.MethodOAuth, auth.MethodMCPHub:
		return errors.New("a credential, not a session")
	}
	return nil
}

// rolesDegraded answers 409 config_degraded when the latest rackbook.yml does not
// load: the lists shown are those of the last good one, and nothing can be edited
// until a file that loads is back.
func (s *server) rolesDegraded(w http.ResponseWriter) bool {
	_ = s.o.Store.Config() // without Git this re-reads the file, and so notices a change
	if p := s.o.Store.ConfigProblem(); p != "" {
		writeError(w, http.StatusConflict, "config_degraded",
			"rackbook.yml does not load, so the roles cannot be edited: fix the file first ("+p+")", "problem", p)
		return true
	}
	return false
}

type rolesBody struct {
	Version  string              `json:"version"`
	Roles    map[string][]string `json:"roles"`
	Auditors *[]string           `json:"auditors"`
	Message  string              `json:"message"`
}

// request reads the body into a rolesedit request. It answers 400 itself.
func (s *server) rolesRequest(w http.ResponseWriter, r *http.Request) (rolesedit.Request, bool) {
	var b rolesBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return rolesedit.Request{}, false
	}
	l := rolesedit.Lists{}
	for _, n := range []string{rolesedit.ListAdmin, rolesedit.ListEditor, rolesedit.ListViewer} {
		v, ok := b.Roles[n]
		if !ok || v == nil {
			writeError(w, http.StatusBadRequest, "bad_request", "roles."+n+" is required: the complete list, [] for none")
			return rolesedit.Request{}, false
		}
		switch n {
		case rolesedit.ListAdmin:
			l.Admin = v
		case rolesedit.ListEditor:
			l.Editor = v
		case rolesedit.ListViewer:
			l.Viewer = v
		}
	}
	if len(b.Roles) != 3 {
		writeError(w, http.StatusBadRequest, "bad_request", "roles has admin, editor and viewer, and nothing else")
		return rolesedit.Request{}, false
	}
	if b.Auditors == nil || *b.Auditors == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "auditors is required: the complete list, [] for none")
		return rolesedit.Request{}, false
	}
	l.Auditors = *b.Auditors
	return rolesedit.Request{Version: b.Version, Lists: l, Message: b.Message, Evaluate: s.callerEvaluator(r), Identities: s.signedInIdentities(), Local: s.localView()}, true
}

// callerEvaluator evaluates the person making the request, on their own session,
// under lists of the editor's choosing.
func (s *server) callerEvaluator(r *http.Request) rolesedit.Evaluator {
	subject := s.who(r).Subject()
	return func(cfg *config.Config, spec *roles.Spec, auditors []string) (rolesedit.Cap, error) {
		c, err := s.o.Auth.CapabilitiesUnder(cfg, spec, auditors, subject)
		if err != nil {
			return rolesedit.Cap{}, err
		}
		return rolesedit.Cap{
			Role: c.Role.String(), Auditor: c.Auditor, RoleFrom: nonNilStrings(c.RoleFrom), AuditorFrom: nonNilStrings(c.AuditorFrom),
			ByIdentity: c.ByIdentity.String(), AuditorByIdentity: c.AuditorByIdent,
		}, nil
	}
}

// localView is what the role editor knows of local accounts: whether they are available and the
// state of each one.
func (s *server) localView() rolesedit.Local {
	if s.o.Local == nil {
		return rolesedit.Local{}
	}
	l := rolesedit.Local{Available: true, States: map[string]string{}}
	for _, a := range s.o.Local.Roster() {
		l.States[a.Username] = a.State
	}
	return l
}

// signedInIdentities are the identities audit/identities.json knows, if there is
// an audit log. The warning "nobody who signed in matches this entry" needs them.
func (s *server) signedInIdentities() []string {
	var ids []string
	for _, e := range s.o.Audit.Identities() {
		ids = append(ids, e.Identity)
	}
	return ids
}

// rolesGet returns the lists with a description of each entry.
func (s *server) rolesGet(w http.ResponseWriter, r *http.Request) {
	if !s.rolesAdmin(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, s.rolesView(r))
}

func (s *server) rolesView(r *http.Request) map[string]any {
	cfg := s.o.Store.Config()
	problem := s.o.Store.ConfigProblem()
	cur, explicit := rolesedit.Current(cfg)
	local := s.localView()
	ann := rolesedit.AnnotateLocal(cfg, cur, local)
	out := map[string]any{
		"version":  rolesedit.Version(cur),
		"loads":    problem == "",
		"explicit": explicit,
		"roles":    map[string]any{"admin": ann.Admin, "editor": ann.Editor, "viewer": ann.Viewer},
		"auditors": ann.Auditors,
		"file":     "rackbook.yml",
		// writeMode is how a save reaches the repository: push (a commit) or pr (a pull request)
		"writeMode": cfg.Write.Mode,
		"readOnly":  s.o.ReadOnly,
		"sso":       cfg.Auth.Mode == "oidc",
		// authMode "none" means nobody signs in: whoever reaches the console is an admin here, as for every admin write
		"authMode": s.o.Auth.Mode(),
		// the v0.1 auth.editors list: read as editor entries, never changed here
		"editors": nonNilStrings(cfg.Auth.Editors),
		// the /infra administrators and auditors are set by the deployment (flags), not here
		"infra": s.o.Infra != nil,
	}
	if s.o.Infra != nil {
		// the one group or app role each of the two flags names, if any ("group:<id>", "app-role:<value>")
		claims := map[string]any{}
		if e := s.o.Infra.Admins.ClaimEntry(); e != "" {
			claims["admins"] = e
		}
		if e := s.o.Infra.Auditors.ClaimEntry(); e != "" {
			claims["auditors"] = e
		}
		if len(claims) > 0 {
			// how long after a sign-in the entry counts (--infra-claims-absolute), in seconds
			claims["claimsAbsolute"] = int(s.o.Infra.Admins.ClaimsAbsolute().Seconds())
			out["infraClaims"] = claims
		}
	}
	// local accounts, offered by name for local: entries; the accounts' sign-in details never come here
	if s.o.Local != nil {
		accts := s.o.Local.Roster()
		out["local"] = map[string]any{"available": true, "accounts": accts}
	} else {
		out["local"] = map[string]any{"available": false, "accounts": []LocalAccount{}}
	}
	if problem != "" {
		out["problem"] = problem
	}
	spec, aud := cur.Spec()
	if c, err := s.callerEvaluator(r)(cfg, spec, aud); err == nil {
		out["you"] = c
	}
	return out
}

func refusalBody(rf *rolesedit.Refusal) map[string]any {
	m := map[string]any{"code": rf.Code, "message": rf.Message}
	if rf.Entries != nil {
		m["entries"] = rf.Entries
	}
	return m
}

// rolesPreview says what a save would do and writes nothing: the diff of
// rackbook.yml, what the caller would be afterwards, the warnings and, when a save
// would be refused, the refusal.
func (s *server) rolesPreview(w http.ResponseWriter, r *http.Request) {
	if !s.rolesAdmin(w, r) || s.rolesDegraded(w) {
		return
	}
	req, ok := s.rolesRequest(w, r)
	if !ok {
		return
	}
	var plan *rolesedit.Plan
	_, pr, err := s.o.Store.DryRunFunc(r.Context(), func(cfg *config.Config) (*edit.Result, error) {
		p, err := rolesedit.Build(cfg, req)
		plan = p
		return &edit.Result{}, err
	}, gitstore.WriteOptions{})
	if err != nil {
		s.rolesFailure(w, err)
		return
	}
	out := map[string]any{
		"version": plan.Version, "changed": plan.Changed, "file": plan.File, "diff": plan.Diff, "subject": plan.Subject,
		"entries": plan.Entries, "warnings": nonNilWarnings(plan.Warnings),
		"you":         map[string]any{"now": plan.Now, "after": plan.AfterCap},
		"pullRequest": pr, "readOnly": s.o.ReadOnly,
	}
	if plan.Refusal != nil {
		out["refusal"] = refusalBody(plan.Refusal)
	}
	writeJSON(w, http.StatusOK, out)
}

func nonNilWarnings(w []rolesedit.Warning) []rolesedit.Warning {
	if w == nil {
		return []rolesedit.Warning{}
	}
	return w
}

// rolesSave commits the change.
func (s *server) rolesSave(w http.ResponseWriter, r *http.Request) {
	if !s.rolesAdmin(w, r) || !s.writable(w, r, roles.Manage) || s.rolesDegraded(w) {
		return
	}
	req, ok := s.rolesRequest(w, r)
	if !ok {
		return
	}
	res, err := s.o.Store.WriteFunc(r.Context(), func(cfg *config.Config) (*edit.Result, error) {
		return rolesedit.Apply(cfg, req)
	}, s.who(r), gitstore.WriteOptions{})
	if err != nil {
		s.rolesFailure(w, err)
		return
	}
	s.log.Info("roles changed", "by", s.who(r).ID, "commit", res.Commit, "pullRequest", res.PullRequest, "changed", res.Changed())
	out := map[string]any{"changed": res.Changed(), "pullRequest": res.PullRequest, "subject": res.Subject(), "file": "rackbook.yml"}
	if res.PullRequest {
		// in pr mode nothing changes until the pull request is merged
		out["pullRequestUrl"] = res.Commit
	} else {
		out["commit"] = res.Commit
		view := s.rolesView(r)
		out["version"], out["roles"], out["auditors"] = view["version"], view["roles"], view["auditors"]
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) rolesFailure(w http.ResponseWriter, err error) {
	var ve *rolesedit.VersionError
	var rf *rolesedit.Refusal
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusConflict, "conflict", ve.Error(), "current", map[string]any{
			"version": ve.Version, "roles": map[string]any{"admin": ve.Current.Admin, "editor": ve.Current.Editor, "viewer": ve.Current.Viewer}, "auditors": ve.Current.Auditors,
		})
	case errors.As(err, &rf):
		extra := []any{}
		if rf.Entries != nil {
			extra = append(extra, "entries", rf.Entries)
		}
		writeError(w, http.StatusUnprocessableEntity, rf.Code, rf.Message, extra...)
	case errors.Is(err, rolesedit.ErrNoVersion):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, rolesedit.ErrNoRolesBlock):
		writeError(w, http.StatusUnprocessableEntity, "no_roles_block", err.Error())
	default:
		s.writeFailure(w, err)
	}
}
