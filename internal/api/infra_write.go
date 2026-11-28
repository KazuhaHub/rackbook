package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/auth"
)

// The infra editors (README, "Editing the infra repository"). Every write is
// one commit on the followed branch. They are open only to the infra
// administrators with a recent browser sign-in under the pinned identity
// provider, never to API tokens, and never on /mcp.

const maxInfraBody = 2 << 20

func (s *server) infraWriteRoutes(mux *routeMux) {
	mux.HandleFunc("GET /api/infra/write", s.infraWriteState)
	mux.HandleFunc("GET /api/infra/features", s.infraFeatures)
	mux.HandleFunc("GET /api/infra/hosts/{name}/vars", s.infraHostVars)
	mux.HandleFunc("POST /api/infra/hosts/{name}/vars", s.infraSetVars)
	mux.HandleFunc("POST /api/infra/hosts/{name}/features/{feature}", s.infraSetFeature)
	mux.HandleFunc("GET /api/infra/groups", s.infraGroups)
	mux.HandleFunc("POST /api/infra/groups", s.infraSetGroups)
	mux.HandleFunc("POST /api/infra/commits/{hash}/revert", s.infraRevert)
}

// writesOn: the editors are enabled and the server is not read-only.
func (s *server) writesOn() bool {
	return s.o.Infra != nil && s.o.Infra.Write && !s.o.ReadOnly && s.o.Infra.Repo.CanWrite()
}

func (s *server) infraAudit(who *auth.Identity, action, outcome string) {
	if s.o.Infra == nil || s.o.Infra.Audit == nil {
		return
	}
	s.o.Infra.Audit.Record(ansiblerepo.AuditEntry{Time: s.now(), Who: who.IDOrEmpty(), Action: action, Outcome: outcome, Via: s.recordedVia(who)})
}

// infraWriter admits a write: the caller is an infra administrator, the
// editors are on, and the sign-in is recent.
func (s *server) infraWriter(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	via, ok := s.infraAdminVia(w, r)
	if !ok {
		s.infraAudit(s.who(r), r.Method+" "+r.URL.Path, "forbidden")
		return nil, false
	}
	if !s.writesOn() {
		writeError(w, http.StatusForbidden, "read_only", "editing the infra repository is switched off here")
		return nil, false
	}
	who := stampInfra(s.who(r), via)
	if !s.o.Infra.Admins.Fresh(who, s.now()) {
		s.infraAudit(who, r.Method+" "+r.URL.Path, "reauth_required")
		writeError(w, http.StatusForbidden, "reauth_required", "sign in again to edit the infra repository",
			"maxAgeSeconds", int64(s.o.Infra.Admins.WriteAge()/time.Second))
		return nil, false
	}
	return who, true
}

func (s *server) infraWriteState(w http.ResponseWriter, r *http.Request) {
	if !s.infraReader(w, r) {
		return
	}
	who := s.who(r)
	if !s.canInfraAdmin(r) {
		// an infra auditor: the editors and the secrets are off for them
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "secrets": false, "fresh": false, "auditor": true, "maxAgeSeconds": int64(s.o.Infra.Admins.WriteAge() / time.Second)})
		return
	}
	out := map[string]any{"enabled": s.writesOn(), "secrets": s.secretsOn(), "fresh": s.o.Infra.Admins.Fresh(who, s.now()), "maxAgeSeconds": int64(s.o.Infra.Admins.WriteAge() / time.Second)}
	if !who.OIDCAt.IsZero() {
		out["signedInAt"] = who.OIDCAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
}

func readInfraBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInfraBody))
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// writeInfraError answers an edit that did not commit.
func (s *server) writeInfraError(w http.ResponseWriter, err error) {
	var ce *ansiblerepo.ConflictError
	var ve *ansiblerepo.ValidationError
	var rf *ansiblerepo.RefusedError
	var ee *ansiblerepo.EditError
	switch {
	case errors.As(err, &ce):
		writeError(w, http.StatusConflict, "conflict", ce.Error(), "reason", ce.Reason, "files", ce.Files, "later", nz(ce.Later), "diffs", nzd(ce.Diffs))
	case errors.As(err, &ve):
		writeError(w, http.StatusUnprocessableEntity, "invalid", ve.Error(), "issues", ve.Issues)
	case errors.As(err, &rf):
		writeError(w, http.StatusConflict, "revert_refused", rf.Error(), "reason", rf.Code, "files", nz(rf.Files))
	case errors.As(err, &ee):
		writeError(w, http.StatusUnprocessableEntity, "edit_failed", ee.Error())
	case errors.Is(err, ansiblerepo.ErrNoChange):
		writeError(w, http.StatusUnprocessableEntity, "no_change", "nothing changed")
	case errors.Is(err, ansiblerepo.ErrBusy):
		writeError(w, http.StatusConflict, "busy", err.Error())
	case errors.Is(err, ansiblerepo.ErrReadOnly), errors.Is(err, ansiblerepo.ErrNoAuthor):
		writeError(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, ansiblerepo.ErrNoHost):
		writeError(w, http.StatusNotFound, "not_found", "no such host")
	case errors.Is(err, ansiblerepo.ErrNoSecret):
		writeError(w, http.StatusNotFound, "no_such_key", "no such key")
	case errors.Is(err, ansiblerepo.ErrSecretsOff):
		writeError(w, http.StatusForbidden, "secrets_off", err.Error())
	default:
		s.internal(w, err)
	}
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nzd(d []ansiblerepo.FileDiff) []ansiblerepo.FileDiff {
	if d == nil {
		return []ansiblerepo.FileDiff{}
	}
	return d
}

func (s *server) outcome(w http.ResponseWriter, o *ansiblerepo.Outcome) {
	if o.Issues == nil {
		o.Issues = []ansiblerepo.Issue{}
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *server) infraFeatures(w http.ResponseWriter, r *http.Request) {
	if !s.infraReader(w, r) {
		return
	}
	specs, invalid := s.o.Infra.Repo.Features()
	if specs == nil {
		specs = []*ansiblerepo.FeatureSpec{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"features": specs, "invalid": nz(invalid)})
}

// infraHostVars is the raw host_vars file for the editor. fileState sends no
// content when the hide scan finds anything, so it is not less redacted than the
// host page; it stays in the secret class (infra administrators only) as defence
// in depth, because it is edit support.
func (s *server) infraHostVars(w http.ResponseWriter, r *http.Request) {
	if !s.infraAdmin(w, r) {
		return
	}
	fs, err := s.o.Infra.Repo.HostFile(r.Context(), r.PathValue("name"))
	if err != nil {
		s.writeInfraError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, fs)
}

type varsBody struct {
	Base              string `json:"base"`
	Content           string `json:"content"`
	Preview           bool   `json:"preview"`
	ConfirmSecretScan bool   `json:"confirmSecretScan"`
}

func scopeOf(path string) string {
	p := strings.TrimPrefix(path, "inventory/")
	p = strings.TrimSuffix(strings.TrimSuffix(p, ".yml"), ".yaml")
	return p
}

func (s *server) infraSetVars(w http.ResponseWriter, r *http.Request) {
	who, ok := s.infraWriter(w, r)
	if !ok {
		return
	}
	var b varsBody
	if !readInfraBody(w, r, &b) {
		return
	}
	host := r.PathValue("name")
	if _, err := s.o.Infra.Repo.HostFile(r.Context(), host); err != nil {
		s.writeInfraError(w, err)
		return
	}
	if !utf8.ValidString(b.Content) || strings.ContainsRune(b.Content, 0) || len(b.Content) > 1<<20 {
		writeError(w, http.StatusUnprocessableEntity, "edit_failed", "the content must be UTF-8 text of at most 1 MiB")
		return
	}
	content := strings.ReplaceAll(b.Content, "\r\n", "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	path := s.o.Infra.Repo.HostVarsPath(host)
	e := ansiblerepo.Edit{Scope: scopeOf(path), Action: "edit", Who: who, ConfirmSecretScan: b.ConfirmSecretScan,
		Files: []ansiblerepo.FileEdit{{Path: path, Base: b.Base, Make: func(cur []byte) ([]byte, error) {
			if hasHidden(cur) {
				return nil, errors.New("the file holds values that look like secrets and is not edited here")
			}
			return []byte(content), nil
		}}}}
	s.finishEdit(w, r, e, b.Preview)
}

func (s *server) finishEdit(w http.ResponseWriter, r *http.Request, e ansiblerepo.Edit, preview bool) {
	o, err := s.o.Infra.Repo.Apply(r.Context(), e, preview)
	if err != nil {
		s.writeInfraError(w, err)
		return
	}
	s.outcome(w, o)
}

func hasHidden(content []byte) bool { return ansiblerepo.HiddenIn(content) > 0 }

type featureBody struct {
	Base string `json:"base"`
	// SecretsBase is the object ID of the host's SOPS file as the editor saw
	// it; left out, the current one is used (a key is set on its own, so there
	// is nothing to overwrite).
	SecretsBase       string         `json:"secretsBase"`
	Enabled           bool           `json:"enabled"`
	Settings          map[string]any `json:"settings"`
	Preview           bool           `json:"preview"`
	ConfirmSecretScan bool           `json:"confirmSecretScan"`
}

func (s *server) infraSetFeature(w http.ResponseWriter, r *http.Request) {
	who, ok := s.infraWriter(w, r)
	if !ok {
		return
	}
	var b featureBody
	if !readInfraBody(w, r, &b) {
		return
	}
	host, feature := r.PathValue("name"), r.PathValue("feature")
	repo := s.o.Infra.Repo
	cur, err := repo.HostFile(r.Context(), host)
	if err != nil {
		s.writeInfraError(w, err)
		return
	}
	if !ansiblerepo.ValidFeatureName(feature) {
		writeError(w, http.StatusNotFound, "not_found", "no such feature")
		return
	}
	var settings []ansiblerepo.Setting
	var secrets []ansiblerepo.SecretValue
	var known []string
	action := "disable " + feature
	if b.Enabled {
		spec, err := repo.Feature(feature)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "no such feature")
			return
		}
		var issues []ansiblerepo.Issue
		if settings, known, secrets, issues = spec.SettingsFromInput(b.Settings); len(issues) == 0 && len(secrets) > 0 && !repo.SecretsEnabled() {
			issues = []ansiblerepo.Issue{{Code: "feature.secret_unavailable", Severity: ansiblerepo.SevError, Path: "features." + feature + "." + secrets[0].Setting,
				Params:  map[string]string{"feature": feature, "setting": secrets[0].Setting},
				Message: feature + ": " + secrets[0].Setting + " is a secret setting and editing secrets is not set up here"}}
		}
		if len(issues) > 0 {
			s.infraAudit(who, "infra("+scopeOf(cur.Path)+"): features "+feature, "validation_failed")
			writeError(w, http.StatusUnprocessableEntity, "invalid", "the settings were refused", "issues", issues)
			return
		}
		action = "update " + feature
		if !ansiblerepo.HasFeature([]byte(cur.Content), feature) {
			action = "enable " + feature
		}
	}
	e := ansiblerepo.Edit{Scope: scopeOf(cur.Path), Action: action, Who: who, ConfirmSecretScan: b.ConfirmSecretScan,
		Files: []ansiblerepo.FileEdit{{Path: cur.Path, Base: b.Base, Make: func(old []byte) ([]byte, error) {
			if hasHidden(old) {
				return nil, errors.New("the file holds values that look like secrets and is not edited here")
			}
			return ansiblerepo.SetFeature(old, feature, b.Enabled, settings, known)
		}}}}
	if b.Enabled && len(secrets) > 0 {
		// the secret settings go to the host's SOPS file, in the same commit
		sf, err := repo.SecretsFile(r.Context(), host)
		if err != nil {
			s.writeInfraError(w, err)
			return
		}
		base := b.SecretsBase
		if base == "" {
			base = sf.Base
		}
		ops := make([]ansiblerepo.SecretOp, len(secrets))
		for i, sv := range secrets {
			ops[i] = ansiblerepo.SecretOp{Key: sv.Key, Value: sv.Value}
		}
		fe, err := repo.SecretsFileEdit(host, base, ops)
		if err != nil {
			s.writeInfraError(w, err)
			return
		}
		e.Files = append(e.Files, fe)
	}
	s.finishEdit(w, r, e, b.Preview)
}

func (s *server) infraGroups(w http.ResponseWriter, r *http.Request) {
	if !s.infraReader(w, r) {
		return
	}
	inv, err := s.o.Infra.Repo.Inventory(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

type groupsBody struct {
	Base              string                         `json:"base"`
	Changes           []ansiblerepo.MembershipChange `json:"changes"`
	Preview           bool                           `json:"preview"`
	ConfirmSecretScan bool                           `json:"confirmSecretScan"`
}

func (s *server) infraSetGroups(w http.ResponseWriter, r *http.Request) {
	who, ok := s.infraWriter(w, r)
	if !ok {
		return
	}
	var b groupsBody
	if !readInfraBody(w, r, &b) {
		return
	}
	if len(b.Changes) == 0 || len(b.Changes) > 500 {
		writeError(w, http.StatusUnprocessableEntity, "no_change", "nothing changed")
		return
	}
	inv, err := s.o.Infra.Repo.Inventory(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	hosts, groups := map[string]bool{}, map[string]bool{}
	for _, h := range inv.Membership.Hosts {
		hosts[h] = true
	}
	for _, g := range inv.Membership.Groups {
		groups[g] = true
	}
	var parts []string
	for _, c := range b.Changes {
		if !hosts[c.Host] || !groups[c.Group] {
			writeError(w, http.StatusUnprocessableEntity, "edit_failed", fmt.Sprintf("unknown host or group: %s / %s", c.Host, c.Group))
			return
		}
		sign := "-"
		if c.Member {
			sign = "+"
		}
		parts = append(parts, sign+c.Host+" "+c.Group)
	}
	action := "groups " + strings.Join(parts, ", ")
	if len(action) > 100 {
		action = fmt.Sprintf("groups: %d changes", len(b.Changes))
	}
	e := ansiblerepo.Edit{Scope: "inventory/hosts", Action: action, Who: who, ConfirmSecretScan: b.ConfirmSecretScan,
		Files: []ansiblerepo.FileEdit{{Path: "inventory/hosts.yml", Base: b.Base, Make: func(old []byte) ([]byte, error) {
			return ansiblerepo.SetMembership(old, b.Changes)
		}}}}
	s.finishEdit(w, r, e, b.Preview)
}

func (s *server) infraRevert(w http.ResponseWriter, r *http.Request) {
	who, ok := s.infraWriter(w, r)
	if !ok {
		return
	}
	var b struct {
		Preview bool `json:"preview"`
	}
	if !readInfraBody(w, r, &b) {
		return
	}
	o, err := s.o.Infra.Repo.Revert(r.Context(), r.PathValue("hash"), who, b.Preview)
	if err != nil {
		s.writeInfraError(w, err)
		return
	}
	s.outcome(w, o)
}
