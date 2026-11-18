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
	"github.com/kazuhahub/rackbook/internal/types"
	"github.com/kazuhahub/rackbook/internal/validate"
)

// Data type management (docs/design-v0.2.md section 3). Administrators only.

func (s *server) typesRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/types", s.typesList)
	mux.HandleFunc("POST /api/types", s.typesCreate)
	mux.HandleFunc("GET /api/types/{name}", s.typesGet)
	mux.HandleFunc("POST /api/types/{name}/plan", s.typesPlan)
	mux.HandleFunc("PUT /api/types/{name}", s.typesUpdate)
	mux.HandleFunc("DELETE /api/types/{name}", s.typesDelete)
}

// admin answers 403 unless the caller is an administrator.
func (s *server) admin(w http.ResponseWriter, r *http.Request) bool {
	if !auth.Can(r.Context(), roles.Manage) {
		writeError(w, http.StatusForbidden, "forbidden", "only administrators may manage data types")
		return false
	}
	return true
}

type typeSummary struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Group       string `json:"group,omitempty"`
	Icon        string `json:"icon,omitempty"`
	File        string `json:"file"`
	Path        string `json:"path,omitempty"`
	SchemaFile  string `json:"schemaFile"`
	Count       int    `json:"count"`
	Fields      int    `json:"fields"`
	Problems    int    `json:"problems"`
}

func (s *server) typesList(w http.ResponseWriter, r *http.Request) {
	if !s.admin(w, r) {
		return
	}
	l := s.o.Store.Ledger()
	problems := map[string]int{}
	for _, is := range validate.Run(l) {
		problems[is.Collection]++
	}
	out := []typeSummary{}
	for _, c := range l.Collections {
		fields := len(c.Schema.Props)
		out = append(out, typeSummary{Name: c.Name, Title: c.Title, Description: c.Description, Group: c.Group, Icon: c.Icon,
			File: c.File, Path: c.Path, SchemaFile: c.Collection.Schema, Count: len(c.Records), Fields: fields, Problems: problems[c.Name]})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"types": out, "fieldTypes": types.FieldTypes, "formats": validate.FormatNames,
		"dataDir": l.Config.Types.DataDir, "schemaDir": l.Config.Types.SchemaDir, "writeMode": l.Config.Write.Mode,
	})
}

func (s *server) typesGet(w http.ResponseWriter, r *http.Request) {
	if !s.admin(w, r) {
		return
	}
	l := s.o.Store.Ledger()
	t, err := types.Load(l, r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"type": t, "incoming": l.BackRefs(t.Name)})
}

type typeBody struct {
	Type       *types.Type       `json:"type"`
	Migrations []types.Migration `json:"migrations"`
	Delete     bool              `json:"delete"`
}

func (s *server) typeBody(w http.ResponseWriter, r *http.Request) (typeBody, bool) {
	var b typeBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.UseNumber()
	if err := dec.Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return b, false
	}
	return b, true
}

// typesPlan is the dry run: the same request as the write, nothing is
// written. A name that does not exist plans a creation; "delete": true plans
// the removal.
func (s *server) typesPlan(w http.ResponseWriter, r *http.Request) {
	if !s.admin(w, r) {
		return
	}
	b, ok := s.typeBody(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	req := types.Request{Name: name, Type: b.Type, Migrations: b.Migrations}
	switch {
	case b.Delete:
		req.Op = types.OpDelete
	case s.o.Store.Ledger().Collection(name) == nil:
		req.Op = types.OpCreate
	default:
		req.Op = types.OpUpdate
	}
	if req.Op != types.OpDelete && b.Type == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "type is required")
		return
	}
	plan, err := types.Build(s.o.Store.Config(), req)
	if err != nil {
		s.typeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *server) typesCreate(w http.ResponseWriter, r *http.Request) {
	if !s.writable(w, r, roles.Manage) {
		return
	}
	b, ok := s.typeBody(w, r)
	if !ok {
		return
	}
	if b.Type == nil || b.Type.Name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "type.name is required")
		return
	}
	s.writeType(w, r, types.Request{Op: types.OpCreate, Name: b.Type.Name, Type: b.Type}, http.StatusCreated)
}

func (s *server) typesUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.writable(w, r, roles.Manage) {
		return
	}
	b, ok := s.typeBody(w, r)
	if !ok {
		return
	}
	if b.Type == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "type is required")
		return
	}
	s.writeType(w, r, types.Request{Op: types.OpUpdate, Name: r.PathValue("name"), Type: b.Type, Migrations: b.Migrations}, http.StatusOK)
}

func (s *server) typesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.writable(w, r, roles.Manage) {
		return
	}
	s.writeType(w, r, types.Request{Op: types.OpDelete, Name: r.PathValue("name")}, http.StatusOK)
}

// writeType commits a type change through the Git write path: one commit with
// the schema, rackbook.yml and, for a new type, its data file.
func (s *server) writeType(w http.ResponseWriter, r *http.Request, req types.Request, status int) {
	res, err := s.o.Store.WriteFunc(r.Context(), func(cfg *config.Config) (*edit.Result, error) {
		return types.Apply(cfg, req)
	}, s.who(r), gitstore.WriteOptions{})
	if err != nil {
		s.typeFailure(w, err)
		return
	}
	s.log.Info("data type changed", "op", req.Op, "type", req.Name, "by", s.who(r).ID, "commit", res.Commit)
	writeJSON(w, status, map[string]any{"name": req.Name, "commit": res.Commit, "files": nonNilStrings(res.Files), "changed": res.Changed()})
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *server) typeFailure(w http.ResponseWriter, err error) {
	var pe *types.PlanError
	switch {
	case errors.As(err, &pe):
		writeError(w, http.StatusUnprocessableEntity, "refused", err.Error(), "plan", pe.Plan)
	case errors.Is(err, types.ErrUnknownType):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	default:
		s.writeFailure(w, err)
	}
}
