package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/modules"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/modsettings"
)

// The modules panel (docs/modules.md, section 7). Administrators see and edit
// the modules; a module reads its own settings and reports its own runs with
// its own API token, and nothing else.

func (s *server) modulesRoutes(mux *routeMux) {
	mux.HandleFunc("GET /api/modules", s.modulesList)
	mux.HandleFunc("GET /api/modules/status", s.modulesStatus)
	mux.HandleFunc("GET /api/modules/{name}/settings", s.moduleSettings)
	mux.HandleFunc("PUT /api/modules/{name}/settings", s.moduleSave)
	mux.HandleFunc("POST /api/modules/{name}/preview", s.modulePreview)
	mux.HandleFunc("POST /api/modules/{name}/run-request", s.moduleRunRequest)
	mux.HandleFunc("POST /api/modules/{name}/runs", s.moduleRuns)
}

func (s *server) now() time.Time {
	if s.o.Now != nil {
		return s.o.Now()
	}
	return time.Now()
}

// moduleAdmin answers 403 unless the caller is a signed-in administrator. An
// API token never is, whatever its creator's role.
func (s *server) moduleAdmin(w http.ResponseWriter, r *http.Request) bool {
	id := s.who(r)
	if id == nil || id.Method == auth.MethodToken || !auth.Can(r.Context(), roles.Manage) {
		writeError(w, http.StatusForbidden, "forbidden", "only administrators may manage modules")
		return false
	}
	return true
}

// callerModule is the module whose token made the request ("" = not a module token).
func (s *server) callerModule(r *http.Request) (string, *config.Module) {
	id := s.who(r)
	if id == nil || id.Method != auth.MethodToken {
		return "", nil
	}
	return s.o.Store.Config().ModuleForToken(id.Token)
}

func (s *server) isAdmin(r *http.Request) bool {
	id := s.who(r)
	return id != nil && id.Method != auth.MethodToken && auth.Can(r.Context(), roles.Manage)
}

// module finds the module of the path.
func (s *server) module(w http.ResponseWriter, r *http.Request) (string, *config.Module, bool) {
	name := r.PathValue("name")
	m := s.o.Store.Config().Modules[name]
	if m == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such module")
		return "", nil, false
	}
	return name, m, true
}

// effective returns the schedule the module runs by: its settings, else the
// defaults of its type.
func effective(m *config.Module) (times []string, tz string, custom bool) {
	var set modsettings.Settings = m.ParsedSettings()
	def := modsettings.DefaultSendAt
	if m.Type == modsettings.TypeEntra {
		def = modsettings.DefaultSyncAt
	}
	if set != nil {
		times, tz = set.Schedule()
	}
	custom = len(times) > 0
	if len(times) == 0 {
		times = def
	}
	if tz == "" {
		tz = modsettings.DefaultTimezone
	}
	return times, tz, custom
}

type scheduleOut struct {
	Times    []string `json:"times"`
	Timezone string   `json:"timezone"`
	Default  bool     `json:"default"` // times come from the defaults, not the settings
}

type requestOut struct {
	ID        string    `json:"id"`
	Requested time.Time `json:"requested"`
	By        string    `json:"by,omitempty"`
}

type moduleView struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"` // "" = no settings in the console
	Token      string   `json:"token"`
	TokenState string   `json:"tokenStatus"` // active, revoked, expired, missing
	ReadOnly   bool     `json:"readOnly"`
	Collection string   `json:"collection,omitempty"`
	Fields     []string `json:"fields"`
	DirectPush bool     `json:"directPush"`

	Settings map[string]any `json:"settings"`
	Version  string         `json:"version"`
	Paused   bool           `json:"paused"`

	Status     string            `json:"status"` // ok, failed, skipped, never
	LastRun    *modsettings.Run  `json:"lastRun"`
	LastOK     *time.Time        `json:"lastOk"`
	Runs       []modsettings.Run `json:"runs"`
	RunRequest *requestOut       `json:"runRequest"`
	Schedule   scheduleOut       `json:"schedule"`
	NextRun    *time.Time        `json:"nextRun"` // next daily slot; nil when paused
	Due        bool              `json:"due"`     // would run at its next hourly check
	Keys       []string          `json:"keys"`    // the settings the console edits
	Effective  map[string]any    `json:"effective"`
}

func (s *server) moduleView(name string, m *config.Module, tokenStatus map[string]string) moduleView {
	cur, ver := modules.Current(m)
	runs := s.o.Modules.Runs(name)
	if runs == nil {
		runs = []modsettings.Run{}
	}
	v := moduleView{
		Name: name, Type: m.Type, Token: m.Token, TokenState: "missing", ReadOnly: m.ReadOnly(), Collection: m.Collection,
		Fields: strs(m.Fields), DirectPush: m.DirectPush, Settings: cur, Version: ver, Status: "never", Runs: runs,
		Keys: modsettings.Keys(m.Type),
	}
	if st, ok := tokenStatus[m.Token]; ok {
		v.TokenState = st
	}
	if set := m.ParsedSettings(); set != nil {
		v.Paused = set.IsPaused()
	}
	if len(runs) > 0 {
		v.LastRun, v.Status = &runs[0], runs[0].Status
	}
	if ok := s.o.Modules.LastOK(name); !ok.IsZero() {
		v.LastOK = &ok
	}
	if p := s.o.Modules.Pending(name); p != nil {
		v.RunRequest = &requestOut{ID: p.ID, Requested: p.Requested, By: p.By}
	}
	times, tz, custom := effective(m)
	v.Schedule = scheduleOut{Times: times, Timezone: tz, Default: !custom}
	now := s.now()
	if m.Type != "" && !v.Paused {
		if t, ok := modsettings.NextSlot(now, times, tz); ok {
			v.NextRun = &t
		}
		var lastOK time.Time
		if v.LastOK != nil {
			lastOK = *v.LastOK
		}
		pending := ""
		if v.RunRequest != nil {
			pending = v.RunRequest.ID
		}
		v.Due = modsettings.Decide(modsettings.Input{Now: now, Times: times, Timezone: tz, LastOK: lastOK, RunRequest: pending}).Run
	}
	return v
}

func (s *server) tokenStates() map[string]string {
	out := map[string]string{}
	if s.o.Tokens == nil {
		return out
	}
	ts, err := s.o.Tokens.List()
	if err != nil {
		return out
	}
	for _, t := range ts {
		out[t.Name] = s.describe(t).Status
	}
	return out
}

func sortedModules(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.Modules))
	for n, m := range cfg.Modules {
		if m != nil {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

func (s *server) modulesList(w http.ResponseWriter, r *http.Request) {
	if !s.moduleAdmin(w, r) {
		return
	}
	cfg := s.o.Store.Config()
	states := s.tokenStates()
	out := []moduleView{}
	for _, n := range sortedModules(cfg) {
		out = append(out, s.moduleView(n, cfg.Modules[n], states))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"modules": out, "now": s.now().UTC(), "writeMode": cfg.Write.Mode,
		"historyKept": s.o.Modules.Path != "",
	})
}

// moduleSettings is what a module reads at start: its own settings, whether a
// "run now" request waits, and when it last succeeded. An administrator may
// read it too.
func (s *server) moduleSettings(w http.ResponseWriter, r *http.Request) {
	// authorize before looking the module up, so the answer does not tell a
	// caller which module names exist
	if own, _ := s.callerModule(r); own != r.PathValue("name") && !s.isAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "a module may read only its own settings")
		return
	}
	name, m, ok := s.module(w, r)
	if !ok {
		return
	}
	cur, ver := modules.Current(m)
	out := modsettings.Remote{Name: name, Type: m.Type, Settings: cur, Version: ver, LastOK: s.o.Modules.LastOK(name), LastRun: s.o.Modules.LastRun(name), Now: s.now().UTC()}
	if p := s.o.Modules.Pending(name); p != nil {
		out.RunRequest = p.ID
	}
	writeJSON(w, http.StatusOK, out)
}

type settingsBody struct {
	Version       string         `json:"version"`
	Settings      map[string]any `json:"settings"`
	ConfirmImpact bool           `json:"confirm_impact"`
}

func (s *server) settingsBody(w http.ResponseWriter, r *http.Request) (settingsBody, bool) {
	var b settingsBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return b, false
	}
	if b.Settings == nil {
		b.Settings = map[string]any{}
	}
	return b, true
}

func (s *server) moduleSave(w http.ResponseWriter, r *http.Request) {
	if !s.moduleAdmin(w, r) || !s.writable(w, r, roles.Manage) {
		return
	}
	name, _, ok := s.module(w, r)
	if !ok {
		return
	}
	b, ok := s.settingsBody(w, r)
	if !ok {
		return
	}
	ch := modules.Change{Name: name, Version: b.Version, Settings: b.Settings, ConfirmImpact: b.ConfirmImpact}
	res, err := s.o.Store.WriteFunc(r.Context(), func(cfg *config.Config) (*edit.Result, error) {
		return modules.Apply(cfg, ch)
	}, s.who(r), gitstore.WriteOptions{})
	if err != nil {
		s.moduleFailure(w, err)
		return
	}
	s.log.Info("module settings changed", "module", name, "by", s.who(r).ID, "commit", res.Commit, "changed", res.Changed())
	out := map[string]any{"name": name, "changed": res.Changed(), "commit": res.Commit, "pullRequest": res.PullRequest}
	if m := s.o.Store.Config().Modules[name]; m != nil && !res.PullRequest {
		cur, ver := modules.Current(m)
		out["settings"], out["version"] = cur, ver
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) moduleFailure(w http.ResponseWriter, err error) {
	var ve *modules.VersionError
	var ie *modules.InvalidError
	var ce *modules.ImpactError
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusConflict, "conflict", ve.Error(), "current", map[string]any{"settings": ve.Current, "version": ve.Version})
	case errors.As(err, &ce):
		writeError(w, http.StatusUnprocessableEntity, "confirm_required", ce.Error(), "impact", ce.Impact)
	case errors.As(err, &ie):
		writeError(w, http.StatusUnprocessableEntity, "refused", ie.Message)
	case errors.Is(err, modules.ErrUnknownModule):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, modules.ErrNoSettings):
		writeError(w, http.StatusUnprocessableEntity, "no_settings", err.Error())
	default:
		s.writeFailure(w, err)
	}
}

// modulePreview says what a settings change would do to the module's records.
// It writes nothing.
func (s *server) modulePreview(w http.ResponseWriter, r *http.Request) {
	if !s.moduleAdmin(w, r) {
		return
	}
	name, m, ok := s.module(w, r)
	if !ok {
		return
	}
	b, ok := s.settingsBody(w, r)
	if !ok {
		return
	}
	if m.Type == "" {
		writeError(w, http.StatusUnprocessableEntity, "no_settings", modules.ErrNoSettings.Error())
		return
	}
	cfg := s.o.Store.Config()
	next, err := modsettings.DecodeAndValidate(m.Type, b.Settings, func(c string) bool { return cfg.Collection(c) != nil })
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "refused", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, modules.PreviewImpact(cfg, name, next))
}

func (s *server) moduleRunRequest(w http.ResponseWriter, r *http.Request) {
	if !s.moduleAdmin(w, r) || !s.writable(w, r, roles.Manage) {
		return
	}
	name, m, ok := s.module(w, r)
	if !ok {
		return
	}
	if set := m.ParsedSettings(); set != nil && set.IsPaused() {
		writeError(w, http.StatusConflict, "paused", "the module is paused; resume it first")
		return
	}
	req, err := s.o.Modules.Request(name, s.who(r).ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.log.Info("module run requested", "module", name, "by", s.who(r).ID, "request", req.ID)
	writeJSON(w, http.StatusOK, map[string]any{"runRequest": requestOut{ID: req.ID, Requested: req.Requested, By: req.By}})
}

// moduleRuns takes a run report. Only the module's own token may send it.
func (s *server) moduleRuns(w http.ResponseWriter, r *http.Request) {
	if own, _ := s.callerModule(r); own == "" || own != r.PathValue("name") {
		writeError(w, http.StatusForbidden, "forbidden", "only the module's own token may report its runs")
		return
	}
	name, _, ok := s.module(w, r)
	if !ok {
		return
	}
	var run modsettings.Run
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&run); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return
	}
	run.Clean()
	if err := run.Validate(s.now()); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if skew := run.Finished.Sub(s.now()); skew > modsettings.SkewWorthLogging {
		s.log.Warn("module clock is ahead of the server's; run stored as reported", "module", name, "ahead", skew.Round(time.Second).String())
	}
	if err := s.o.Modules.AddRun(name, run); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
}

// modulesStatus is the short view rackbook-notify reads: the last run of every
// module. Administrators and the token of a notify module may read it.
func (s *server) modulesStatus(w http.ResponseWriter, r *http.Request) {
	_, m := s.callerModule(r)
	if !s.isAdmin(r) && (m == nil || m.Type != modsettings.TypeNotify) {
		writeError(w, http.StatusForbidden, "forbidden", "only administrators and the notify module may read module status")
		return
	}
	cfg := s.o.Store.Config()
	out := []modsettings.ModuleStatus{}
	for _, n := range sortedModules(cfg) {
		mod := cfg.Modules[n]
		st := modsettings.ModuleStatus{Name: n, Type: mod.Type, LastRun: s.o.Modules.LastRun(n)}
		if set := mod.ParsedSettings(); set != nil {
			st.Paused = set.IsPaused()
		}
		out = append(out, st)
	}
	writeJSON(w, http.StatusOK, map[string]any{"modules": out})
}
