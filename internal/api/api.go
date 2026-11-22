// Package api implements the HTTP API of docs/api.md and serves the console.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/apierr"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/expiry"
	"github.com/kazuhahub/rackbook/internal/export"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/locale"
	"github.com/kazuhahub/rackbook/internal/modules"
	"github.com/kazuhahub/rackbook/internal/prefs"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/tokens"
	"github.com/kazuhahub/rackbook/internal/validate"
)

const maxBody = 1 << 20

// Options configures the handler.
type Options struct {
	Store    *gitstore.Store
	Auth     *auth.Authenticator // nil = auth mode none, roles from the store's config
	ReadOnly bool
	BaseURL  string       // public URL used in llms.txt; derived from the request when empty
	Web      fs.FS        // console files (root of dist); may lack index.html
	MCP      http.Handler // optional, mounted at /mcp
	// Login mounts the /auth endpoints and the account and user APIs (oidc
	// mode). It receives the console handler, which serves the login page.
	Login interface {
		Mount(mux *http.ServeMux, static http.Handler)
	}
	// RestrictHost limits accepted Host headers to loopback names and the host
	// of BaseURL (DNS-rebinding protection for --auth none).
	RestrictHost bool
	Logger       *slog.Logger

	// Public are exact paths served without authentication (the OAuth
	// protected resource metadata).
	Public map[string]http.Handler
	// Tokens enables the admin token endpoints (/api/admin/tokens).
	Tokens *tokens.Registry
	// OAuth is the built-in authorization server (nil = off). Its public
	// endpoints (metadata, token, registration, JWKS) are served without sign-in
	// and may be called cross-origin; the rest is mounted behind the sign-in.
	OAuth OAuthServer
	// Modules keeps the run history and run requests of the modules panel; nil
	// = in memory only.
	Modules *modules.State
	// Prefs keeps each person's console preferences (the language); nil = in
	// memory only.
	Prefs *prefs.Store
	// Infra turns on the read-only /infra pages (nil = off, and /api/infra is a 404).
	Infra *InfraOptions
	// Audit is the audit log (nil = none: the activity view then shows every
	// commit as unverified, and /api/audit/status says the log is off).
	Audit *audit.Log
	// Now is the clock; nil = time.Now.
	Now func() time.Time
}

// OAuthServer is the built-in authorization server (internal/oauthserver).
type OAuthServer interface {
	Public() map[string]http.Handler
	Mount(mux *http.ServeMux)
}

type server struct {
	o   Options
	log *slog.Logger
	// public are the exact paths served without authentication.
	public map[string]http.Handler
	// reveals limits how often one administrator may reveal a stored secret.
	reveals *revealLimiter
}

// New returns the full handler: API, exports, MCP and console.
func New(o Options) http.Handler {
	s := &server{o: o, log: o.Logger}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.reveals = &revealLimiter{log: s.log}
	if o.Infra != nil {
		s.reveals.Path = o.Infra.RevealStatePath
	}
	if s.o.Auth == nil {
		// No authentication, but roles (and the v0.1 editors list) still apply.
		a, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeNone, Config: o.Store.Config, Degraded: func() bool { return o.Store.ConfigProblem() != "" }})
		if err != nil {
			panic(err) // mode none cannot fail
		}
		s.o.Auth = a
	}
	if s.o.Modules == nil {
		s.o.Modules = &modules.State{}
	}
	if s.o.Prefs == nil {
		s.o.Prefs = &prefs.Store{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /api/meta", s.meta)
	mux.HandleFunc("GET /api/check", s.check)
	mux.HandleFunc("GET /api/history", s.history)
	mux.HandleFunc("GET /api/expiring", s.expiring)
	mux.HandleFunc("GET /api/c/{collection}", s.list)
	mux.HandleFunc("GET /api/c/{collection}/{id}", s.get)
	mux.HandleFunc("POST /api/c/{collection}", s.add)
	mux.HandleFunc("PUT /api/c/{collection}/{id}", s.put)
	mux.HandleFunc("DELETE /api/c/{collection}/{id}", s.del)
	mux.HandleFunc("POST /api/admin/accept-remote", s.acceptRemote)
	s.accountRoutes(mux)  // account.go
	s.tokenRoutes(mux)    // tokens.go
	s.typesRoutes(mux)    // types.go
	s.modulesRoutes(mux)  // modules.go
	s.brandingRoutes(mux) // branding.go: public
	s.infraRoutes(mux)    // infra.go: only with Options.Infra
	s.activityRoutes(mux) // activity.go
	public := map[string]http.Handler{}
	for p, h := range o.Public {
		public[p] = h
	}
	if o.OAuth != nil {
		o.OAuth.Mount(mux)
		for p, h := range o.OAuth.Public() {
			public[p] = h
		}
	}
	s.public = public
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such API endpoint")
	})
	mux.HandleFunc("GET /export.md", s.exportMD)
	mux.HandleFunc("GET /export.json", s.exportJSON)
	mux.HandleFunc("GET /llms.txt", s.llms)
	mux.HandleFunc("GET /llms-full.txt", s.llmsFull)
	if o.MCP != nil {
		mux.Handle("/mcp", o.MCP)
		mux.Handle("/mcp/", o.MCP)
	}
	mux.HandleFunc("/", s.static)
	if o.Login != nil {
		o.Login.Mount(mux, http.HandlerFunc(s.static))
	}

	authed := s.o.Auth.Middleware(mux)
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RawPath is set only when the request escaped something (e.g. %2F), so the
		// branding exemption matches exactly the two plain paths and nothing else.
		if r.URL.Path == "/healthz" || (r.URL.RawPath == "" && isBrandingPath(r.URL.Path)) {
			mux.ServeHTTP(w, r)
			return
		}
		if p, canonical := auth.CanonicalPath(r); canonical {
			if ph, ok := s.public[p]; ok {
				ph.ServeHTTP(w, r)
				return
			}
		}
		authed.ServeHTTP(w, r)
	})
	return securityHeaders(s.guard(h))
}

// guard rejects DNS-rebinding (unexpected Host) and cross-site or non-JSON writes.
func (s *server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.o.RestrictHost && !s.hostAllowed(r.Host) {
			writeError(w, http.StatusForbidden, "forbidden_host", "this Host is not allowed; use localhost or the configured --base-url host")
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			// The OAuth token and registration endpoints are called by clients on
			// other origins by design (browser-based MCP clients); they take no
			// cookies, only the parameters of the request.
			if _, open := s.public[r.URL.Path]; !open && !s.sameOrigin(r) {
				writeError(w, http.StatusForbidden, "cross_site", "cross-site requests are not allowed")
				return
			}
			if (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.HasPrefix(r.URL.Path, "/api/") {
				if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
					writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin decides whether a state-changing request comes from our own
// console. Sec-Fetch-Site, when the browser sends it, decides alone (it stays
// correct behind a proxy that rewrites Host). Otherwise an Origin must match
// the Host, X-Forwarded-Host or the --base-url host. Requests with neither
// header are non-browser clients and pass.
func (s *server) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	allowed := []string{r.Host}
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		allowed = append(allowed, strings.TrimSpace(strings.Split(h, ",")[0]))
	}
	if s.o.BaseURL != "" {
		if b, err := url.Parse(s.o.BaseURL); err == nil {
			allowed = append(allowed, b.Host)
		}
	}
	for _, h := range allowed {
		if strings.EqualFold(u.Host, h) {
			return true
		}
	}
	return false
}

func (s *server) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	if s.o.BaseURL != "" {
		if u, err := url.Parse(s.o.BaseURL); err == nil && strings.EqualFold(u.Hostname(), host) {
			return true
		}
	}
	return false
}

// internal logs the real error with a request id and returns a generic 500.
func (s *server) internal(w http.ResponseWriter, err error) {
	var b [6]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	s.log.Error("request failed", "request_id", id, "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error (request id "+id+")", "requestId", id)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// 'unsafe-eval': the console validates forms with ajv, which compiles each JSON Schema
		// to a function at runtime. The console loads no third-party scripts and renders no
		// ledger value as HTML.
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// JSON helpers -------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string, extra ...any) {
	body := map[string]any{"error": code, "message": msg}
	for i := 0; i+1 < len(extra); i += 2 {
		body[extra[i].(string)] = extra[i+1]
	}
	writeJSON(w, status, body)
}

// who is the caller authenticated by the middleware (never nil there).
func (s *server) who(r *http.Request) *auth.Identity { return auth.FromContext(r.Context()) }

// canEdit reports whether the caller may write: not in read-only mode and with
// at least the editor role.
func (s *server) canEdit(r *http.Request) bool {
	return !s.o.ReadOnly && auth.Can(r.Context(), roles.Write)
}

// Read endpoints -------------------------------------------------------------

type facetOut struct {
	Field  string   `json:"field"`
	Match  string   `json:"match"`
	Values []string `json:"values"`
}

type noteOut struct {
	Title string                       `json:"title"`
	Text  string                       `json:"text"`
	I18n  map[string]map[string]string `json:"i18n,omitempty"`
}

type collectionOut struct {
	Name        string           `json:"name"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Group       string           `json:"group"`
	Icon        string           `json:"icon,omitempty"`
	File        string           `json:"file"`
	Path        string           `json:"path,omitempty"`
	SchemaFile  string           `json:"schemaFile"`
	Key         []string         `json:"key"`
	Label       string           `json:"label"`
	List        []string         `json:"list"`
	Facets      []facetOut       `json:"facets"`
	Schema      json.RawMessage  `json:"schema"`
	Refs        []ledger.RefInfo `json:"refs"`
	Backrefs    []ledger.BackRef `json:"backrefs"`
	Notes       []noteOut        `json:"notes"`
	Count       int              `json:"count"`
	// I18n is title, description and group in the other languages.
	I18n         map[string]map[string]string `json:"i18n,omitempty"`
	ExpiryField  string                       `json:"expiryField"`
	RevokedField string                       `json:"revokedField"`
}

type moduleOut struct {
	Name       string   `json:"name"`
	Type       string   `json:"type,omitempty"`
	ReadOnly   bool     `json:"readOnly"`
	Collection string   `json:"collection"`
	Fields     []string `json:"fields"`
	DirectPush bool     `json:"directPush"`
}

func strs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *server) meta(w http.ResponseWriter, r *http.Request) {
	l := s.o.Store.Ledger()
	cfg := l.Config
	user := map[string]any{"canEdit": s.canEdit(r), "canAdmin": auth.Can(r.Context(), roles.Manage)}
	if s.canInfra(r) {
		user["canInfra"] = true
		if s.writesOn() {
			user["canInfraWrite"] = true
		}
	}
	if id := s.who(r); id != nil {
		user["role"], user["authMethod"] = id.EffectiveRole().String(), id.Method
		for k, v := range map[string]string{"id": id.ID, "email": id.Email, "name": id.Name} {
			if v != "" {
				user[k] = v
			}
		}
		if l := s.o.Prefs.Locale(id.ID); l != "" && personal(id) {
			user["locale"] = l
		}
	}
	cols := make([]collectionOut, 0, len(l.Collections))
	for _, c := range l.Collections {
		out := collectionOut{
			Name: c.Name, Title: c.Title, Description: c.Description, Group: c.Group, Icon: c.Icon,
			File: c.File, Path: c.Path, SchemaFile: c.Collection.Schema,
			Key: strs(c.Key), Label: c.Label, List: strs(c.List), Facets: []facetOut{},
			Schema: c.SchemaRaw, Refs: l.Refs(c.Name), Backrefs: l.BackRefs(c.Name), Notes: []noteOut{}, Count: len(c.Records),
			ExpiryField: expiry.ExpiryField(c), RevokedField: expiry.RevokedField(c),
			I18n: c.I18n.Only("title", "description", "group"),
		}
		if out.Schema == nil {
			out.Schema = json.RawMessage("{}")
		}
		for _, f := range c.Facets {
			out.Facets = append(out.Facets, facetOut{Field: f.Field, Match: f.Match, Values: strs(f.Values)})
		}
		for _, n := range l.Notes {
			if n.Collection == c.Name {
				out.Notes = append(out.Notes, noteOut{Title: n.Title, Text: n.Text, I18n: n.I18n.Only("title")})
			}
		}
		cols = append(cols, out)
	}
	mods := make([]moduleOut, 0, len(cfg.Modules))
	for name, m := range cfg.Modules {
		mods = append(mods, moduleOut{Name: name, Type: m.Type, ReadOnly: m.ReadOnly(), Collection: m.Collection, Fields: strs(m.Fields), DirectPush: m.DirectPush})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Name < mods[j].Name })
	meta := map[string]any{
		"title": cfg.Title, "description": cfg.Description,
		"readOnly": s.o.ReadOnly, "writeMode": cfg.Write.Mode, "user": user, "collections": cols, "modules": mods,
	}
	if s.o.OAuth != nil {
		meta["oauthServer"] = true // the console shows the authorized-clients lists
	}
	if t := cfg.I18n.Texts.Only("title", "description"); t != nil {
		meta["i18n"] = t // raw per-language text; the console picks by its current language
	}
	// The Accept-Language match and the configured default let the console pick
	// its language at boot; user.locale (a saved choice) wins over both.
	w.Header().Add("Vary", "Accept-Language")
	meta["defaultLocale"] = cfg.DefaultLocale()
	meta["locale"] = locale.Match(r.Header.Get("Accept-Language"), cfg.DefaultLocale())
	meta["branding"] = map[string]any{"name": cfg.Branding.Name, "logo": cfg.BrandLogo() != nil}
	if a := s.o.Store.Alert(); a != nil {
		meta["alert"] = a
	}
	if s.o.Audit != nil && s.canSee(r, seeAudit) {
		if st := s.o.Audit.Status(); !st.OK {
			// the banner for administrators; the Activity page has the details
			meta["auditAlert"] = map[string]any{"problems": len(st.Problems), "firstSeq": st.FirstBrokenSeq}
		}
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *server) check(w http.ResponseWriter, r *http.Request) {
	confirmed, _ := gitstore.ConfirmedRecords(r.Context(), s.o.Store.Config().Dir)
	issues, warnings := validate.Split(validate.RunWith(s.o.Store.Ledger(), validate.Options{Confirmed: func(coll, id string) bool { return confirmed[edit.RecordRef(coll, id)] }}))
	writeJSON(w, http.StatusOK, map[string]any{"ok": len(issues) == 0, "errors": issues, "warnings": warnings})
}

func (s *server) history(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	commits, err := s.o.Store.History(r.Context(), limit, r.URL.Query().Get("collection"), r.URL.Query().Get("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"commits": commits})
}

func (s *server) expiring(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	days := expiry.DefaultDays
	if v := q.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "days must be a whole number")
			return
		}
		days = n
	}
	res, err := expiry.List(s.o.Store.Ledger(), expiry.Options{Days: days, Collections: q["collection"], Unknown: q.Get("unknown") == "true"})
	if errors.Is(err, expiry.ErrUnknownCollection) {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) collection(w http.ResponseWriter, r *http.Request) (*ledger.Ledger, *ledger.Collection) {
	l := s.o.Store.Ledger()
	c := l.Collection(r.PathValue("collection"))
	if c == nil {
		writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("unknown collection %q", r.PathValue("collection")))
		return nil, nil
	}
	return l, c
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	_, c := s.collection(w, r)
	if c == nil {
		return
	}
	recs := c.Records
	if recs == nil {
		recs = []*ledger.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": recs})
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	l, c := s.collection(w, r)
	if c == nil {
		return
	}
	rec := c.Get(r.PathValue("id"))
	if rec == nil {
		writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("no record %q in %s", r.PathValue("id"), c.Name))
		return
	}
	back := map[string][]*ledger.Record{}
	for _, b := range l.BackRefs(c.Name) {
		back[b.Collection] = []*ledger.Record{}
	}
	for coll, recs := range l.Backrefs(c.Name, rec) {
		back[coll] = recs
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": rec.ID, "hash": rec.Hash, "data": rec.Data, "backrefs": back})
}

// Write endpoints ------------------------------------------------------------

type body struct {
	Data map[string]any `json:"data"`
	Hash string         `json:"hash"`
	// ConfirmNotSecret retries a write held as secret_suspected: "this is not a
	// secret". Never accepted for block-tier findings, nor for a token write that
	// becomes a pull request.
	ConfirmNotSecret bool `json:"confirm_not_secret"`
}

// confirmed sets op's secret-scan confirmation when the caller asked for it and
// may give it.
func (s *server) confirmed(r *http.Request, op edit.Op, want bool) edit.Op {
	if !want {
		return op
	}
	who := s.who(r)
	if gitstore.MayConfirm(who, s.o.Store.Config(), op.Kind, op.Collection) {
		op.ConfirmNotSecret = true
		op.ConfirmedBy = who.IDOrEmpty()
		if op.ConfirmedBy == "" {
			op.ConfirmedBy = "anonymous"
		}
	}
	return op
}

func (s *server) readBody(w http.ResponseWriter, r *http.Request) (body, bool) {
	var b body
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.UseNumber()
	if err := dec.Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return b, false
	}
	return b, true
}

// writable runs the shared checks of write endpoints: the server must not be
// read-only and the caller's role must allow action.
func (s *server) writable(w http.ResponseWriter, r *http.Request, action roles.Action) bool {
	if s.o.ReadOnly {
		writeError(w, http.StatusForbidden, "read_only", "the ledger is read-only")
		return false
	}
	if !auth.Can(r.Context(), action) {
		writeError(w, http.StatusForbidden, "forbidden", fmt.Sprintf("your role (%s) may not do this", s.who(r).EffectiveRole()))
		return false
	}
	return true
}

// permits applies a credential's own narrowing (an API token's collections and
// actions) on top of the role.
func (s *server) permits(w http.ResponseWriter, r *http.Request, action, collection string) bool {
	if s.who(r).Permits(action, collection) {
		return true
	}
	writeError(w, http.StatusForbidden, "forbidden", fmt.Sprintf("this token may not %s records in %s", action, collection))
	return false
}

func (s *server) apply(w http.ResponseWriter, r *http.Request, op edit.Op) *gitstore.WriteResult {
	// Tokens are contributor level: their writes open pull requests unless granted otherwise.
	opts := gitstore.WriteOptionsFor(s.who(r), s.o.Store.Config(), op.Kind, op.Collection)
	res, err := s.o.Store.WriteFunc(r.Context(), gitstore.ApplyOpAs(s.who(r), op), s.who(r), opts)
	if err == nil {
		return res
	}
	s.writeFailure(w, err)
	return nil
}

// writeFailure answers a failed write with the status and code of apierr, so
// the API and the MCP tools fail the same way. Internal errors are logged and
// shown with a request id.
func (s *server) writeFailure(w http.ResponseWriter, err error) {
	info := apierr.Classify(err)
	if info.Status == http.StatusInternalServerError {
		s.internal(w, err)
		return
	}
	extra := make([]any, 0, 2*len(info.Extra))
	for k, v := range info.Extra {
		extra = append(extra, k, v)
	}
	writeError(w, info.Status, info.Code, info.Message, extra...)
}

func (s *server) acceptRemote(w http.ResponseWriter, r *http.Request) {
	if s.o.ReadOnly {
		writeError(w, http.StatusForbidden, "read_only", "the ledger is read-only")
		return
	}
	if !auth.Can(r.Context(), roles.Manage) {
		writeError(w, http.StatusForbidden, "forbidden", "only administrators may accept the remote history")
		return
	}
	var b struct {
		Commit string `json:"commit"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&b); err != nil || b.Commit == "" {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"commit": "<remote tip>"}`)
		return
	}
	who := s.who(r)
	hash, err := s.o.Store.AcceptRemote(r.Context(), b.Commit)
	switch {
	case err == nil:
		s.log.Warn("remote history accepted", "by", who.ID, "remote", hash)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lastGood": hash})
	case errors.Is(err, gitstore.ErrConfig):
		writeError(w, http.StatusServiceUnavailable, "config_error", "the accepted commit's rackbook.yml does not load, nothing was changed: "+err.Error())
	case errors.Is(err, gitstore.ErrNoAlert):
		writeError(w, http.StatusConflict, "no_alert", err.Error())
	case errors.Is(err, gitstore.ErrNotRemoteTip):
		writeError(w, http.StatusConflict, "not_remote_tip", err.Error())
	case errors.Is(err, gitstore.ErrLocalCommits):
		writeError(w, http.StatusConflict, "local_commits", err.Error())
	case errors.Is(err, gitstore.ErrRepoDirty):
		writeError(w, http.StatusServiceUnavailable, "repo_dirty", err.Error())
	default:
		s.internal(w, err)
	}
}

func recordResponse(res *gitstore.WriteResult) map[string]any {
	out := map[string]any{"id": res.ID, "hash": res.Hash, "data": res.Data, "commit": res.Commit}
	if res.PullRequest {
		out["pullRequest"] = true
	}
	return out
}

func (s *server) add(w http.ResponseWriter, r *http.Request) {
	if !s.writable(w, r, roles.Write) {
		return
	}
	_, c := s.collection(w, r)
	if c == nil {
		return
	}
	b, ok := s.readBody(w, r)
	if !ok {
		return
	}
	if !s.permits(w, r, auth.ActCreate, c.Name) {
		return
	}
	if res := s.apply(w, r, s.confirmed(r, edit.Op{Kind: edit.Add, Collection: c.Name, Data: b.Data}, b.ConfirmNotSecret)); res != nil {
		writeJSON(w, http.StatusCreated, recordResponse(res))
	}
}

func (s *server) put(w http.ResponseWriter, r *http.Request) {
	if !s.writable(w, r, roles.Write) {
		return
	}
	_, c := s.collection(w, r)
	if c == nil {
		return
	}
	b, ok := s.readBody(w, r)
	if !ok {
		return
	}
	if b.Hash == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "hash is required: send the hash of the record you started from")
		return
	}
	if !s.permits(w, r, auth.ActUpdate, c.Name) {
		return
	}
	if res := s.apply(w, r, s.confirmed(r, edit.Op{Kind: edit.Edit, Collection: c.Name, ID: r.PathValue("id"), Hash: b.Hash, Data: b.Data}, b.ConfirmNotSecret)); res != nil {
		writeJSON(w, http.StatusOK, recordResponse(res))
	}
}

func (s *server) del(w http.ResponseWriter, r *http.Request) {
	if !s.writable(w, r, roles.Delete) {
		return
	}
	_, c := s.collection(w, r)
	if c == nil {
		return
	}
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "hash is required: send the hash of the record you started from")
		return
	}
	if !s.permits(w, r, auth.ActDelete, c.Name) {
		return
	}
	clear := r.URL.Query().Get("clearReferences") == "true"
	if res := s.apply(w, r, edit.Op{Kind: edit.Delete, Collection: c.Name, ID: r.PathValue("id"), Hash: hash, ClearReferences: clear,
		MayUpdate: func(coll string) bool {
			return s.who(r).Permits(auth.ActUpdate, coll) && auth.Can(r.Context(), roles.Write)
		}}); res != nil {
		out := map[string]any{"commit": res.Commit}
		if res.PullRequest {
			out["pullRequest"] = true
		}
		if len(res.Cleared) > 0 {
			out["cleared"] = res.Cleared
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// Exports --------------------------------------------------------------------

func (s *server) baseURL(r *http.Request) string {
	if s.o.BaseURL != "" {
		return strings.TrimRight(s.o.BaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p == "https" || p == "http" {
		scheme = p
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return scheme + "://" + host
}

func writeText(w http.ResponseWriter, contentType, text string) {
	w.Header().Set("Content-Type", contentType)
	io.WriteString(w, text)
}

func (s *server) exportMD(w http.ResponseWriter, r *http.Request) {
	writeText(w, "text/markdown; charset=utf-8", export.Markdown(s.o.Store.Ledger()))
}

func (s *server) llmsFull(w http.ResponseWriter, r *http.Request) {
	writeText(w, "text/plain; charset=utf-8", export.Markdown(s.o.Store.Ledger()))
}

func (s *server) llms(w http.ResponseWriter, r *http.Request) {
	writeText(w, "text/plain; charset=utf-8", export.LLMS(s.o.Store.Ledger(), s.baseURL(r)))
}

func (s *server) exportJSON(w http.ResponseWriter, r *http.Request) {
	b, err := export.JSON(s.o.Store.Ledger())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(b)
}

// Console ---------------------------------------------------------------------

const notBuilt = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rackbook</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#222}
@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}a{color:#8ab4f8}}code{background:#8882;padding:.1em .3em;border-radius:3px}</style>
</head><body>
<h1>Rackbook</h1>
<p>The web console is not built into this binary.</p>
<p>Build it with <code>make build</code> (or <code>npm --prefix web ci &amp;&amp; npm --prefix web run build</code>, then <code>go build ./cmd/rackbook</code>).</p>
<p>The API is up: <a href="/api/meta">/api/meta</a>, <a href="/api/check">/api/check</a>, <a href="/llms.txt">/llms.txt</a>, <a href="/export.md">/export.md</a>.</p>
</body></html>
`

func (s *server) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	web := s.o.Web
	index, err := readIndex(web)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, notBuilt)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name != "" && name != "index.html" {
		if st, err := fs.Stat(web, name); err == nil && !st.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFileFS(w, r, web, name)
			return
		}
		if path.Ext(name) != "" && strings.HasPrefix(name, "assets/") {
			// A chunk from an older build: never let a proxy cache the miss.
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(index)
}

func readIndex(web fs.FS) ([]byte, error) {
	if web == nil {
		return nil, fs.ErrNotExist
	}
	b, err := fs.ReadFile(web, "index.html")
	if err == nil && len(bytes.TrimSpace(b)) == 0 {
		return nil, fs.ErrNotExist
	}
	return b, err
}
