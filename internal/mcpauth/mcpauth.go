// Package mcpauth makes /mcp an OAuth protected resource (RFC 9728) and
// authenticates the bearer credentials Rackbook accepts there: access tokens
// of the trusted OAuth issuers (MCPHub, Entra ID, Keycloak, ...) on /mcp only,
// and Rackbook API tokens (rbk_...) on /api, /mcp, /export.* and /llms*. It
// plugs into auth.Authenticator through auth.BearerAuthenticator.
package mcpauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	mcpsdkauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/auth/oauth"
	"github.com/kazuhahub/rackbook/internal/clientip"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/oauthserver"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

// Well-known paths of the protected resource metadata. RFC 9728 inserts the
// well-known segment before the resource's path, so /mcp is announced at the
// second; the first is what the WWW-Authenticate challenge names.
const (
	MetadataPath     = "/.well-known/oauth-protected-resource"
	MetadataPathMCP  = MetadataPath + "/mcp"
	mcpPath          = "/mcp"
	identityExtraKey = "identity"
)

// Resource authenticates bearer credentials.
type Resource struct {
	Config   func() *config.Config
	Auth     *auth.Authenticator
	Verifier *oauth.Verifier
	// Builtin is Rackbook's own authorization server (auth.mcp.builtin_issuer);
	// nil = none. Its tokens are checked in-process, never by fetching its
	// metadata over HTTP, so it is not a trusted_issuers entry.
	Builtin *oauthserver.Server
	Tokens  *tokens.Registry // nil = no API tokens
	Limiter *tokens.Limiter
	// TrustedProxies are the --trusted-proxy prefixes: CF-Connecting-IP is
	// believed only from them.
	TrustedProxies []netip.Prefix
	Log            *slog.Logger
}

func (r *Resource) mcp() config.AuthMCP { return r.Config().Auth.MCP }

// builtin returns the built-in authorization server when it is on.
func (r *Resource) builtin() *oauthserver.Server {
	if r.Builtin != nil && r.mcp().BuiltinIssuer.Enabled {
		return r.Builtin
	}
	return nil
}

// scopeChallenge is the scope parameter of a challenge: what the built-in
// server can grant, so a client asks for it.
func (r *Resource) scopeChallenge() string {
	if r.builtin() == nil {
		return ""
	}
	var scopes []string
	for _, s := range []string{r.mcp().Scopes.ReadScope(), r.mcp().Scopes.WriteScope()} {
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	return strings.Join(scopes, " ")
}

func (r *Resource) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

// IsMCPPath reports whether path is /mcp or below it.
func IsMCPPath(path string) bool { return path == mcpPath || strings.HasPrefix(path, mcpPath+"/") }

// tokenPath lists what an API token may reach: /mcp, record and collection
// reads and writes, exports and llms. Account, passkey, user and admin
// endpoints are for people (browser sessions) only.
func tokenPath(p string) bool {
	switch {
	case IsMCPPath(p):
		return true
	case strings.HasPrefix(p, "/api/c/"), p == "/api/meta", p == "/api/check", p == "/api/history", p == "/api/expiring", strings.HasPrefix(p, "/api/modules/"):
		return true
	}
	return strings.HasPrefix(p, "/export.") || strings.HasPrefix(p, "/llms")
}

// metadataURL is where the protected resource metadata is published: on the
// origin of auth.mcp.resource.
func (r *Resource) metadataURL() string {
	u, err := url.Parse(r.mcp().Resource)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + MetadataPath
}

// Challenge implements auth.BearerAuthenticator.
func (r *Resource) Challenge(req *http.Request) string {
	if !IsMCPPath(req.URL.Path) || !r.mcp().Enabled() {
		return ""
	}
	ch := fmt.Sprintf(`Bearer resource_metadata=%q`, r.metadataURL())
	if sc := r.scopeChallenge(); sc != "" {
		ch += fmt.Sprintf(`, scope=%q`, sc)
	}
	return ch
}

func (r *Resource) invalidToken(req *http.Request, reason string) *auth.RequestError {
	ch := `Bearer error="invalid_token"`
	if m := r.Challenge(req); m != "" {
		ch += ", " + strings.TrimPrefix(m, "Bearer ")
	}
	return &auth.RequestError{Status: http.StatusUnauthorized, Code: "invalid_token", Msg: "the access token is not valid", Challenge: ch}
}

// AuthenticateBearer implements auth.BearerAuthenticator.
func (r *Resource) AuthenticateBearer(req *http.Request) (*auth.Identity, error) {
	scheme, tok, ok := strings.Cut(req.Header.Get("Authorization"), " ")
	tok = strings.TrimSpace(tok)
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return nil, nil
	}
	if strings.HasPrefix(tok, tokens.Prefix) {
		if r.Tokens == nil {
			return nil, nil
		}
		if !tokenPath(req.URL.Path) {
			return nil, &auth.RequestError{Status: http.StatusForbidden, Code: "forbidden", Msg: "API tokens may not use this endpoint"}
		}
		return r.token(req, tok)
	}
	if IsMCPPath(req.URL.Path) && r.mcp().Enabled() {
		return r.accessToken(req, tok)
	}
	return nil, nil
}

// accessToken verifies an access token of a trusted issuer.
func (r *Resource) accessToken(req *http.Request, raw string) (*auth.Identity, error) {
	if b := r.builtin(); b != nil && b.IsOwn(raw) {
		return r.builtinToken(req, b, raw)
	}
	m := r.mcp()
	// Opaque tokens cost an introspection call per guess, so failures are
	// rate-limited per client like rbk_ tokens.
	opaque := oauth.IsOpaque(raw)
	var ip string
	if opaque && r.Limiter != nil {
		ip = clientip.Of(req, r.TrustedProxies)
		if blocked, wait := r.Limiter.Blocked(ip); blocked {
			return nil, &auth.RequestError{Status: http.StatusTooManyRequests, Code: "rate_limited", Msg: "too many failed token attempts, try again later", RetryAfter: wait}
		}
	}
	c, err := r.Verifier.Verify(req.Context(), raw, m)
	if errors.Is(err, oauth.ErrUnavailable) {
		r.log().Warn("mcp token introspection unavailable", "err", err.Error())
		return nil, &auth.RequestError{Status: http.StatusServiceUnavailable, Code: "introspection_unavailable", Msg: "the token cannot be checked right now, try again"}
	}
	if err != nil {
		if opaque && r.Limiter != nil {
			r.Limiter.Fail(ip)
		}
		r.log().Info("mcp access token refused", "reason", err.Error())
		return nil, r.invalidToken(req, err.Error())
	}
	user := roles.FoldASCII(strings.TrimSpace(c.Username))
	if user == "" {
		return nil, r.invalidToken(req, "empty user")
	}
	id := &auth.Identity{ID: user, Name: c.Username, Method: auth.MethodOAuth, Client: c.ClientID, Issuer: c.Alias,
		Scopes: c.Scopes, ScopeLimited: true, Via: "mcp"}
	if c.Kind == config.KindMCPHub {
		id.Method, id.Issuer = auth.MethodMCPHub, ""
	}
	// The e-mail is only what the issuer vouches for; a username that looks like
	// an address is not one (match_email uses Email and nothing else).
	id.Email = c.VerifiedEmail
	id.Narrow = narrowByScopes(m, c.Scopes)
	return r.Auth.Evaluate(id), nil
}

// narrowByScopes makes a scope only narrow the role, never widen it.
func narrowByScopes(m config.AuthMCP, scopes []string) func(roles.Role) roles.Role {
	readScope, writeScope := m.Scopes.ReadScope(), m.Scopes.WriteScope()
	have := map[string]bool{}
	for _, s := range scopes {
		have[s] = true
	}
	return func(role roles.Role) roles.Role {
		if readScope != "" && !have[readScope] {
			return roles.None
		}
		if writeScope != "" && !have[writeScope] {
			return roles.Lower(role, roles.Viewer)
		}
		return role
	}
}

// builtinToken verifies an access token of the built-in authorization server
// in-process, then evaluates the role of the person who approved the grant, as
// it is now. A person who no longer has a role gets 401: the grant is useless
// and the client has to authorize again (a refresh also ends it).
func (r *Resource) builtinToken(req *http.Request, b *oauthserver.Server, raw string) (*auth.Identity, error) {
	c, err := b.VerifyAccess(raw)
	if err != nil {
		r.log().Info("mcp access token refused", "reason", err.Error(), "issuer", "built-in")
		return nil, r.invalidToken(req, err.Error())
	}
	id := &auth.Identity{ID: roles.FoldASCII(c.Subject.ID), Name: c.Subject.Name, Email: c.Subject.Email, Method: auth.MethodOAuth,
		Client: c.ClientName, Issuer: config.BuiltinIssuerAlias, Scopes: c.Scopes, ScopeLimited: true, Via: "mcp", Groups: c.Subject.Groups}
	id.Narrow = narrowByScopes(r.mcp(), c.Scopes)
	// The role comes from the person's own login identity (their sign-in method
	// decides which role entries match), not from the OAuth method.
	r.Auth.EvaluateSubject(id, roles.Subject{ID: id.ID, Email: c.Subject.Email, Method: c.Subject.Method, Groups: c.Subject.Groups})
	if id.Role == roles.None {
		r.log().Info("mcp access token refused", "reason", "no role", "user", id.ID, "issuer", "built-in")
		return nil, r.invalidToken(req, "no role")
	}
	return id, nil
}

// token authenticates a Rackbook API token.
func (r *Resource) token(req *http.Request, secret string) (*auth.Identity, error) {
	ip := clientip.Of(req, r.TrustedProxies)
	if blocked, wait := r.Limiter.Blocked(ip); blocked {
		return nil, &auth.RequestError{Status: http.StatusTooManyRequests, Code: "rate_limited", Msg: "too many failed token attempts, try again later", RetryAfter: wait}
	}
	t, err := r.Tokens.Lookup(secret)
	if err != nil {
		r.Limiter.Fail(ip)
		r.log().Info("api token refused", "reason", err.Error(), "ip", ip)
		return nil, &auth.RequestError{Status: http.StatusUnauthorized, Code: "invalid_token", Msg: "the token is not valid", Challenge: `Bearer error="invalid_token"`}
	}
	r.Tokens.Touch(t.Name)
	id := &auth.Identity{ID: roles.FoldASCII(t.CreatedBy), Method: auth.MethodToken, Token: t.Name, ScopeLimited: true}
	if strings.Contains(t.CreatedBy, "@") {
		id.Email = t.CreatedBy
	}
	capRole, scopes := roles.Viewer, []string{tokens.ScopeRead}
	if t.Scope == tokens.ScopeWrite {
		capRole, scopes = roles.Editor, []string{tokens.ScopeRead, tokens.ScopeWrite}
	}
	id.Scopes = scopes
	// The token's role is its creator's role as it is now, capped by its scope.
	id.Narrow = func(role roles.Role) roles.Role { return roles.Lower(role, capRole) }
	r.Auth.EvaluateSubject(id, roles.Subject{ID: id.ID, Email: id.Email, Method: t.SubjectMethod()})
	cols, acts := t.Collections, t.Actions
	id.Allow = func(action, collection string) bool {
		if t.Scope != tokens.ScopeWrite {
			return false
		}
		return (len(acts) == 0 || contains(acts, action)) && (len(cols) == 0 || contains(cols, collection))
	}
	id.DirectPush = t.WriteMode == tokens.ModePush && id.Role == roles.Admin && len(cols) > 0
	return id, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// MetadataHandler serves the RFC 9728 document. It answers 404 until
// auth.mcp.trusted_issuers is configured.
func (r *Resource) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		m := r.mcp()
		if !m.Enabled() || req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.NotFound(w, req)
			return
		}
		var issuers, scopes []string
		if b := r.builtin(); b != nil {
			issuers = append(issuers, b.Issuer())
		}
		for _, t := range m.TrustedIssuers {
			issuers = append(issuers, t.Issuer)
		}
		for _, s := range []string{m.Scopes.ReadScope(), m.Scopes.WriteScope()} {
			if s != "" {
				scopes = append(scopes, s)
			}
		}
		doc := map[string]any{
			"resource":                 m.Resource,
			"authorization_servers":    issuers,
			"bearer_methods_supported": []string{"header"},
		}
		if len(scopes) > 0 {
			doc["scopes_supported"] = scopes
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		writeJSON(w, doc)
	})
}

// Handler wraps the /mcp handler: it marks the request's identity as arriving
// through MCP (the Edited-via trailer says "mcp") and hands it to the tool
// handlers through the SDK's token info, which also binds each MCP session to
// the user who opened it.
func Handler(next http.Handler) http.Handler {
	verify := func(ctx contextT, _ string, req *http.Request) (*mcpsdkauth.TokenInfo, error) {
		id := auth.FromContext(req.Context())
		if id == nil {
			return nil, mcpsdkauth.ErrInvalidToken
		}
		ti := &mcpsdkauth.TokenInfo{Expiration: time.Now().Add(time.Hour), Scopes: id.Scopes, Extra: map[string]any{identityExtraKey: id}}
		if id.ID != "" {
			ti.UserID = id.Method + ":" + id.Issuer + ":" + id.ID
		}
		return ti, nil
	}
	wrapped := mcpsdkauth.RequireBearerToken(verify, nil)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if id := auth.FromContext(req.Context()); id != nil {
			c := *id
			c.Via = "mcp"
			req = req.WithContext(auth.WithIdentity(req.Context(), &c))
		}
		if req.Header.Get("Authorization") == "" {
			// The SDK middleware wants a bearer header; the identity is already
			// authenticated, so give it a placeholder.
			req = req.Clone(req.Context())
			req.Header.Set("Authorization", "Bearer -")
		}
		wrapped.ServeHTTP(w, req)
	})
}

// IdentityFrom returns the identity Handler stored for an MCP request, or nil
// (a stdio session has none).
func IdentityFrom(ti *mcpsdkauth.TokenInfo) *auth.Identity {
	if ti == nil {
		return nil
	}
	id, _ := ti.Extra[identityExtraKey].(*auth.Identity)
	return id
}
