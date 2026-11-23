package auth

import (
	"context"
	"time"

	"github.com/kazuhahub/rackbook/internal/roles"
)

// Authentication methods, as reported in Identity.Method and /api/meta
// user.authMethod.
const (
	MethodNone             = "none"
	MethodCloudflareAccess = "cloudflare-access"
	MethodOIDC             = "oidc"
	MethodPasskey          = "passkey"
	MethodMCPHub           = "mcphub"
	MethodOAuth            = "oauth" // access token of another trusted OAuth issuer
	MethodToken            = "token"
	// MethodCLI marks commits made by the rackbook command line.
	MethodCLI = "cli"
	// MethodSystem marks what Rackbook does by itself, with no person behind it: the daily
	// audit anchor's commit. No sign-in produces it.
	MethodSystem = "system"
)

// AnchorIdentity is the ID of that commit's identity. No sign-in may produce it: the OIDC and
// MCP paths refuse it as an identity.
const AnchorIdentity = "rackbook-audit-anchor"

// Identity is an authenticated caller. Authenticators build one per request
// and finish it with Authenticator.Evaluate, which sets Role from the config
// as it is now (a config reload on pull takes effect on the next request).
type Identity struct {
	ID     string // lowercased identity string: e-mail, UPN, MCPHub username, token name
	Name   string // display name
	Email  string // may be empty (MCPHub usernames, tokens)
	Method string // one of the Method constants
	Client string // e.g. the MCPHub OAuth client_id
	Issuer string // method oauth: alias of the trusted issuer
	Groups []string

	// OIDC sessions only: the issuer and client ID the login was made under
	// (the values of the running server at that moment) and when the person
	// last signed in. /infra checks them against its own pinned values.
	OIDCIssuer string
	OIDCClient string
	// OIDCClaim is the claim the identity was taken from ("sub" for a subject
	// identity) and OIDCTenant the ID token's tid, as the login established them.
	OIDCClaim  string
	OIDCTenant string
	OIDCAt     time.Time

	// Scopes are the OAuth scopes (or token scopes) the credential carries;
	// ScopeLimited says the credential can be narrower than the user's role,
	// in which case Narrow decides how.
	Scopes       []string
	ScopeLimited bool

	// Role is the role granted by auth.roles. Do not use it for access
	// decisions; use EffectiveRole, Can or the package-level Can.
	Role roles.Role

	// Auditor is the auditor capability (auth.auditors), evaluated for the same
	// subject as Role. It is not a role. Do not use it for access decisions;
	// use IsAuditor, which also honours scope narrowing.
	Auditor bool

	// Narrow lowers the role for this credential. It receives Role and
	// returns the role the credential may use; a result higher than the
	// input is ignored, so a scope can never widen a role.
	Narrow func(roles.Role) roles.Role

	// Via names the channel in the Edited-via trailer instead of the product
	// name ("mcp" for requests to /mcp). Empty = the product name.
	Via string
	// Token is the name of the Rackbook API token the request used ("" =
	// none). The identity is then the token's creator.
	Token string
	// Allow narrows writes to certain collections and actions (an API token's
	// collections/actions). action is create, update or delete. Nil = no
	// narrowing beyond the role.
	Allow func(action, collection string) bool
	// DirectPush says the credential may push create and update straight to the
	// tracked branch (a token granted write_mode push by a current admin).
	DirectPush bool
}

// Write actions as passed to Permits.
const (
	ActCreate = "create"
	ActUpdate = "update"
	ActDelete = "delete"
)

// Permits reports whether the credential's own narrowing (not the role) lets
// it perform action on collection.
func (i *Identity) Permits(action, collection string) bool {
	return i != nil && (i.Allow == nil || i.Allow(action, collection))
}

// EffectiveRole is Role after scope narrowing.
func (i *Identity) EffectiveRole() roles.Role {
	if i == nil {
		return roles.None
	}
	r := i.Role
	if i.Narrow != nil {
		r = roles.Lower(r, i.Narrow(r))
	}
	return r
}

// Can reports whether the identity may perform a. A nil identity may not.
func (i *Identity) Can(a roles.Action) bool { return i.EffectiveRole().Allows(a) }

// IsAuditor reports whether the credential carries the auditor capability: the
// subject is on auth.auditors and the credential may read at all (a scope that
// narrows the role to nothing takes the capability with it). An admin is an
// auditor only when listed. The capability adds reading the audit areas; it
// never allows a write.
func (i *Identity) IsAuditor() bool {
	return i != nil && i.Auditor && i.EffectiveRole() >= roles.Viewer
}

// IDOrEmpty is the identity's ID, or "" for a nil identity.
func (i *Identity) IDOrEmpty() string {
	if i == nil {
		return ""
	}
	return i.ID
}

// Anonymous reports an identity without an ID (auth none, no --editor).
func (i *Identity) Anonymous() bool { return i == nil || i.ID == "" }

// Subject is the view of the identity that roles are matched against.
func (i *Identity) Subject() roles.Subject {
	return roles.Subject{ID: roles.FoldASCII(i.ID), Email: i.Email, Method: i.Method, Issuer: i.Issuer, Groups: i.Groups}
}

type ctxKey struct{}

// WithIdentity stores id in ctx.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the identity stored by the middleware, or nil.
func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(ctxKey{}).(*Identity)
	return id
}

// Can reports whether the identity in ctx may perform a. Without an identity
// in the context nothing is allowed.
func Can(ctx context.Context, a roles.Action) bool { return FromContext(ctx).Can(a) }

// IsAuditor reports whether the identity in ctx carries the auditor capability.
func IsAuditor(ctx context.Context) bool { return FromContext(ctx).IsAuditor() }
