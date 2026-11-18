package auth

import (
	"context"

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
	MethodToken            = "token"
	// MethodCLI marks commits made by the rackbook command line.
	MethodCLI = "cli"
)

// Identity is an authenticated caller. Authenticators build one per request
// and finish it with Authenticator.Evaluate, which sets Role from the config
// as it is now (a config reload on pull takes effect on the next request).
type Identity struct {
	ID     string // lowercased identity string: e-mail, UPN, MCPHub username, token name
	Name   string // display name
	Email  string // may be empty (MCPHub usernames, tokens)
	Method string // one of the Method constants
	Client string // e.g. the MCPHub OAuth client_id
	Groups []string

	// Scopes are the OAuth scopes (or token scopes) the credential carries;
	// ScopeLimited says the credential can be narrower than the user's role,
	// in which case Narrow decides how.
	Scopes       []string
	ScopeLimited bool

	// Role is the role granted by auth.roles. Do not use it for access
	// decisions; use EffectiveRole, Can or the package-level Can.
	Role roles.Role

	// Narrow lowers the role for this credential. It receives Role and
	// returns the role the credential may use; a result higher than the
	// input is ignored, so a scope can never widen a role.
	Narrow func(roles.Role) roles.Role
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

// Anonymous reports an identity without an ID (auth none, no --editor).
func (i *Identity) Anonymous() bool { return i == nil || i.ID == "" }

// Subject is the view of the identity that roles are matched against.
func (i *Identity) Subject() roles.Subject {
	return roles.Subject{ID: roles.FoldASCII(i.ID), Email: i.Email, Method: i.Method, Groups: i.Groups}
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
