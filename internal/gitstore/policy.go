package gitstore

import (
	"strings"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// WriteOptionsFor decides how a write by who reaches the repository.
//
// Console users (any method but MCPHub and tokens) follow write.mode. A write
// made with an MCPHub access token or a Rackbook API token is contributor
// level: it opens a pull request (branch rackbook/mcp/<user>/<time> or
// rackbook/token/<name>/<time>), unless the credential may push directly and
// the change is a create or an update. Deletes are always a pull request.
//
// Direct push is granted to an MCPHub user by auth.mcp.direct_push (users or
// roles, plus the collection), and to a token by write_mode push, which only
// counts while its creator is still an admin (Identity.DirectPush).
func WriteOptionsFor(who *auth.Identity, cfg *config.Config, kind edit.Kind, collection string) WriteOptions {
	if who == nil {
		return WriteOptions{}
	}
	var opts WriteOptions
	switch who.Method {
	case auth.MethodMCPHub, auth.MethodOAuth:
		opts = WriteOptions{ForcePR: true, BranchPrefix: "rackbook/mcp/" + Slug(who.ID)}
	case auth.MethodToken:
		opts = WriteOptions{ForcePR: true, BranchPrefix: "rackbook/token/" + Slug(who.Token)}
	default:
		return WriteOptions{}
	}
	if kind == edit.Delete {
		return opts
	}
	direct := who.Method == auth.MethodToken && who.DirectPush
	if (who.Method == auth.MethodMCPHub || who.Method == auth.MethodOAuth) && cfg != nil {
		direct = directPushListed(who, cfg.Auth.MCP, collection)
	}
	if direct {
		opts.ForcePR = false
	}
	return opts
}

// MayConfirm says whether who may confirm "this is not a secret" on a write.
// Editors and OAuth/MCP identities with write rights may; an API token never
// may when its write becomes a pull request (a token is contributor level: no
// one reviews a confirmation made by a script). The role check has already
// happened.
func MayConfirm(who *auth.Identity, cfg *config.Config, kind edit.Kind, collection string) bool {
	if who == nil || who.Method != auth.MethodToken {
		return true
	}
	opts := WriteOptionsFor(who, cfg, kind, collection)
	pr := opts.ForcePR || (!opts.Direct && cfg != nil && cfg.Write.Mode == "pr")
	return !pr
}

// directPushListed matches by method: mcphub:<user> only an MCPHub identity,
// oauth:<alias>:<user> only that issuer's, an e-mail address only with
// match_email and a verified e-mail on the identity. Role names work for both.
func directPushListed(who *auth.Identity, m config.AuthMCP, collection string) bool {
	id := roles.FoldASCII(who.ID)
	role := who.EffectiveRole().String()
	for _, r := range m.DirectPush {
		onCollection := false
		for _, c := range r.Collections {
			onCollection = onCollection || c == "*" || c == collection
		}
		if !onCollection {
			continue
		}
		for _, u := range r.Users {
			u = roles.FoldASCII(strings.TrimSpace(u))
			switch {
			case strings.HasPrefix(u, "mcphub:"):
				if who.Method == auth.MethodMCPHub && u == "mcphub:"+id {
					return true
				}
			case strings.HasPrefix(u, "oauth:"):
				if who.Method == auth.MethodOAuth && u == "oauth:"+roles.FoldASCII(who.Issuer)+":"+id {
					return true
				}
			case m.MatchEmail && who.Email != "" && u == roles.FoldASCII(who.Email):
				return true
			}
		}
		for _, rr := range r.Roles {
			if rr == role {
				return true
			}
		}
	}
	return false
}
