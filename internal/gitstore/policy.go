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
		direct = directPushListed(who, cfg.Auth.MCP.DirectPush, collection)
	}
	if direct {
		opts.ForcePR = false
	}
	return opts
}

func directPushListed(who *auth.Identity, rules []config.DirectPush, collection string) bool {
	id := roles.FoldASCII(who.ID)
	role := who.EffectiveRole().String()
	for _, r := range rules {
		onCollection := false
		for _, c := range r.Collections {
			onCollection = onCollection || c == "*" || c == collection
		}
		if !onCollection {
			continue
		}
		for _, u := range r.Users {
			u = roles.FoldASCII(strings.TrimSpace(u))
			if u == id || u == "mcphub:"+id || u == "oauth:"+roles.FoldASCII(who.Issuer)+":"+id {
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
