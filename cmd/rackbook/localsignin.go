package main

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/localauth"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/rolesedit"
	"github.com/kazuhahub/rackbook/internal/routes"
)

// mounts is the built-in login and the sign-in of local accounts mounted as one.
type mounts []interface {
	Mount(mux routes.Mux, static http.Handler)
}

func (m mounts) Mount(mux routes.Mux, static http.Handler) {
	for _, x := range m {
		x.Mount(mux, static)
	}
}

// grantAdmin commits local:<username> to auth.roles.admin, for `rackbook accounts recover --grant-admin` against a running
// server: the same commit the role editor makes, from the command line (it has no session to lock out).
func grantAdmin(store *gitstore.Store, local *accounts.Store) func(ctx context.Context, username, operator string) error {
	return func(ctx context.Context, username, operator string) error {
		who := &auth.Identity{ID: "cli:" + operator, Name: operator, Method: auth.MethodCLI}
		entry := roles.LocalPrefix + username
		_, err := store.WriteFunc(ctx, func(cfg *config.Config) (*edit.Result, error) {
			cur, explicit := rolesedit.Current(cfg)
			if !explicit {
				return nil, rolesedit.ErrNoRolesBlock
			}
			next := cur
			if slices.Contains(next.Admin, entry) {
				return &edit.Result{}, nil
			}
			next.Admin = append(slices.Clone(cur.Admin), entry)
			l := rolesedit.Local{Available: true, States: map[string]string{}}
			for _, a := range local.Roster() {
				l.States[a.Username] = a.State
			}
			return rolesedit.Apply(cfg, rolesedit.Request{Version: rolesedit.Version(cur), Lists: next, Local: l, Message: "roles: grant admin to " + entry + " (accounts recover)"})
		}, who, gitstore.WriteOptions{})
		if err != nil {
			var rf *rolesedit.Refusal
			if errors.As(err, &rf) {
				return rf
			}
			return err
		}
		return nil
	}
}

// ssoOnlyRoster is the role editor's view of local accounts, with whether sso_only is in force.
type ssoOnlyRoster struct {
	rosterOf
	svc *localauth.Service
}

func (r ssoOnlyRoster) SSOOnlyInForce() bool { return r.svc != nil && r.svc.SSOOnlyInForce() }
