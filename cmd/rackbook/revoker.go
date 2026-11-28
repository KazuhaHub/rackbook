package main

import (
	"context"
	"errors"
	"strings"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

// accountRevoker revokes what a local account owns outside the account store (design-local-accounts.md, 5.11): the API tokens
// it created, which is a commit to .rackbook/tokens.yml through the normal path, and the OAuth grants it approved in the
// built-in authorization server.
type accountRevoker struct {
	registry *tokens.Registry
	grants   interface {
		GrantsOf(identity string) []string
		RevokeGrant(id, reason string) error
	}
}

// who is the identity of the commits and log lines: Rackbook acting on its own.
var revokerWho = &auth.Identity{ID: "rackbook-account-revocation", Name: "Rackbook", Method: auth.MethodSystem}

func (r accountRevoker) Owned(username string) (names, grantIDs []string, err error) {
	id := roles.LocalPrefix + username
	ts, err := r.registry.List()
	if err != nil {
		return nil, nil, err
	}
	for _, t := range ts {
		if strings.EqualFold(t.CreatedBy, id) && t.CreatedVia == auth.MethodLocal && t.Revoked == "" {
			names = append(names, t.Name)
		}
	}
	if r.grants != nil {
		grantIDs = r.grants.GrantsOf(id)
	}
	return names, grantIDs, nil
}

func (r accountRevoker) RevokeToken(ctx context.Context, name string) error {
	_, err := r.registry.Revoke(ctx, name, revokerWho)
	if errors.Is(err, tokens.ErrMissing) {
		return nil // already gone
	}
	return err
}

func (r accountRevoker) RevokeGrant(_ context.Context, id string) error {
	if r.grants == nil {
		return nil
	}
	return r.grants.RevokeGrant(id, "revoked with the local account")
}
