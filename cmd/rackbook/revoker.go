package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
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

// TokenIDs gives each name its token's id: the SHA-256 of the secret that tokens.yml keeps.
func (r accountRevoker) TokenIDs(names []string) (map[string]string, error) {
	ts, err := r.registry.List()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, t := range ts {
		if slices.Contains(names, t.Name) {
			out[t.Name] = t.Hash
		}
	}
	return out, nil
}

// RecordTokens is the record layer: it revokes in tokens.yml the tokens with these ids that are not revoked there yet. It is a
// direct commit to the tracked branch even in write.mode pr (the passkeys of single sign-on do the same: this is Rackbook's own
// state, not ledger data, and a pull request nobody merges would leave the token alive in the record). A commit or a push that
// fails is returned and retried; the revocation list already blocks the token.
func (r accountRevoker) RecordTokens(ctx context.Context, ids []string) error {
	ts, err := r.registry.List()
	if err != nil {
		return err
	}
	var first error
	for _, t := range ts {
		if t.Revoked != "" || !slices.Contains(ids, t.Hash) {
			continue
		}
		if _, err := r.registry.Revoke(ctx, t.Name, revokerWho, gitstore.Direct()); err != nil && !errors.Is(err, tokens.ErrMissing) && first == nil {
			first = err
		}
	}
	return first
}

func (r accountRevoker) RevokeGrant(_ context.Context, id string) error {
	if r.grants == nil {
		return nil
	}
	return r.grants.RevokeGrant(id, "revoked with the local account")
}

// tokenRevoked is the registry's block for local accounts: the token is on the store's revocation list, or its creator is a local
// account whose credentials were revoked after the token was made. The second rule is what catches a token that was not in the
// checkout when the list was made (a pull request not merged yet, a create waiting on the Git lock). Its creation time is the one
// Rackbook wrote into tokens.yml when it made the token.
func tokenRevoked(st *accounts.Store, t tokens.Token) bool {
	if st.IsRevoked(accounts.KindToken, t.Hash) {
		return true
	}
	if t.CreatedVia != auth.MethodLocal {
		return false
	}
	name, ok := roles.LocalUsername(t.CreatedBy)
	return ok && st.Refuses(name, tokens.ParseTime(t.Created))
}

// grantRevoked is the OAuth server's block: the grant is on the list, or the local account that approved it has had its credentials
// revoked since. The approval time is the server's own.
func grantRevoked(st *accounts.Store, id, subject string, approved time.Time) bool {
	if st.IsRevoked(accounts.KindGrant, id) {
		return true
	}
	name, ok := roles.LocalUsername(subject)
	return ok && st.Refuses(name, approved)
}
