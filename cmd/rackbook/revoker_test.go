package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

type fakeGrants struct {
	by      map[string][]string
	revoked []string
}

func (f *fakeGrants) GrantsOf(id string) []string { return f.by[id] }
func (f *fakeGrants) RevokeGrant(id, _ string) error {
	f.revoked = append(f.revoked, id)
	return nil
}

// The adapter finds the tokens a local account created (by creator and by how it signed in) and revokes them by a commit through
// the registry, after which the token is refused; another person's token is left alone.
func TestAccountRevokerRevokesTheTokensOfALocalIdentity(t *testing.T) {
	cfg := filepath.Join(testutil.CopyExample(t), "rackbook.yml")
	st, err := gitstore.Open(context.Background(), gitstore.Options{ConfigPath: cfg, NoGit: true, Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	reg := &tokens.Registry{Store: st}
	ctx := context.Background()
	mk := func(name, by, via string) string {
		c, err := reg.Create(ctx, tokens.CreateParams{Name: name, Scope: tokens.ScopeRead}, &auth.Identity{ID: by, Name: by, Method: via})
		if err != nil {
			t.Fatal(err)
		}
		return c.Secret
	}
	old := mk("ci", "local:alice", auth.MethodLocal)
	second := mk("ci2", "local:alice", auth.MethodLocal)
	other := mk("theirs", "local:bob", auth.MethodLocal)
	sso := mk("sso", "local:alice", auth.MethodOIDC) // a look-alike name from single sign-on: not this account's
	g := &fakeGrants{by: map[string][]string{"local:alice": {"g1", "g2"}}}
	rv := accountRevoker{registry: reg, grants: g}
	names, grants, err := rv.Owned("alice")
	if err != nil || len(names) != 2 || len(grants) != 2 {
		t.Fatalf("%v %v %v", names, grants, err)
	}
	for _, n := range names {
		if err := rv.RevokeToken(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range grants {
		if err := rv.RevokeGrant(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{old, second} {
		if _, err := reg.Lookup(s); err == nil {
			t.Fatal("a revoked token was accepted")
		}
	}
	for _, s := range []string{other, sso} {
		if _, err := reg.Lookup(s); err != nil {
			t.Fatalf("a token of another identity was revoked: %v", err)
		}
	}
	if len(g.revoked) != 2 {
		t.Fatalf("%v", g.revoked)
	}
	// revoking again is not an error, and a name that never existed is not either
	if err := rv.RevokeToken(ctx, "ci"); err != nil {
		t.Fatalf("%v", err)
	}
	if err := rv.RevokeToken(ctx, "never-was"); err != nil {
		t.Fatalf("%v", err)
	}
	if names, _, _ := rv.Owned("alice"); len(names) != 0 {
		t.Fatalf("%v", names)
	}
}
