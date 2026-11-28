package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/localauth"
	"github.com/kazuhahub/rackbook/internal/statekey"
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

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	c := exec.Command("git", append([]string{"-C", dir}, args...)...)
	c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.org")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// dataRepo is a data repository with an origin; its write mode is the given one once the tokens exist (they are made under push).
type dataRepo struct {
	dir, bare, cfg string
}

func newDataRepo(t *testing.T) *dataRepo {
	t.Helper()
	dir := testutil.CopyExample(t)
	bare := t.TempDir()
	gitRun(t, bare, "init", "--bare", "-b", "main")
	gitRun(t, dir, "init", "-b", "main")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-m", "seed")
	gitRun(t, dir, "remote", "add", "origin", bare)
	gitRun(t, dir, "push", "-u", "origin", "main")
	return &dataRepo{dir: dir, bare: bare, cfg: filepath.Join(dir, "rackbook.yml")}
}

func (r *dataRepo) open(t *testing.T) *gitstore.Store {
	t.Helper()
	st, err := gitstore.Open(context.Background(), gitstore.Options{ConfigPath: r.cfg, Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The adapter finds the tokens a local account created (by creator and by how it signed in) and gives their ids; another
// person's token and a look-alike from single sign-on are left alone.
func TestAccountRevokerFindsTheTokensOfALocalIdentity(t *testing.T) {
	r := newDataRepo(t)
	reg := &tokens.Registry{Store: r.open(t)}
	ctx := context.Background()
	mk := func(name, by, via string) string {
		c, err := reg.Create(ctx, tokens.CreateParams{Name: name, Scope: tokens.ScopeRead}, &auth.Identity{ID: by, Name: by, Method: via})
		if err != nil {
			t.Fatal(err)
		}
		return c.Secret
	}
	mk("ci", "local:alice", auth.MethodLocal)
	mk("ci2", "local:alice", auth.MethodLocal)
	mk("theirs", "local:bob", auth.MethodLocal)
	mk("sso", "local:alice", auth.MethodOIDC)
	g := &fakeGrants{by: map[string][]string{"local:alice": {"g1", "g2"}}}
	rv := accountRevoker{registry: reg, grants: g}
	names, grants, err := rv.Owned("alice")
	if err != nil || len(names) != 2 || len(grants) != 2 {
		t.Fatalf("%v %v %v", names, grants, err)
	}
	ids, err := rv.TokenIDs(names)
	if err != nil || len(ids) != 2 || len(ids["ci"]) != 64 {
		t.Fatalf("%v %v", ids, err)
	}
}

// Reset an account that owns a token and a grant, set it up again, and probe: both are refused, in a deployment that commits
// directly, in one whose write mode is pr, and when the push of the record fails. The block is the store's list, so it does not
// matter what Git does; the record in tokens.yml is made directly (a pull request nobody merges would leave it alive) and is retried.
func TestRevocationEndToEndInEveryWriteModeAndWithAFailingPush(t *testing.T) {
	for _, c := range []struct {
		name     string
		mode     string
		failPush bool
	}{{"push", "push", false}, {"pr", "pr", false}, {"push fails", "push", true}, {"pr and push fails", "pr", true}} {
		t.Run(c.name, func(t *testing.T) {
			repo := newDataRepo(t)
			ctx := context.Background()
			// the tokens are made under write.mode push, then the mode is switched
			reg0 := &tokens.Registry{Store: repo.open(t)}
			who := &auth.Identity{ID: "local:alice", Name: "Alice", Method: auth.MethodLocal}
			created, err := reg0.Create(ctx, tokens.CreateParams{Name: "ci", Scope: tokens.ScopeRead}, who)
			if err != nil {
				t.Fatal(err)
			}
			other, err := reg0.Create(ctx, tokens.CreateParams{Name: "bobs", Scope: tokens.ScopeRead}, &auth.Identity{ID: "local:bob", Name: "Bob", Method: auth.MethodLocal})
			if err != nil {
				t.Fatal(err)
			}
			if c.mode == "pr" {
				testutil.Replace(t, repo.dir, "rackbook.yml", "mode: push", "mode: pr")
				gitRun(t, repo.dir, "commit", "-am", "write.mode pr")
				gitRun(t, repo.dir, "push", "origin", "main")
			}
			if c.failPush {
				hook := filepath.Join(repo.bare, "hooks", "pre-receive")
				if err := os.WriteFile(hook, []byte("#!/bin/sh\necho refused >&2\nexit 1\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			reg := &tokens.Registry{Store: repo.open(t)}

			// the account store, and a local account that owns the token
			key, _ := statekey.GenerateKey()
			state := t.TempDir()
			log, err := audit.Open(filepath.Join(state, "audit"), audit.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			st, err := accounts.Open(accounts.Options{StateDir: state, Key: key, Log: log})
			if err != nil {
				t.Fatal(err)
			}
			reg.Blocked = func(tk tokens.Token) bool { return tokenRevoked(st, tk) }
			hasher := accounts.NewHasherCost(accounts.NewSlots(3, 5*time.Second), 64, 1, 1)
			setup := func(tok string) {
				t.Helper()
				_, hold, _ := accounts.NewHold()
				if _, _, err := st.OpenLink(tok, hold, "", time.Now()); err != nil {
					t.Fatal(err)
				}
				sec, _ := accounts.NewTOTPSecret()
				fac, err := accounts.NewTOTPFactor(sec, accounts.TOTPCode(sec, accounts.TOTPStep(time.Now())), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				pw, _ := hasher.Hash(ctx, accounts.ClassNormal, "correct horse battery staple")
				if _, err := st.CompleteSetup(accounts.Setup{Token: tok, Holder: hold, Password: pw, TOTP: fac, Factor: "totp"}, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			tok, err := st.Invite(accounts.CLI("t"), "alice", "Alice", 72*time.Hour, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			_, hold, _ := accounts.NewHold()
			_ = hold
			setup(tok)

			// a grant, which the real OAuth server refuses on the same list (its own test), is represented by its id here
			grants := &fakeGrants{by: map[string][]string{"local:alice": {"grant-1"}}}
			rv := accountRevoker{registry: reg, grants: grants}
			if _, err := reg.Lookup(created.Secret); err != nil {
				t.Fatalf("the token works before: %v", err)
			}
			env := localauth.AdminEnv{Store: st, BaseURL: "https://ledger.example.com", Revoker: rv,
				InviteTTL: func() time.Duration { return 72 * time.Hour }, ResetTTL: func() time.Duration { return 24 * time.Hour }}
			// the reset records the revocations and applies them: refused from this moment, and nothing waited for git
			resp := env.Do(localauth.AdminRequest{Cmd: "reset", Username: "alice", Scope: "all", Operator: "ops"})
			if !resp.OK || len(resp.Links) != 1 {
				t.Fatalf("%+v", resp)
			}
			link := strings.SplitN(resp.Links[0].URL, "#", 2)[1]
			setup(link) // set up again
			if _, err := reg.Lookup(created.Secret); err == nil {
				t.Fatal("the old token was accepted after the reset and the setup")
			}
			if _, err := reg.Lookup(other.Secret); err != nil {
				t.Fatalf("another account's token was refused: %v", err)
			}
			if !st.IsRevoked(accounts.KindGrant, "grant-1") {
				t.Fatal("the old grant is not on the revocation list the OAuth server consults")
			}
			if a := st.Lookup("alice"); a.State != accounts.StateActive || !a.PendingRevocations.Empty() {
				t.Fatalf("%+v", a)
			}
			// the record layer: made with a direct commit, or failing and retried; either way the token stays refused
			err = localauth.RecordRevoked(ctx, st, rv)
			ts, _ := reg.List()
			recorded := false
			for _, tk := range ts {
				if tk.Name == "ci" {
					recorded = tk.Revoked != ""
				}
			}
			if c.failPush {
				if err == nil {
					t.Fatal("the push was refused and the record layer said nothing")
				}
			} else if err != nil || !recorded {
				t.Fatalf("the record in tokens.yml: err=%v recorded=%v", err, recorded)
			}
			if _, err := reg.Lookup(created.Secret); err == nil {
				t.Fatal("the old token was accepted after the record layer ran")
			}
		})
	}
}

// activeAccount makes a local account with a password and a second factor in a fresh account store.
func activeAccount(t *testing.T, name string) (*accounts.Store, func()) {
	t.Helper()
	key, _ := statekey.GenerateKey()
	state := t.TempDir()
	log, err := audit.Open(filepath.Join(state, "audit"), audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	st, err := accounts.Open(accounts.Options{StateDir: state, Key: key, Log: log})
	if err != nil {
		log.Close()
		t.Fatal(err)
	}
	tok, err := st.Invite(accounts.CLI("t"), name, name, 72*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, hold, _ := accounts.NewHold()
	if _, _, err := st.OpenLink(tok, hold, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	sec, _ := accounts.NewTOTPSecret()
	fac, err := accounts.NewTOTPFactor(sec, accounts.TOTPCode(sec, accounts.TOTPStep(time.Now())), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := accounts.NewHasherCost(accounts.NewSlots(3, 5*time.Second), 64, 1, 1).Hash(context.Background(), accounts.ClassNormal, "correct horse battery staple")
	if _, err := st.CompleteSetup(accounts.Setup{Token: tok, Holder: hold, Password: pw, TOTP: fac, Factor: "totp"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return st, log.Close
}

// The explicit list is made from the checkout, so it misses a token that is not in it yet: one waiting in a pull request (write mode
// pr), or one whose create is waiting on the Git lock (push). The standing rule catches it: its creation time is before its creator's
// credentials_valid_after, whenever it appears.
func TestCredentialsValidAfterCatchesTokensThatAreNotInTheCheckoutYet(t *testing.T) {
	ctx := context.Background()
	who := &auth.Identity{ID: "local:alice", Name: "Alice", Method: auth.MethodLocal}
	later := func(d time.Duration) time.Time { return time.Now().Add(d) }

	t.Run("a pull request merged after the disable", func(t *testing.T) {
		repo := newDataRepo(t)
		testutil.Replace(t, repo.dir, "rackbook.yml", "mode: push", "mode: pr")
		gitRun(t, repo.dir, "commit", "-am", "write.mode pr")
		gitRun(t, repo.dir, "push", "origin", "main")
		reg := &tokens.Registry{Store: repo.open(t)}
		st, closeLog := activeAccount(t, "alice")
		defer closeLog()
		reg.Blocked = func(tk tokens.Token) bool { return tokenRevoked(st, tk) }
		// the token exists only in a pull request: it is not in tokens.yml, so no list made now can name it
		secret, _ := tokens.Generate()
		pending := tokens.Token{Name: "in-a-pr", ShownPrefix: tokens.ShownPrefix(secret), Hash: tokens.HashSecret(secret), Scope: tokens.ScopeRead,
			CreatedBy: "local:alice", CreatedVia: auth.MethodLocal, Created: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
		env := localauth.AdminEnv{Store: st, Revoker: accountRevoker{registry: reg}, BaseURL: "https://x.example",
			InviteTTL: func() time.Duration { return 72 * time.Hour }, ResetTTL: func() time.Duration { return 24 * time.Hour }}
		time.Sleep(1100 * time.Millisecond)
		if r := env.Do(localauth.AdminRequest{Cmd: "disable", Username: "alice", Operator: "ops"}); !r.OK {
			t.Fatalf("%+v", r)
		}
		if names, _, _ := (accountRevoker{registry: reg}).Owned("alice"); len(names) != 0 {
			t.Fatalf("the list could not have named it: %v", names)
		}
		// the pull request is merged, and the account is brought back
		if _, err := reg.Store.MutateStateFile(ctx, tokens.File, "merge the pull request", who, func(old []byte, _ bool) ([]byte, error) {
			ts, err := tokens.Parse(old)
			if err != nil {
				return nil, err
			}
			return tokens.Marshal(append(ts, pending))
		}, gitstore.Direct()); err != nil {
			t.Fatal(err)
		}
		if r := env.Do(localauth.AdminRequest{Cmd: "enable", Username: "alice", Operator: "ops"}); !r.OK {
			t.Fatalf("%+v", r)
		}
		if _, err := reg.Lookup(secret); err == nil {
			t.Fatal("a token that was waiting in a pull request came alive with the account")
		}
		// a token the account makes after that is its own
		s2, _ := tokens.Generate()
		fresh := tokens.Token{Name: "fresh", ShownPrefix: tokens.ShownPrefix(s2), Hash: tokens.HashSecret(s2), Scope: tokens.ScopeRead,
			CreatedBy: "local:alice", CreatedVia: auth.MethodLocal, Created: later(2 * time.Second).UTC().Truncate(time.Second).Format(time.RFC3339)}
		if _, err := reg.Store.MutateStateFile(ctx, tokens.File, "a later token", who, func(old []byte, _ bool) ([]byte, error) {
			ts, _ := tokens.Parse(old)
			return tokens.Marshal(append(ts, fresh))
		}, gitstore.Direct()); err != nil {
			t.Fatal(err)
		}
		if _, err := reg.Lookup(s2); err != nil {
			t.Fatalf("a token made after the revocation was refused: %v", err)
		}
		// the console lists the first one as revoked, not active
		ts, _ := reg.Listed()
		for _, tk := range ts {
			if tk.Name == "in-a-pr" && tk.Revoked == "" {
				t.Fatal("listed as active")
			}
			if tk.Name == "fresh" && tk.Revoked != "" {
				t.Fatal("a good token listed as revoked")
			}
		}
		raw, _ := reg.List()
		for _, tk := range raw {
			if tk.Name == "in-a-pr" && tk.Revoked != "" {
				t.Fatal("the record layer must still see it as not revoked in the file")
			}
		}
	})

	t.Run("a create waiting on the git lock", func(t *testing.T) {
		repo := newDataRepo(t)
		store := repo.open(t)
		reg := &tokens.Registry{Store: store}
		st, closeLog := activeAccount(t, "alice")
		defer closeLog()
		reg.Blocked = func(tk tokens.Token) bool { return tokenRevoked(st, tk) }
		// a write holds the store's lock
		release, held := make(chan struct{}), make(chan struct{})
		go func() {
			_, _ = store.WriteFunc(ctx, func(*config.Config) (*edit.Result, error) {
				close(held)
				<-release
				return &edit.Result{}, nil
			}, who, gitstore.WriteOptions{})
		}()
		<-held
		var created *tokens.Created
		done := make(chan error, 1)
		go func() {
			var err error
			created, err = reg.Create(ctx, tokens.CreateParams{Name: "waiting", Scope: tokens.ScopeRead}, who)
			done <- err
		}()
		time.Sleep(1200 * time.Millisecond) // the create has its creation time and waits for the lock
		env := localauth.AdminEnv{Store: st, Revoker: accountRevoker{registry: reg}, BaseURL: "https://x.example",
			InviteTTL: func() time.Duration { return 72 * time.Hour }, ResetTTL: func() time.Duration { return 24 * time.Hour }}
		if r := env.Do(localauth.AdminRequest{Cmd: "reset", Username: "alice", Scope: "all", Operator: "ops"}); !r.OK {
			t.Fatalf("%+v", r)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if _, err := reg.Lookup(created.Secret); err == nil {
			t.Fatal("a token whose create was waiting on the git lock is live after the reset")
		}
	})
}
