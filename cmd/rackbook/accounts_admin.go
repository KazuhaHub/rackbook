package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/localauth"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// The commands of local accounts that change accounts (docs/design-local-accounts.md, 11.2): invite, reset, unlock, disable,
// enable, remove, end-sessions and recover. With the server running they go over the admin channel, authenticated and
// sealed under the state key; with the server stopped they take the state directory's lock and work on the files
// directly. The behaviour and the output are the same. A link is printed to this terminal only, never to a log, and never
// takes a password: a person sets their own at the link.

func operatorOf(cmd *cobra.Command) string {
	op, _ := cmd.Flags().GetString("operator")
	if strings.TrimSpace(op) == "" {
		if u, err := user.Current(); err == nil {
			op = u.Username
		}
	}
	if strings.TrimSpace(op) == "" {
		op = "unknown"
	}
	return op
}

// runAdmin sends the command to the running server, or runs it on the files when no server answers.
func runAdmin(cmd *cobra.Command, req localauth.AdminRequest) error {
	dir, key, err := stateAndKey(cmd)
	if err != nil {
		return err
	}
	defer key.Zero()
	req.Operator = operatorOf(cmd)
	if msg := confirmText(req); msg != "" {
		if yes, _ := cmd.Flags().GetBool("yes"); !yes {
			ok, err := confirm(cmd, msg+" Type yes to go on: ")
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("not confirmed: nothing was changed")
			}
		}
	}
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	c, err := localauth.DialAdmin(ctx, dir, key)
	switch {
	case err == nil:
		defer c.Close()
		resp, err := c.Do(req)
		if err != nil {
			return fmt.Errorf("the server's admin channel: %w", err)
		}
		return report(out, resp)
	case !errors.Is(err, localauth.ErrNoServer):
		return fmt.Errorf("the server's admin channel: %w", err)
	}
	// no server: the files
	key.Zero()
	off, done, err := offlineSession(cmd)
	if err != nil {
		return err
	}
	defer done()
	st, err := off.OpenStore()
	if err != nil {
		var se *accounts.StartError
		if errors.As(err, &se) {
			return fmt.Errorf("the account store does not start: %s: %s", se.Code, se.Msg)
		}
		return err
	}
	base, _ := cmd.Flags().GetString("base-url")
	guard, err := offlineGuard(cmd)
	if err != nil {
		return err
	}
	env := localauth.AdminEnv{Guard: guard,
		Store: st, BaseURL: base,
		InviteTTL: func() time.Duration { return durationFlag(cmd, "invite-ttl", 72*time.Hour) },
		ResetTTL:  func() time.Duration { return durationFlag(cmd, "reset-ttl", 24*time.Hour) },
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "the server is not running: working on the files in --state-dir directly")
	return report(out, env.Do(req))
}

// confirmText says what a command that is hard to undo does, for the confirmation it asks for (--yes skips it).
func confirmText(req localauth.AdminRequest) string {
	switch {
	case req.Cmd == "remove":
		return "This removes " + req.Username + ": its credentials are deleted and its sessions end, and the name can never be used again."
	case req.Cmd == "disable":
		return "This disables " + req.Username + ": its sessions end at once and its API tokens and app connections are revoked."
	case req.Cmd == "reset" && req.All:
		return "This resets EVERY account: all sessions end, every API token and app connection is revoked, and each person must use a new link."
	}
	return ""
}

// offlineGuard is the last-administrator guard of 5.9 for the command line with the server stopped. It needs rackbook.yml
// (--config) to know whether sso_only is in force and who holds the admin role; without it the guard cannot be checked, and the
// command says so.
func offlineGuard(cmd *cobra.Command) (func(*accounts.State, string) error, error) {
	if cmd.Flags().Lookup("config") == nil {
		return nil, nil
	}
	path, _ := cmd.Flags().GetString("config")
	if path == "" {
		if c := cmd.Name(); c == "disable" || c == "remove" {
			fmt.Fprintln(cmd.ErrOrStderr(), "note: without --config the sso_only guard (the last local administrator cannot be disabled or removed) is not checked")
		}
		return nil, nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	pol, err := roles.CompileAuditors(cfg.Auth.Roles, cfg.Auth.Auditors, roles.Options{MCPMatchEmail: cfg.Auth.MCP.MatchEmail}, cfg.Auth.Editors...)
	if err != nil {
		return nil, err
	}
	isAdmin := func(u string) bool {
		return pol.Evaluate(roles.Subject{ID: roles.LocalPrefix + u, Method: roles.MethodLocal}) == roles.Admin
	}
	ssoOnly := func() bool { return cfg.Auth.SignInSettings().SSOOnlyConfigured(ssoConfigured(cfg)) }
	return localauth.LastAdminGuard(ssoOnly, isAdmin), nil
}

func durationFlag(cmd *cobra.Command, name string, def time.Duration) time.Duration {
	if cmd.Flags().Lookup(name) == nil {
		return def
	}
	d, _ := cmd.Flags().GetDuration(name)
	if d <= 0 {
		return def
	}
	return d
}

func report(out io.Writer, r localauth.AdminResponse) error {
	for _, l := range r.Links {
		what := "invite link"
		if l.Kind == "reset" {
			what = "reset link (scope " + l.Scope + ")"
		}
		fmt.Fprintf(out, "%s for %s, valid until %s:\n  %s\n", what, l.Username, l.Expires, l.URL)
	}
	for _, l := range r.Lines {
		fmt.Fprintln(out, l)
	}
	if !r.OK {
		msg := r.Error
		if msg == "" {
			msg = "some accounts could not be changed"
		}
		return errors.New(msg)
	}
	if len(r.Links) > 0 {
		fmt.Fprintln(out, "Give the link to the person yourself. It works once, in one browser; Rackbook does not send it anywhere and does not keep it.")
	}
	return nil
}

func newAdminCommands() []*cobra.Command {
	var out []*cobra.Command
	add := func(use, short string, args cobra.PositionalArgs, build func(cmd *cobra.Command, args []string) localauth.AdminRequest, flags func(*cobra.Command)) {
		c := &cobra.Command{Use: use, Short: short, Args: args}
		c.RunE = func(cmd *cobra.Command, a []string) error { return runAdmin(cmd, build(cmd, a)) }
		c.Flags().String("base-url", "", "the public https URL of the console, for the full link when the server is not running")
		if use := strings.Fields(use)[0]; use == "disable" || use == "remove" || use == "reset" {
			c.Flags().Bool("yes", false, "do not ask for confirmation")
		}
		if use := strings.Fields(use)[0]; use == "disable" || use == "remove" {
			c.Flags().String("config", "", "rackbook.yml, to apply the sso_only guard (the last local administrator) when the server is not running")
		}
		if flags != nil {
			flags(c)
		}
		out = append(out, c)
	}
	add("invite <username>", "Invite a person: make the account and print the one-time setup link", cobra.ExactArgs(1),
		func(cmd *cobra.Command, a []string) localauth.AdminRequest {
			n, _ := cmd.Flags().GetString("name")
			return localauth.AdminRequest{Cmd: "invite", Username: a[0], Name: n}
		}, func(c *cobra.Command) {
			c.Flags().String("name", "", "the display name")
			c.Flags().Duration("invite-ttl", 72*time.Hour, "how long the link works (offline; online the auth.local.invite_ttl setting decides)")
		})
	add("reset [username]", "Issue a reset link: --scope password, second_factor or all; --all resets every account", cobra.MaximumNArgs(1),
		func(cmd *cobra.Command, a []string) localauth.AdminRequest {
			sc, _ := cmd.Flags().GetString("scope")
			all, _ := cmd.Flags().GetBool("all")
			r := localauth.AdminRequest{Cmd: "reset", Scope: sc, All: all}
			if len(a) > 0 {
				r.Username = a[0]
			}
			return r
		}, func(c *cobra.Command) {
			c.Flags().String("scope", "all", "what is deleted and must be set again: password, second_factor or all")
			c.Flags().Bool("all", false, "reset every account (incident response, after the state directory and its key leaked)")
			c.Flags().Duration("reset-ttl", 24*time.Hour, "how long the links work (offline; online the auth.local.reset_ttl setting decides)")
		})
	simple := func(use, cmdName, short string) {
		add(use+" <username>", short, cobra.ExactArgs(1), func(cmd *cobra.Command, a []string) localauth.AdminRequest {
			return localauth.AdminRequest{Cmd: cmdName, Username: a[0]}
		}, nil)
	}
	simple("unlock", "unlock", "Clear an account's locks and failure counters and lift restricted and passkey_only")
	simple("disable", "disable", "Disable an account: its sessions end at once and its role is gone")
	simple("enable", "enable", "Enable a disabled account")
	simple("remove", "remove", "Remove an account: credentials deleted, a tombstone keeps the name used")
	add("end-sessions [username]", "End every session of an account, or of all accounts with --all", cobra.MaximumNArgs(1),
		func(cmd *cobra.Command, a []string) localauth.AdminRequest {
			all, _ := cmd.Flags().GetBool("all")
			r := localauth.AdminRequest{Cmd: "end-sessions", All: all}
			if len(a) > 0 {
				r.Username = a[0]
			}
			return r
		}, func(c *cobra.Command) { c.Flags().Bool("all", false, "every account") })
	add("recover <username>", "The lockout fallback: invite the account if it does not exist, else issue a full reset, and print the link", cobra.ExactArgs(1),
		func(cmd *cobra.Command, a []string) localauth.AdminRequest {
			g, _ := cmd.Flags().GetBool("grant-admin")
			n, _ := cmd.Flags().GetString("name")
			return localauth.AdminRequest{Cmd: "recover", Username: a[0], Name: n, GrantAdmin: g}
		}, func(c *cobra.Command) {
			c.Flags().Bool("grant-admin", false, "also commit local:<username> to auth.roles.admin (online; offline it prints the line to add)")
			c.Flags().String("name", "", "the display name of a new account")
			c.Flags().Duration("invite-ttl", 72*time.Hour, "how long the link of a new account works (offline)")
			c.Flags().Duration("reset-ttl", 24*time.Hour, "how long a reset link works (offline)")
		})
	return out
}
