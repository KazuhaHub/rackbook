package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

func newToken() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "List and revoke Rackbook API tokens (.rackbook/tokens.yml)",
		Long: `API tokens live in .rackbook/tokens.yml in the data repository (only their SHA-256).
Create them in the console (令牌); list and revoke them here. Revoking edits the file in
your work tree and, with --commit or --push, commits it like "rackbook set" does. A
running server picks the change up on its next pull.`,
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List the tokens",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(filepath.Join(cfg.Dir, filepath.FromSlash(tokens.File)))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			ts, err := tokens.Parse(b)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tPREFIX\tSCOPE\tCREATED BY\tCREATED\tEXPIRES\tSTATUS")
			now := time.Now()
			for _, t := range tokens.Sorted(ts) {
				status := "active"
				switch {
				case t.Revoked != "":
					status = "revoked"
				case !t.Active(now):
					status = "expired"
				}
				exp := t.Expires
				if exp == "" {
					exp = "never"
				}
				fmt.Fprintf(tw, "%s\t%s…\t%s\t%s\t%s\t%s\t%s\n", t.Name, t.ShownPrefix, t.Scope, t.CreatedBy, t.Created, exp, status)
			}
			return tw.Flush()
		},
	}
	revoke := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			path := filepath.Join(cfg.Dir, filepath.FromSlash(tokens.File))
			old, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("no tokens: %w", err)
			}
			nw, err := tokens.ApplyRevoke(old, args[0], "", time.Now())
			if err != nil {
				if errors.Is(err, tokens.ErrMissing) {
					return fmt.Errorf("no token named %q", args[0])
				}
				return err
			}
			out := cmd.OutOrStdout()
			if string(nw) == string(old) {
				fmt.Fprintf(out, "%s is already revoked\n", args[0])
				return nil
			}
			if err := os.WriteFile(path, nw, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(out, "revoked %s (%s)\n", args[0], tokens.File)
			commit, _ := cmd.Flags().GetBool("commit")
			push, _ := cmd.Flags().GetBool("push")
			if !commit && !push {
				return nil
			}
			ctx := context.Background()
			short, err := gitstore.CommitFiles(ctx, cfg.Dir, []string{tokens.File}, "rackbook(auth): revoke token "+args[0], nil, "")
			if err != nil {
				return fmt.Errorf("the file was changed but the commit failed: %w", rewrittenHint(err))
			}
			fmt.Fprintf(out, "committed %s\n", short)
			if push {
				if err := gitstore.PushCurrent(ctx, cfg.Dir); err != nil {
					return fmt.Errorf("committed %s but the push failed: %w", short, err)
				}
				fmt.Fprintln(out, "pushed")
			}
			return nil
		},
	}
	addWriteFlags(revoke)
	cmd.AddCommand(list, revoke)
	return cmd
}
