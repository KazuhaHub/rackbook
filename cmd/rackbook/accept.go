package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kazuhahub/rackbook/internal/gitstore"
)

func newAcceptRemote() *cobra.Command {
	return &cobra.Command{
		Use:   "accept-remote <commit>",
		Short: "Accept the rewritten remote history in this clone",
		Long: `Rackbook never force-pushes, and it stops writing when the remote branch is
no longer a descendant of the last commit it saw in this clone (somebody
rewrote the history). After you checked the new history, record it here as
the new base.

<commit> must be the current tip of the remote branch, and its rackbook.yml
must load. The command changes nothing unless the history really was
rewritten. It never resets or touches your work tree: bringing your branch to
the new history (and keeping or dropping your local commits) is up to you,
with normal git, for example "git reset --hard origin/<branch>" after saving
local work. For a running server use "rackbook serve --accept-remote <commit>"
or the admin button in the console instead.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			hash, err := gitstore.AcceptRemoteInClone(cmd.Context(), cfg.Path, args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "accepted %s as the new base; your work tree was not changed\n", hash)
			return nil
		},
	}
}
