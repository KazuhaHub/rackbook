package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/mcpserver"
)

func newMCP() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run the read-only MCP server on stdio",
		Long:  "Run the MCP server on stdin/stdout for AI agents. The files are re-read on every call.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := configPath(cmd, "")
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			store, err := gitstore.Open(ctx, gitstore.Options{ConfigPath: path, NoGit: true})
			if err != nil {
				return err
			}
			return mcpserver.RunStdio(ctx, mcpserver.New(store.Ledger, version))
		},
	}
}
