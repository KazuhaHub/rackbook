package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
)

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "rackbook",
		Short:         "Git-native infrastructure ledger",
		Long:          "Rackbook validates, serves, queries and exports an infrastructure ledger kept as YAML in Git.\n\nEvery flag can also be set with an environment variable: RACKBOOK_ plus the flag name in upper case with dashes as underscores (--cf-team is RACKBOOK_CF_TEAM).",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return applyEnv(cmd.Flags())
		},
	}
	root.PersistentFlags().String("config", "", "path to rackbook.yml (default: search upwards from the current directory)")
	root.SetVersionTemplate("rackbook {{.Version}}\n")
	root.AddCommand(
		newCheck(), newServe(), newMCP(), newExport(),
		newList(), newGet(), newAdd(), newSet(), newRm(),
		newSchema(), newAcceptRemote(), newVersion(),
		newToken(),
	)
	return root
}

// applyEnv fills flags that were not given on the command line from RACKBOOK_<NAME>.
func applyEnv(fs *pflag.FlagSet) error {
	var err error
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Changed || err != nil {
			return
		}
		name := "RACKBOOK_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(name); ok && v != "" {
			if e := f.Value.Set(v); e != nil {
				err = fmt.Errorf("%s=%q: %w", name, v, e)
			}
		}
	})
	return err
}

// configPath resolves --config, else searches upwards from dir ("" = cwd).
func configPath(cmd *cobra.Command, dir string) (string, error) {
	if p, _ := cmd.Flags().GetString("config"); p != "" {
		return p, nil
	}
	if dir == "" {
		dir = "."
	}
	return config.Find(dir)
}

func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	p, err := configPath(cmd, "")
	if err != nil {
		return nil, err
	}
	return config.Load(p)
}

func loadLedger(cmd *cobra.Command) (*ledger.Ledger, error) {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, err
	}
	return ledger.Load(cfg, nil), nil
}

func newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "rackbook %s\n", version)
		},
	}
}
