package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/validate"
)

func newCheck() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate the ledger (YAML, schemas, rules); exit 1 on errors",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, _ := cmd.Flags().GetString("format")
			if format != "text" && format != "json" {
				return fmt.Errorf("--format must be text or json")
			}
			out := cmd.OutOrStdout()
			var issues []ledger.Issue
			collections, records := 0, 0
			cfg, err := loadConfig(cmd)
			if err != nil {
				issues = []ledger.Issue{{Rule: ledger.RuleConfig, Message: err.Error()}}
			} else {
				l := ledger.Load(cfg, nil)
				confirmed, _ := gitstore.ConfirmedRecords(cmd.Context(), cfg.Dir)
				issues = validate.RunWith(l, validate.Options{Confirmed: func(coll, id string) bool { return confirmed[edit.RecordRef(coll, id)] }})
				for _, w := range cfg.Warnings {
					issues = append(issues, ledger.Issue{Rule: ledger.RuleConfig, Severity: "warning", Message: w})
				}
				collections = len(l.Collections)
				for _, c := range l.Collections {
					records += len(c.Records)
				}
			}
			issues, warnings := validate.Split(issues)
			if format == "json" {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				if err := enc.Encode(map[string]any{"ok": len(issues) == 0, "errors": issues, "warnings": warnings}); err != nil {
					return err
				}
			} else if len(issues) == 0 {
				fmt.Fprintf(out, "ok: %d collections, %d records\n", collections, records)
				for _, i := range warnings {
					fmt.Fprintln(out, "warning: "+i.String())
				}
			} else {
				for _, i := range issues {
					fmt.Fprintln(out, i)
				}
				for _, i := range warnings {
					fmt.Fprintln(out, "warning: "+i.String())
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "%d error(s)\n", len(issues))
			}
			if len(issues) > 0 {
				return exitError{1}
			}
			return nil
		},
	}
	cmd.Flags().String("format", "text", "output format: text or json")
	return cmd
}
