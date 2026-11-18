package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kazuhahub/rackbook/internal/export"
)

func newExport() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the ledger as Markdown, llms.txt or JSON",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, _ := cmd.Flags().GetString("format")
			outFile, _ := cmd.Flags().GetString("output")
			base, _ := cmd.Flags().GetString("base-url")
			l, err := loadLedger(cmd)
			if err != nil {
				return err
			}
			var data []byte
			switch format {
			case "markdown", "md", "llms-full":
				data = []byte(export.Markdown(l))
			case "llms":
				data = []byte(export.LLMS(l, base))
			case "json":
				if data, err = export.JSON(l); err != nil {
					return err
				}
			default:
				return fmt.Errorf("--format must be markdown, llms, llms-full or json")
			}
			if outFile == "" || outFile == "-" {
				_, err = cmd.OutOrStdout().Write(data)
				return err
			}
			return os.WriteFile(outFile, data, 0o644)
		},
	}
	cmd.Flags().String("format", "markdown", "markdown, llms, llms-full or json")
	cmd.Flags().StringP("output", "o", "", "write to FILE instead of stdout")
	cmd.Flags().String("base-url", "", "public URL of the console; makes llms.txt link to the JSON API")
	return cmd
}
