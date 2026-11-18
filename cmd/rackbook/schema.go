package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newSchema() *cobra.Command {
	return &cobra.Command{
		Use:   "schema [collection]",
		Short: "Print the JSON Schema of a collection (all collections when omitted)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loadLedger(cmd)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(args) == 1 {
				c, err := collectionOf(l, args[0])
				if err != nil {
					return err
				}
				if c.SchemaRaw == nil {
					return fmt.Errorf("collection %s has no readable schema", c.Name)
				}
				var buf bytes.Buffer
				if err := json.Indent(&buf, c.SchemaRaw, "", "  "); err != nil {
					return err
				}
				buf.WriteByte('\n')
				_, err = out.Write(buf.Bytes())
				return err
			}
			var b bytes.Buffer
			b.WriteByte('{')
			for i, c := range l.Collections {
				if i > 0 {
					b.WriteByte(',')
				}
				name, _ := json.Marshal(c.Name)
				b.Write(name)
				b.WriteByte(':')
				if c.SchemaRaw != nil {
					b.Write(c.SchemaRaw)
				} else {
					b.WriteString("null")
				}
			}
			b.WriteByte('}')
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, b.Bytes(), "", "  "); err != nil {
				return err
			}
			pretty.WriteByte('\n')
			_, err = out.Write(pretty.Bytes())
			return err
		},
	}
}
