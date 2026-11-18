package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

func collectionOf(l *ledger.Ledger, name string) (*ledger.Collection, error) {
	c := l.Collection(name)
	if c == nil {
		names := make([]string, len(l.Collections))
		for i, x := range l.Collections {
			names[i] = x.Name
		}
		return nil, fmt.Errorf("unknown collection %q; available: %s", name, strings.Join(names, ", "))
	}
	return c, nil
}

// parseAssignments turns "f=v" arguments into typed values by the schema.
// A nil value means "remove the field" (empty right-hand side).
func parseAssignments(c *ledger.Collection, args []string) (map[string]any, error) {
	out := map[string]any{}
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%q: expected field=value", a)
		}
		if v == "" {
			out[k] = nil
			continue
		}
		val, err := coerce(c.Schema, k, v)
		if err != nil {
			return nil, err
		}
		out[k] = val
	}
	return out, nil
}

// coerce parses raw according to the schema type of the field.
func coerce(s ledger.Schema, field, raw string) (any, error) {
	p, _ := s.Prop(field)
	switch p.Type {
	case "boolean":
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a boolean (true or false)", field, raw)
		}
		return b, nil
	case "integer":
		i, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not an integer", field, raw)
		}
		return i, nil
	case "number":
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a number", field, raw)
		}
		return f, nil
	case "array":
		if strings.HasPrefix(strings.TrimSpace(raw), "[") {
			var v []any
			if err := json.Unmarshal([]byte(raw), &v); err != nil {
				return nil, fmt.Errorf("%s: %w", field, err)
			}
			return v, nil
		}
		parts := strings.Split(raw, ",")
		list := make([]any, len(parts))
		for i, x := range parts {
			list[i] = strings.TrimSpace(x)
		}
		return list, nil
	case "object":
		var v map[string]any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		return v, nil
	}
	return raw, nil
}

// orderedNode renders data as a YAML mapping in schema order.
func orderedNode(c *ledger.Collection, data map[string]any) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode}
	done := map[string]bool{}
	add := func(k string) {
		v, ok := data[k]
		if !ok || done[k] {
			return
		}
		done[k] = true
		var vn yaml.Node
		_ = vn.Encode(v)
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, &vn)
	}
	for _, p := range c.Schema.Props {
		add(p.Name)
	}
	var rest []string
	for k := range data {
		rest = append(rest, k)
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k)
	}
	return n
}

func marshalYAML(n any) (string, error) {
	b, err := yaml.Marshal(n)
	return string(b), err
}

// list -------------------------------------------------------------------------

func newList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <collection>",
		Short: "List the records of a collection",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loadLedger(cmd)
			if err != nil {
				return err
			}
			c, err := collectionOf(l, args[0])
			if err != nil {
				return err
			}
			wheres, _ := cmd.Flags().GetStringArray("where")
			where := map[string]string{}
			for _, w := range wheres {
				k, v, ok := strings.Cut(w, "=")
				if !ok || k == "" {
					return fmt.Errorf("--where %q: expected field=value", w)
				}
				where[k] = v
			}
			var recs []*ledger.Record
			for _, r := range c.Records {
				if ledger.Match(r, where) {
					recs = append(recs, r)
				}
			}
			out := cmd.OutOrStdout()
			format, _ := cmd.Flags().GetString("format")
			switch format {
			case "json":
				if recs == nil {
					recs = []*ledger.Record{}
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				return enc.Encode(recs)
			case "yaml":
				list := &yaml.Node{Kind: yaml.SequenceNode}
				for _, r := range recs {
					list.Content = append(list.Content, orderedNode(c, r.Data))
				}
				if len(recs) == 0 {
					fmt.Fprintln(out, "[]")
					return nil
				}
				s, err := marshalYAML(list)
				fmt.Fprint(out, s)
				return err
			case "table":
				cols := c.List
				if len(cols) == 0 {
					cols = c.Schema.Order()
				}
				tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, strings.Join(cols, "\t"))
				for _, r := range recs {
					row := make([]string, len(cols))
					for i, k := range cols {
						row[i] = strings.ReplaceAll(ledger.Str(r.Data[k]), "\n", " ")
					}
					fmt.Fprintln(tw, strings.Join(row, "\t"))
				}
				return tw.Flush()
			}
			return fmt.Errorf("--format must be table, json or yaml")
		},
	}
	cmd.Flags().StringArray("where", nil, "keep records whose field equals value (repeatable): --where device=web-1")
	cmd.Flags().String("format", "table", "table, json or yaml")
	return cmd
}

// get --------------------------------------------------------------------------

func newGet() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <collection> <id>",
		Short: "Print one record (id = key values joined with /)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loadLedger(cmd)
			if err != nil {
				return err
			}
			c, err := collectionOf(l, args[0])
			if err != nil {
				return err
			}
			r := c.Get(args[1])
			if r == nil {
				return fmt.Errorf("no record %q in %s", args[1], c.Name)
			}
			out := cmd.OutOrStdout()
			if format, _ := cmd.Flags().GetString("format"); format == "json" {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				return enc.Encode(r)
			}
			s, err := marshalYAML(orderedNode(c, r.Data))
			fmt.Fprint(out, s)
			return err
		},
	}
	cmd.Flags().String("format", "yaml", "yaml or json")
	return cmd
}

// add / set / rm ---------------------------------------------------------------

func addConfirmFlag(cmd *cobra.Command) {
	cmd.Flags().Bool("confirm-not-secret", false, "accept a heuristic secret-scan finding (recorded in the commit); block-tier findings cannot be confirmed")
}

func addWriteFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("commit", false, "commit the change to Git (only the changed file)")
	cmd.Flags().Bool("push", false, "commit and push to origin")
}

// finish reports the result and optionally commits and pushes.
func finish(cmd *cobra.Command, cfg *config.Config, res *edit.Result, verb string) error {
	out := cmd.OutOrStdout()
	if !res.Changed() {
		fmt.Fprintf(out, "unchanged %s/%s\n", res.Collection, res.ID)
		return nil
	}
	fmt.Fprintf(out, "%s %s/%s (%s)\n", verb, res.Collection, res.ID, strings.Join(res.Files, ", "))
	commit, _ := cmd.Flags().GetBool("commit")
	push, _ := cmd.Flags().GetBool("push")
	if !commit && !push {
		return nil
	}
	ctx := context.Background()
	short, err := gitstore.CommitFiles(ctx, cfg.Dir, res.Files, res.Subject(), nil, res.Record(), res.Trailers...)
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
}

func applyOp(cmd *cobra.Command, op edit.Op, verb string) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	// Refuse before touching any file when the commit could not go anywhere.
	if commit, _ := cmd.Flags().GetBool("commit"); commit || flagOn(cmd) {
		pushing, _ := cmd.Flags().GetBool("push")
		offline, err := gitstore.CheckRemoteHistory(cmd.Context(), cfg.Dir, pushing)
		if err != nil {
			return rewrittenHint(err)
		}
		if offline {
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: could not reach the remote; committing without checking that its history was not rewritten")
		}
	}
	if on, _ := cmd.Flags().GetBool("confirm-not-secret"); on {
		op.ConfirmNotSecret = true
		op.ConfirmedBy = cliUser(cmd, cfg)
	}
	res, err := edit.Apply(cfg, op)
	if err != nil {
		return explain(err)
	}
	return finish(cmd, cfg, res, verb)
}

func flagOn(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("push")
	return v
}

// rewrittenHint tells the CLI user how to continue after a rewritten remote.
func rewrittenHint(err error) error {
	if errors.Is(err, gitstore.ErrHistoryRewritten) {
		return fmt.Errorf("%w\nnothing was changed. After checking the new history, accept it with: rackbook accept-remote <commit of the remote tip>", err)
	}
	return err
}

// cliUser names who confirms a secret-scan finding at the command line: the Git
// identity of the repository, else the login name.
func cliUser(cmd *cobra.Command, cfg *config.Config) string {
	r := &gitstore.Repo{Dir: cfg.Dir}
	if id := r.ConfigIdentity(cmd.Context()); id.Email != "" {
		return id.Email
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "cli"
}

// explain turns edit errors into readable CLI messages.
func explain(err error) error {
	var se *secretscan.Error
	if errors.As(err, &se) && se.Suspected() {
		return fmt.Errorf("%w\nIf this is not a secret, repeat the command with --confirm-not-secret (recorded in the commit)", err)
	}
	var ie *edit.InvalidError
	if errors.As(err, &ie) {
		var b strings.Builder
		b.WriteString("refusing to write, the change would introduce errors:")
		for _, i := range ie.Issues {
			b.WriteString("\n  " + i.String())
		}
		return errors.New(b.String())
	}
	var ce *edit.ConflictError
	if errors.As(err, &ce) {
		return errors.New(ce.Message)
	}
	if errors.Is(err, yamledit.ErrUnsupported) {
		return fmt.Errorf("%w (edit the YAML by hand)", err)
	}
	return err
}

func newAdd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <collection> field=value...",
		Short: "Add a record (edits the files in the working tree)",
		Long:  "Add a record. Values are converted by the schema type of the field (managed=true is a boolean). The YAML file is spliced in place and the whole ledger is validated first.",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loadLedger(cmd)
			if err != nil {
				return err
			}
			c, err := collectionOf(l, args[0])
			if err != nil {
				return err
			}
			data, err := parseAssignments(c, args[1:])
			if err != nil {
				return err
			}
			for k, v := range data {
				if v == nil {
					delete(data, k)
				}
			}
			return applyOp(cmd, edit.Op{Kind: edit.Add, Collection: c.Name, Data: data}, "added")
		},
	}
	addWriteFlags(cmd)
	addConfirmFlag(cmd)
	return cmd
}

func newSet() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <collection> <id> field=value...",
		Short: "Change fields of a record; field= (empty) removes the field",
		Args:  cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loadLedger(cmd)
			if err != nil {
				return err
			}
			c, err := collectionOf(l, args[0])
			if err != nil {
				return err
			}
			r := c.Get(args[1])
			if r == nil {
				return fmt.Errorf("no record %q in %s", args[1], c.Name)
			}
			changes, err := parseAssignments(c, args[2:])
			if err != nil {
				return err
			}
			data := map[string]any{}
			for k, v := range r.Data {
				data[k] = v
			}
			for k, v := range changes {
				if v == nil {
					delete(data, k)
				} else {
					data[k] = v
				}
			}
			return applyOp(cmd, edit.Op{Kind: edit.Edit, Collection: c.Name, ID: r.ID, Hash: r.Hash, Data: data}, "updated")
		},
	}
	addWriteFlags(cmd)
	addConfirmFlag(cmd)
	return cmd
}

func newRm() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <collection> <id>",
		Short: "Delete a record",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loadLedger(cmd)
			if err != nil {
				return err
			}
			c, err := collectionOf(l, args[0])
			if err != nil {
				return err
			}
			r := c.Get(args[1])
			if r == nil {
				return fmt.Errorf("no record %q in %s", args[1], c.Name)
			}
			return applyOp(cmd, edit.Op{Kind: edit.Delete, Collection: c.Name, ID: r.ID, Hash: r.Hash}, "removed")
		},
	}
	addWriteFlags(cmd)
	return cmd
}
