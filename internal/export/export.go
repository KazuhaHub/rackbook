// Package export renders a ledger as Markdown, llms.txt or JSON. Output is
// deterministic: collections in config order, columns in schema order,
// records in file order.
package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kazuhahub/rackbook/internal/ledger"
)

// Markdown renders the whole ledger: title, then per collection a heading,
// its notes and a table with the schema titles as column headers.
func Markdown(l *ledger.Ledger) string {
	var b strings.Builder
	cfg := l.Config
	title := cfg.Title
	if title == "" {
		title = "Ledger"
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	if cfg.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", cfg.Description)
	}
	lastGroup := ""
	for _, c := range l.Collections {
		level := "##"
		if c.Group != "" {
			if c.Group != lastGroup {
				fmt.Fprintf(&b, "## %s\n\n", c.Group)
			}
			level = "###"
		}
		lastGroup = c.Group
		fmt.Fprintf(&b, "%s %s\n\n", level, c.Title)
		if c.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", c.Description)
		}
		for _, n := range l.Notes {
			if n.Collection != c.Name {
				continue
			}
			fmt.Fprintf(&b, "> **%s**\n", n.Title)
			for _, line := range strings.Split(strings.TrimSpace(n.Text), "\n") {
				fmt.Fprintf(&b, "> %s\n", line)
			}
			b.WriteString("\n")
		}
		writeTable(&b, c)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func columns(c *ledger.Collection) []ledger.Prop {
	cols := append([]ledger.Prop{}, c.Schema.Props...)
	known := map[string]bool{}
	for _, p := range cols {
		known[p.Name] = true
	}
	extra := map[string]bool{}
	for _, r := range c.Records {
		for k := range r.Data {
			if !known[k] {
				extra[k] = true
			}
		}
	}
	var names []string
	for k := range extra {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		cols = append(cols, ledger.Prop{Name: k})
	}
	return cols
}

func writeTable(b *strings.Builder, c *ledger.Collection) {
	if len(c.Records) == 0 {
		b.WriteString("_(no records)_\n")
		return
	}
	cols := columns(c)
	head := make([]string, len(cols))
	sep := make([]string, len(cols))
	for i, p := range cols {
		head[i], sep[i] = cell(p.Label()), "---"
	}
	fmt.Fprintf(b, "| %s |\n| %s |\n", strings.Join(head, " | "), strings.Join(sep, " | "))
	for _, r := range c.Records {
		row := make([]string, len(cols))
		for i, p := range cols {
			row[i] = cell(display(r.Data[p.Name]))
		}
		fmt.Fprintf(b, "| %s |\n", strings.Join(row, " | "))
	}
}

// display renders a value for a table cell: booleans as ✓ (true) or blank.
func display(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case bool:
		if x {
			return "✓"
		}
		return ""
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = display(e)
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		b, _ := json.Marshal(x)
		return string(b)
	}
	return ledger.Str(v)
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", "<br>")
}

// LLMS renders llms.txt (llmstxt.org): an H1, a summary blockquote and one
// list entry per collection. With baseURL the entries link to the JSON API
// and the full exports.
func LLMS(l *ledger.Ledger, baseURL string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	cfg := l.Config
	var b strings.Builder
	title := cfg.Title
	if title == "" {
		title = "Ledger"
	}
	records := 0
	for _, c := range l.Collections {
		records += len(c.Records)
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	if cfg.Description != "" {
		fmt.Fprintf(&b, "> %s\n\n", strings.ReplaceAll(cfg.Description, "\n", " "))
	}
	fmt.Fprintf(&b, "Infrastructure ledger kept as YAML in Git and exported by Rackbook: %d collections, %d records.\n\n", len(l.Collections), records)
	b.WriteString("## Collections\n\n")
	for _, c := range l.Collections {
		var name string
		if baseURL != "" {
			name = fmt.Sprintf("[%s](%s/api/c/%s)", c.Title, baseURL, c.Name)
		} else {
			name = fmt.Sprintf("%s (%s)", c.Title, c.Name)
		}
		count := fmt.Sprintf("%d records", len(c.Records))
		if len(c.Records) == 1 {
			count = "1 record"
		}
		line := fmt.Sprintf("- %s: %s", name, count)
		if c.Description != "" {
			line = fmt.Sprintf("- %s: %s (%s)", name, strings.ReplaceAll(c.Description, "\n", " "), count)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n## Full exports\n\n")
	if baseURL != "" {
		fmt.Fprintf(&b, "- [Everything as Markdown](%s/llms-full.txt): all collections as tables\n", baseURL)
		fmt.Fprintf(&b, "- [Everything as JSON](%s/export.json): machine-readable records\n", baseURL)
	} else {
		b.WriteString("- llms-full.txt: all collections as Markdown tables\n- export.json: machine-readable records\n")
	}
	return b.String()
}

// JSON renders {"title","description","collections":{name:[record,...]},"notes":[...]}
// with collections in config order and record fields in schema order.
func JSON(l *ledger.Ledger) ([]byte, error) {
	var b bytes.Buffer
	enc := func(v any) []byte {
		out, _ := json.Marshal(v)
		return out
	}
	b.WriteString(`{"title":`)
	b.Write(enc(l.Config.Title))
	b.WriteString(`,"description":`)
	b.Write(enc(l.Config.Description))
	b.WriteString(`,"collections":{`)
	for i, c := range l.Collections {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(enc(c.Name))
		b.WriteString(":[")
		for j, r := range c.Records {
			if j > 0 {
				b.WriteByte(',')
			}
			b.Write(orderedJSON(c, r.Data))
		}
		b.WriteByte(']')
	}
	b.WriteString(`},"notes":`)
	notes := l.Notes
	if notes == nil {
		notes = []ledger.Note{}
	}
	nb := make([]map[string]string, len(notes))
	for i, n := range notes {
		nb[i] = map[string]string{"title": n.Title, "text": n.Text, "collection": n.Collection}
	}
	b.Write(enc(nb))
	b.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, b.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func orderedJSON(c *ledger.Collection, data map[string]any) []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	first := true
	for _, p := range columns(c) {
		v, ok := data[p.Name]
		if !ok {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(p.Name)
		val, _ := json.Marshal(v)
		b.Write(k)
		b.WriteByte(':')
		b.Write(val)
	}
	b.WriteByte('}')
	return b.Bytes()
}
