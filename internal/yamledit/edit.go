package yamledit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Opts tunes how records are written.
type Opts struct {
	// Order lists field names in the order new fields are written
	// (normally the schema's property order).
	Order []string
	// GroupField is the first key field (e.g. "device"). Add inserts after
	// the last record with the same value; Delete drops a group's leading
	// "# ---" comment when the last record of the group goes.
	GroupField string
}

// Edit replaces record index of the list at path with data.
func Edit(src []byte, path string, index int, data map[string]any, o Opts) ([]byte, error) {
	if rest, ok := cutBOM(src); ok {
		out, err := Edit(rest, path, index, data, o)
		return withBOM(out, err)
	}
	doc, _, item, err := target(src, path, index)
	if err != nil {
		return nil, err
	}
	if canon(Value(item.Node)) == canon(data) {
		return src, nil // nothing to change
	}
	var text string
	if item.Flow {
		text = editFlow(doc, item, data, o)
	} else {
		text = editBlock(doc, item, data, o)
	}
	out := splice(src, item.Start, item.End, text)
	return verify(src, out, path, func(l []any) ([]any, error) {
		l[index] = data
		return l, nil
	})
}

// Add inserts data as a new record of the list at path.
func Add(src []byte, path string, data map[string]any, o Opts) ([]byte, error) {
	if rest, ok := cutBOM(src); ok {
		out, err := Add(rest, path, data, o)
		return withBOM(out, err)
	}
	doc, err := Parse(src)
	if err != nil {
		return nil, err
	}
	list, err := doc.Records(path)
	if err != nil {
		return nil, err
	}
	var out []byte
	at := len(list.Items) // index the new record ends up at
	switch {
	case !list.Exists && path == "" && doc.Root == nil:
		// Empty (or comment-only) file: start a block list at the end.
		text := blockRecord("- ", 2, data, o.Order)
		out = splice(src, len(src), len(src), ensureNL(src, text))
	case !list.Exists:
		return nil, fmt.Errorf("%w: cannot add to %s (missing or empty); add the first record by hand", ErrUnsupported, displayPath(path))
	default:
		for _, it := range list.Items {
			if it.Node.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("%w: %s holds non-mapping items", ErrUnsupported, displayPath(path))
			}
		}
		model := list.Items[len(list.Items)-1]
		modelIdx := len(list.Items) - 1
		if o.GroupField != "" {
			if want, ok := data[o.GroupField]; ok {
				wantJSON := canon(want)
				for i, it := range list.Items {
					if v, ok := fieldValue(it.Node, o.GroupField); ok && canon(v) == wantJSON {
						model, modelIdx = it, i
					}
				}
			}
		}
		var text string
		if flowStyle(list.Items, model) {
			text = model.Prefix + flowRecord(data, orderedKeys(data, o.Order), nil) + "\n"
		} else {
			text = blockRecord(model.Prefix, model.KeyCol, data, o.Order)
		}
		out = splice(src, model.End, model.End, ensureNL(src[:model.End], text))
		at = modelIdx + 1
	}
	want := func(l []any) ([]any, error) {
		return append(l[:at:at], append([]any{data}, l[at:]...)...), nil
	}
	return verify(src, out, path, want)
}

// flowStyle picks the style for a new record: the majority style of the list
// (so one block-style outlier does not turn every new row into a block), the
// model's own style on a tie.
func flowStyle(items []Item, model Item) bool {
	flow := 0
	for _, it := range items {
		if it.Flow {
			flow++
		}
	}
	switch block := len(items) - flow; {
	case flow > block:
		return true
	case block > flow:
		return false
	}
	return model.Flow
}

// Delete removes record index of the list at path.
func Delete(src []byte, path string, index int, o Opts) ([]byte, error) {
	if rest, ok := cutBOM(src); ok {
		out, err := Delete(rest, path, index, o)
		return withBOM(out, err)
	}
	doc, list, item, err := target(src, path, index)
	if err != nil {
		return nil, err
	}
	start, end := item.StartLine, item.EndLine
	if o.GroupField != "" && onlyInGroup(list, index, o.GroupField) {
		s := start
		for s > 0 && isCommentLine(doc.line(s-1), item.DashCol) {
			s--
		}
		if s < start && strings.HasPrefix(strings.TrimSpace(string(doc.line(s))), "# ---") {
			start = s
		}
	}
	n := doc.numLines()
	blank := func(i int) bool { return i >= 0 && i < n && len(bytes.TrimSpace(doc.line(i))) == 0 }
	switch {
	case blank(start-1) && blank(end):
		end++
	case start == 0 && blank(end):
		end++
	case end >= n:
		for blank(start - 1) {
			start--
		}
	}
	out := splice(src, doc.offset(start), doc.offset(end), "")
	return verify(src, out, path, func(l []any) ([]any, error) {
		return append(l[:index:index], l[index+1:]...), nil
	})
}

func target(src []byte, path string, index int) (*Doc, *List, Item, error) {
	doc, err := Parse(src)
	if err != nil {
		return nil, nil, Item{}, err
	}
	list, err := doc.Records(path)
	if err != nil {
		return nil, nil, Item{}, err
	}
	if index < 0 || index >= len(list.Items) {
		return nil, nil, Item{}, fmt.Errorf("record index %d out of range (%d records)", index, len(list.Items))
	}
	item := list.Items[index]
	if item.Node.Kind != yaml.MappingNode {
		return nil, nil, Item{}, fmt.Errorf("%w: record %d is not a mapping", ErrUnsupported, index)
	}
	return doc, list, item, nil
}

var bom = []byte{0xEF, 0xBB, 0xBF}

// cutBOM removes a leading UTF-8 byte order mark; the edit runs on the rest
// and the mark is put back, so it is preserved.
func cutBOM(src []byte) ([]byte, bool) {
	if bytes.HasPrefix(src, bom) {
		return src[len(bom):], true
	}
	return src, false
}

func withBOM(out []byte, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, bom...), out...), nil
}

func splice(src []byte, start, end int, text string) []byte {
	if bytes.Contains(src, []byte("\r\n")) {
		text = strings.ReplaceAll(text, "\n", "\r\n") // keep the file's line ending
	}
	out := make([]byte, 0, len(src)-(end-start)+len(text))
	out = append(out, src[:start]...)
	out = append(out, text...)
	out = append(out, src[end:]...)
	return out
}

// ensureNL makes text insertable after before: if before does not end in a
// newline one is added in front.
func ensureNL(before []byte, text string) string {
	if len(before) > 0 && before[len(before)-1] != '\n' {
		return "\n" + text
	}
	return text
}

func isCommentLine(l []byte, dashCol int) bool {
	t := bytes.TrimLeft(l, " \t")
	return len(t) > 0 && t[0] == '#' && len(l)-len(t) <= dashCol
}

func onlyInGroup(l *List, index int, field string) bool {
	v, ok := fieldValue(l.Items[index].Node, field)
	if !ok {
		return false
	}
	want := canon(v)
	for i, it := range l.Items {
		if i == index {
			continue
		}
		if w, ok := fieldValue(it.Node, field); ok && canon(w) == want {
			return false
		}
	}
	return true
}

func fieldValue(m *yaml.Node, field string) (any, bool) {
	if m.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == field {
			return Value(m.Content[i+1]), true
		}
	}
	return nil, false
}

func canon(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// oldValues maps each key of a record to its value node.
func oldValues(m *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		out[m.Content[i].Value] = m.Content[i+1]
	}
	return out
}

// editFlow rewrites a flow-style record on one line, keeping a trailing comment.
func editFlow(doc *Doc, item Item, data map[string]any, o Opts) string {
	old := oldValues(item.Node)
	keys := mergedKeys(item.Node, data, o.Order)
	text := item.Prefix + flowRecord(data, keys, old)
	last := doc.line(item.EndLine - 1)
	if c := trailingComment(last); c != "" {
		text += c
	}
	return text + "\n"
}

// trailingComment returns the ` # ...` after a closing brace on the line, if any.
func trailingComment(line []byte) string {
	i := bytes.LastIndexByte(line, '}')
	if i < 0 {
		return ""
	}
	rest := string(line[i+1:])
	if t := strings.TrimSpace(rest); strings.HasPrefix(t, "#") {
		return strings.TrimRight(rest, " \t")
	}
	return ""
}

// mergedKeys keeps the old key order, then appends new keys (schema order, then sorted).
func mergedKeys(oldMap *yaml.Node, data map[string]any, order []string) []string {
	var keys []string
	seen := map[string]bool{}
	for i := 0; i+1 < len(oldMap.Content); i += 2 {
		k := oldMap.Content[i].Value
		if _, ok := data[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	extra := map[string]any{}
	for k, v := range data {
		if !seen[k] {
			extra[k] = v
		}
	}
	return append(keys, orderedKeys(extra, order)...)
}

// editBlock rewrites a block record. Unchanged fields are copied verbatim
// (folded text, quoting, comments); a changed field is re-rendered but keeps
// its end-of-line comment and the own-line comments that follow it.
func editBlock(doc *Doc, item Item, data map[string]any, o Opts) string {
	m := item.Node
	type pair struct {
		body     []string // first line without indentation, the rest as in the file
		trailing []string // blank and comment lines up to the next key
		eol      string   // end-of-line comment of a one-line field, with its spacing
		val      *yaml.Node
	}
	pairs := map[string]pair{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		first := k.Line - 1
		last := item.EndLine
		if i+2 < len(m.Content) {
			last = m.Content[i+2].Line - 1
		}
		var ls []string
		for ln := first; ln < last; ln++ {
			ls = append(ls, string(doc.line(ln)))
		}
		ls[0] = ls[0][min(len(ls[0]), byteCol(doc.line(first), k.Column-1)):]
		// Trailing comment/blank lines sit left of (or at) the key column and after the value's last node line.
		cut := len(ls)
		for cut > 1 && first+cut > maxLine(v) && isOwnLine(ls[cut-1], item.KeyCol) {
			cut--
		}
		p := pair{body: ls[:cut], trailing: ls[cut:], val: v}
		if cut == 1 && v.LineComment != "" {
			if t := strings.TrimRight(ls[0], " \t"); strings.HasSuffix(t, v.LineComment) {
				base := t[:len(t)-len(v.LineComment)]
				p.eol = t[len(strings.TrimRight(base, " \t")):]
			}
		}
		pairs[k.Value] = p
	}
	var b strings.Builder
	for i, k := range mergedKeys(m, data, o.Order) {
		var lines []string
		p, existed := pairs[k]
		if existed && canon(Value(p.val)) == canon(data[k]) {
			lines = append(append([]string{}, p.body...), p.trailing...)
		} else {
			var hint yaml.Style
			if existed && p.val.Kind == yaml.ScalarNode {
				hint = p.val.Style
			}
			lines = blockPair(k, data[k], item.KeyCol, hint)
			if len(lines) == 1 {
				lines[0] += p.eol
			}
			lines = append(lines, p.trailing...)
		}
		for j, l := range lines {
			switch {
			case j == 0 && i == 0:
				b.WriteString(item.Prefix)
			case j == 0:
				b.WriteString(strings.Repeat(" ", item.KeyCol))
			}
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		return item.Prefix + "{}\n"
	}
	return b.String()
}

// isOwnLine reports a blank line or a comment line at or left of col.
func isOwnLine(l string, col int) bool {
	t := strings.TrimLeft(l, " \t")
	return t == "" || (t[0] == '#' && len(l)-len(t) <= col)
}

// blockRecord renders a new block record with the given "- " prefix.
func blockRecord(prefix string, keyCol int, data map[string]any, order []string) string {
	keys := orderedKeys(data, order)
	if len(keys) == 0 {
		return prefix + "{}\n"
	}
	var b strings.Builder
	for i, k := range keys {
		for j, l := range blockPair(k, data[k], keyCol, 0) {
			switch {
			case j == 0 && i == 0:
				b.WriteString(prefix)
			case j == 0:
				b.WriteString(strings.Repeat(" ", keyCol))
			}
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// verify re-parses out and checks that its data equals the data of src with
// mutate applied to the list at path, and that no other part of the
// document changed.
func verify(src, out []byte, path string, mutate func([]any) ([]any, error)) ([]byte, error) {
	before, err := Parse(src)
	if err != nil {
		return nil, err
	}
	after, err := Parse(out)
	if err != nil {
		return nil, fmt.Errorf("edited file no longer parses: %w", err)
	}
	var want any
	if before.Root != nil {
		want = Value(before.Root)
	}
	want, err = mutateTree(want, path, mutate)
	if err != nil {
		return nil, err
	}
	var got any
	if after.Root != nil {
		got = Value(after.Root)
	}
	if canon(want) != canon(got) {
		return nil, errors.New("internal error: edited file does not decode to the intended data; nothing was written")
	}
	return out, nil
}

func mutateTree(tree any, path string, mutate func([]any) ([]any, error)) (any, error) {
	if path == "" {
		l, _ := tree.([]any)
		nl, err := mutate(l)
		if len(nl) == 0 {
			return nil, err // an emptied list reads back as null
		}
		return nl, err
	}
	segs := strings.Split(path, ".")
	m, ok := tree.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("path %s: document is not a mapping", path)
	}
	if len(segs) == 1 {
		l, _ := m[segs[0]].([]any)
		nl, err := mutate(l)
		if err != nil {
			return nil, err
		}
		if len(nl) == 0 {
			m[segs[0]] = nil
		} else {
			m[segs[0]] = nl
		}
		return m, nil
	}
	sub, err := mutateTree(m[segs[0]], strings.Join(segs[1:], "."), mutate)
	if err != nil {
		return nil, err
	}
	m[segs[0]] = sub
	return m, nil
}
