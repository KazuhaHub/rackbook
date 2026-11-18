package yamledit

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// This file splices single entries of a mapping (for example one collection
// under `collections:` in rackbook.yml) and single items of a list (a rule
// under `rules:`). Like the record functions it touches only the lines of the
// entry it changes: other entries, comments and blank lines stay byte for byte.
// Inside a changed entry only the keys that change are rewritten, so comments
// on the other keys survive too.

// EntryChange is one key of an entry: set it to Value, or remove it.
type EntryChange struct {
	Key    string
	Value  any // string, bool, int, []any (scalars or maps), nil is a YAML null
	Remove bool
}

// ErrNoEntry means the entry (or its parent mapping) does not exist.
var ErrNoEntry = errors.New("no such entry")

// spanEnd returns the exclusive 0-based line index where the text of n ends:
// after its last node and any continuation lines, but before the blank and
// comment lines that separate it from whatever comes next.
func (d *Doc) spanEnd(n *yaml.Node) int {
	last := maxLine(n)
	limit := d.numLines()
	if nxt := nextNodeLine(d.Root, last); nxt != 0 {
		limit = nxt - 1
	}
	block := endsInBlockScalar(n)
	end := limit
	for end > last {
		l := bytes.TrimSpace(d.line(end - 1))
		if len(l) == 0 || (!block && l[0] == '#') {
			end--
			continue
		}
		break
	}
	return end
}

func endsInBlockScalar(n *yaml.Node) bool {
	for len(n.Content) > 0 && n.Kind != yaml.AliasNode {
		n = n.Content[len(n.Content)-1]
	}
	return n.Kind == yaml.ScalarNode && (n.Style&(yaml.LiteralStyle|yaml.FoldedStyle)) != 0
}

// mappingAt returns the mapping at path.
func mappingAt(doc *Doc, path string) (*yaml.Node, error) {
	n, ok := doc.Lookup(path)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoEntry, displayPath(path))
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: %s is not a mapping", ErrUnsupported, displayPath(path))
	}
	if n.Style&yaml.FlowStyle != 0 {
		return nil, fmt.Errorf("%w: %s is written in flow style ({...}); edit it by hand", ErrUnsupported, displayPath(path))
	}
	return n, nil
}

func pair(m *yaml.Node, key string) (k, v *yaml.Node, idx int) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1], i / 2
		}
	}
	return nil, nil, -1
}

func pad(n int) string { return strings.Repeat(" ", n) }

// renderField renders `key: value` for a block mapping whose keys sit at
// column indent. Lists of scalars are written inline ([a, b]); lists that hold
// mappings get one `- {…}` line per item.
func renderField(key string, v any, indent int) []string {
	if list, ok := v.([]any); ok {
		complex := false
		for _, e := range list {
			if _, isMap := e.(map[string]any); isMap {
				complex = true
			}
			if _, isOrd := e.(Flow); isOrd {
				complex = true
			}
		}
		if complex && len(list) > 0 {
			out := []string{pad(indent) + keyScalar(key, false) + ":"}
			for _, e := range list {
				out = append(out, pad(indent+2)+"- "+inline(inlineValue(e), 0))
			}
			return out
		}
	}
	lines := blockPair(key, inlineValue(v), indent, 0)
	lines[0] = pad(indent) + lines[0]
	return lines
}

// Flow is an ordered mapping that is written as `{k: v, …}` in the given key order.
type Flow struct {
	Keys   []string
	Values map[string]any
}

// String renders the mapping on one line.
func (f Flow) String() string {
	if len(f.Keys) == 0 {
		return "{}"
	}
	parts := make([]string, len(f.Keys))
	for i, k := range f.Keys {
		parts[i] = keyScalar(k, true) + ": " + inline(inlineValue(f.Values[k]), 0)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// inlineValue turns Flow values into text-carrying values for inline().
func inlineValue(v any) any {
	switch x := v.(type) {
	case Flow:
		return rawText(x.String())
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = inlineValue(e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	}
	return v
}

// rawText is a value that is already rendered YAML.
type rawText string

// SetEntry changes keys of the entry `key` of the mapping at path: each change
// replaces the key's lines, adds the key (after the last existing key, or
// after the key that precedes it in order) or removes it. Everything else in
// the file is untouched.
func SetEntry(src []byte, path, key string, changes []EntryChange, order []string) ([]byte, error) {
	if rest, ok := cutBOM(src); ok {
		out, err := SetEntry(rest, path, key, changes, order)
		return withBOM(out, err)
	}
	out := src
	for _, c := range changes {
		var err error
		if out, err = setKey(out, path, key, c, order); err != nil {
			return nil, err
		}
	}
	return verifyEntry(src, out, path, key, func(entry map[string]any) {
		for _, c := range changes {
			if c.Remove {
				delete(entry, c.Key)
			} else {
				entry[c.Key] = normalize(c.Value)
			}
		}
	})
}

func setKey(src []byte, path, key string, c EntryChange, order []string) ([]byte, error) {
	doc, err := Parse(src)
	if err != nil {
		return nil, err
	}
	parent, err := mappingAt(doc, path)
	if err != nil {
		return nil, err
	}
	_, entry, _ := pair(parent, key)
	if entry == nil {
		return nil, fmt.Errorf("%w: %s.%s", ErrNoEntry, path, key)
	}
	if entry.Kind != yaml.MappingNode || entry.Style&yaml.FlowStyle != 0 {
		return nil, fmt.Errorf("%w: %s.%s is not a block mapping; edit it by hand", ErrUnsupported, path, key)
	}
	k, v, _ := pair(entry, c.Key)
	indent := 4
	if len(entry.Content) > 0 {
		indent = entry.Content[0].Column - 1
	}
	if k != nil {
		start, end := k.Line-1, doc.spanEnd(v)
		if c.Remove {
			return splice(src, doc.offset(start), doc.offset(end), ""), nil
		}
		if canon(Value(v)) == canon(normalize(c.Value)) {
			return src, nil
		}
		text := strings.Join(renderField(c.Key, c.Value, indent), "\n") + "\n"
		return splice(src, doc.offset(start), doc.offset(end), ensureNL(src[:doc.offset(start)], text)), nil
	}
	if c.Remove {
		return src, nil
	}
	// New key: after the nearest earlier key of the order that exists, else
	// before the nearest later one, else at the end.
	text := strings.Join(renderField(c.Key, c.Value, indent), "\n") + "\n"
	at := doc.spanEnd(entry.Content[len(entry.Content)-1])
	if pos := indexOf(order, c.Key); pos >= 0 {
		found := false
		for p := pos - 1; p >= 0 && !found; p-- {
			if _, v, i := pair(entry, order[p]); i >= 0 {
				at, found = doc.spanEnd(v), true
			}
		}
		for p := pos + 1; p < len(order) && !found; p++ {
			if k, _, i := pair(entry, order[p]); i >= 0 {
				at, found = k.Line-1, true
			}
		}
	}
	return splice(src, doc.offset(at), doc.offset(at), ensureNL(src[:doc.offset(at)], text)), nil
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}

// AddEntry appends the entry `key` (a block mapping of fields, in the given
// order) to the mapping at path, after its last entry. A blank line is kept
// between entries when the file separates them that way.
func AddEntry(src []byte, path, key string, fields []EntryChange) ([]byte, error) {
	if rest, ok := cutBOM(src); ok {
		out, err := AddEntry(rest, path, key, fields)
		return withBOM(out, err)
	}
	doc, err := Parse(src)
	if err != nil {
		return nil, err
	}
	parent, err := mappingAt(doc, path)
	if err != nil {
		return nil, err
	}
	if _, _, i := pair(parent, key); i >= 0 {
		return nil, fmt.Errorf("%s.%s already exists", path, key)
	}
	indent := 2
	if len(parent.Content) > 0 {
		indent = parent.Content[0].Column - 1
	}
	var b strings.Builder
	if n := len(parent.Content); n >= 4 {
		// separated by a blank line? look at the line above the last key
		if l := parent.Content[n-2].Line - 1; l > 0 && len(bytes.TrimSpace(doc.line(l-1))) == 0 {
			b.WriteString("\n")
		}
	}
	b.WriteString(pad(indent) + keyScalar(key, false) + ":\n")
	for _, f := range fields {
		if f.Remove {
			continue
		}
		b.WriteString(strings.Join(renderField(f.Key, f.Value, indent+2), "\n") + "\n")
	}
	at := doc.numLines()
	if n := len(parent.Content); n > 0 {
		at = doc.spanEnd(parent.Content[n-1])
	} else if _, ok := doc.Lookup(path); ok {
		return nil, fmt.Errorf("%w: %s is empty; add the first entry by hand", ErrUnsupported, path)
	}
	out := splice(src, doc.offset(at), doc.offset(at), ensureNL(src[:doc.offset(at)], b.String()))
	return verifyParent(src, out, path, func(m map[string]any) {
		e := map[string]any{}
		for _, f := range fields {
			if !f.Remove {
				e[f.Key] = normalize(f.Value)
			}
		}
		m[key] = e
	})
}

// RemoveEntry deletes the entry `key` of the mapping at path.
func RemoveEntry(src []byte, path, key string) ([]byte, error) {
	if rest, ok := cutBOM(src); ok {
		out, err := RemoveEntry(rest, path, key)
		return withBOM(out, err)
	}
	doc, err := Parse(src)
	if err != nil {
		return nil, err
	}
	parent, err := mappingAt(doc, path)
	if err != nil {
		return nil, err
	}
	k, v, idx := pair(parent, key)
	if k == nil {
		return nil, fmt.Errorf("%w: %s.%s", ErrNoEntry, path, key)
	}
	start, end := k.Line-1, doc.spanEnd(v)
	n := doc.numLines()
	blank := func(i int) bool { return i >= 0 && i < n && len(bytes.TrimSpace(doc.line(i))) == 0 }
	switch {
	case blank(start-1) && blank(end):
		end++
	case idx == len(parent.Content)/2-1 && blank(start-1):
		start--
	}
	out := splice(src, doc.offset(start), doc.offset(end), "")
	return verifyParent(src, out, path, func(m map[string]any) { delete(m, key) })
}

// AddItem appends one item to the list at path (after its last item). item is
// the text after "- " (for example `ref: {from: a.b, to: c.d}`); want is the
// value it must parse to. When the list does not exist and path is a single
// top-level key, `path:` and the item are appended at the end of the file.
func AddItem(src []byte, path, item string, want any) ([]byte, error) {
	if rest, ok := cutBOM(src); ok {
		out, err := AddItem(rest, path, item, want)
		return withBOM(out, err)
	}
	doc, err := Parse(src)
	if err != nil {
		return nil, err
	}
	n, ok := doc.Lookup(path)
	var out []byte
	switch {
	case !ok:
		if strings.Contains(path, ".") || doc.Root == nil || doc.Root.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%w: cannot create %s", ErrUnsupported, displayPath(path))
		}
		text := path + ":\n  - " + item + "\n"
		if len(src) > 0 && !bytes.HasSuffix(src, []byte("\n\n")) {
			text = "\n" + text
		}
		out = splice(src, len(src), len(src), ensureNL(src, text))
	case n.Kind == yaml.SequenceNode && n.Style&yaml.FlowStyle == 0 && len(n.Content) > 0:
		dash := indentOfItem(doc, n.Content[0])
		at := doc.spanEnd(n.Content[len(n.Content)-1])
		out = splice(src, doc.offset(at), doc.offset(at), ensureNL(src[:doc.offset(at)], pad(dash)+"- "+item+"\n"))
	default:
		return nil, fmt.Errorf("%w: %s is empty or written inline; add the first item by hand", ErrUnsupported, displayPath(path))
	}
	return verifyList(src, out, path, func(l []any) []any { return append(l, normalize(want)) })
}

// RemoveItem deletes item index of the list at path.
func RemoveItem(src []byte, path string, index int) ([]byte, error) {
	if rest, ok := cutBOM(src); ok {
		out, err := RemoveItem(rest, path, index)
		return withBOM(out, err)
	}
	doc, err := Parse(src)
	if err != nil {
		return nil, err
	}
	n, ok := doc.Lookup(path)
	if !ok || n.Kind != yaml.SequenceNode || n.Style&yaml.FlowStyle != 0 || index < 0 || index >= len(n.Content) {
		return nil, fmt.Errorf("%w: cannot remove item %d of %s", ErrNoEntry, index, displayPath(path))
	}
	it := n.Content[index]
	start := it.Line - 1
	if it.Kind == yaml.MappingNode && len(it.Content) > 0 {
		start = it.Content[0].Line - 1
	}
	end := doc.spanEnd(it)
	if len(n.Content) == 1 {
		if strings.Contains(path, ".") {
			return nil, fmt.Errorf("%w: removing the last item of %s leaves an empty list; remove the key by hand", ErrUnsupported, displayPath(path))
		}
		return RemoveEntry(src, "", path) // the list goes with its last item
	}
	out := splice(src, doc.offset(start), doc.offset(end), "")
	return verifyList(src, out, path, func(l []any) []any { return append(append([]any{}, l[:index]...), l[index+1:]...) })
}

func indentOfItem(doc *Doc, it *yaml.Node) int {
	// the dash sits before the item's first node on its line
	line := doc.line(it.Line - 1)
	i := bytes.IndexByte(line, '-')
	if i < 0 {
		return it.Column - 3
	}
	return i
}

// verifyEntry checks that out decodes to the data of src with mutate applied
// to the entry `key` of the mapping at path.
func verifyEntry(src, out []byte, path, key string, mutate func(map[string]any)) ([]byte, error) {
	return verifyParent(src, out, path, func(m map[string]any) {
		if e, _ := m[key].(map[string]any); e != nil {
			mutate(e)
		}
	})
}

// verifyParent checks that out decodes to the data of src with mutate applied
// to the mapping at path.
func verifyParent(src, out []byte, path string, mutate func(map[string]any)) ([]byte, error) {
	return verifyTree(src, out, func(tree map[string]any) error {
		m, err := descend(tree, path)
		if err != nil {
			return err
		}
		mutate(m)
		return nil
	})
}

// verifyList checks that out decodes to src with mutate applied to the list at path.
func verifyList(src, out []byte, path string, mutate func([]any) []any) ([]byte, error) {
	parent, last := "", path
	if i := strings.LastIndex(path, "."); i >= 0 {
		parent, last = path[:i], path[i+1:]
	}
	return verifyTree(src, out, func(tree map[string]any) error {
		m := tree
		if parent != "" {
			var err error
			if m, err = descend(tree, parent); err != nil {
				return err
			}
		}
		l, _ := m[last].([]any)
		m[last] = mutate(l)
		return nil
	})
}

func descend(tree map[string]any, path string) (map[string]any, error) {
	cur := tree
	if path == "" {
		return cur, nil
	}
	for _, seg := range strings.Split(path, ".") {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrNoEntry, path)
		}
		cur = next
	}
	return cur, nil
}

func verifyTree(src, out []byte, mutate func(map[string]any) error) ([]byte, error) {
	before, err := Parse(src)
	if err != nil {
		return nil, err
	}
	after, err := Parse(out)
	if err != nil {
		return nil, fmt.Errorf("edited file no longer parses: %w", err)
	}
	want, _ := before.Value().(map[string]any)
	if want == nil {
		want = map[string]any{}
	}
	if err := mutate(want); err != nil {
		return nil, err
	}
	if canon(normalize(want)) != canon(normalize(after.Value())) {
		return nil, errors.New("internal error: edited file does not decode to the intended data; nothing was written")
	}
	return out, nil
}

// Value is the decoded document (nil for an empty one).
func (d *Doc) Value() any {
	if d.Root == nil {
		return nil
	}
	return Value(d.Root)
}

// normalize makes values comparable through JSON (Flow and rawText cannot occur in decoded data).
func normalize(v any) any {
	switch x := v.(type) {
	case Flow:
		m := map[string]any{}
		for k, e := range x.Values {
			m[k] = normalize(e)
		}
		return m
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	case map[string]any:
		m := map[string]any{}
		for k, e := range x {
			m[k] = normalize(e)
		}
		return m
	}
	return v
}
