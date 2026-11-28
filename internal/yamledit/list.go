package yamledit

import (
	"bytes"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// SetStringList makes the list of strings at path (the last segment is the
// key, the rest is the mapping that holds it) equal to want, touching only the
// lines of the entries that change:
//
//   - a string that is in the list and in want stays where it is, with its
//     quoting and any comment on its line;
//   - a string that is in the list but not in want is removed with its line;
//   - a string in want that is not in the list is appended at the end, in the
//     order given;
//   - a list that ends up empty is written as `key: []`.
//
// Both layouts of a list are handled, a block list (one `- item` line each) and
// a flow list on one line (`[a, b]`, a comment after the bracket is kept). A key
// that is missing is added at the end of its mapping (as a flow list); a key with
// no value is filled in. Anything else (a list over several lines in flow style,
// an alias, an item that is not a plain string, a mapping in flow style) is
// refused with ErrUnsupported, so the caller can say "edit it by hand". The
// result is checked to decode to the intended list; if it does not, nothing is
// returned. The mapping that holds the key must exist.
//
// The order the list ends up in is the order of the file for what stays,
// followed by the additions. Callers that treat a list as a set (the role lists
// do) need nothing more.
func SetStringList(src []byte, path string, want []string) ([]byte, error) {
	if rest, ok := cutBOM(src); ok {
		out, err := SetStringList(rest, path, want)
		return withBOM(out, err)
	}
	parentPath, key := "", path
	if i := strings.LastIndex(path, "."); i >= 0 {
		parentPath, key = path[:i], path[i+1:]
	}
	doc, err := Parse(src)
	if err != nil {
		return nil, err
	}
	parent, err := mappingAt(doc, parentPath)
	if err != nil {
		return nil, err
	}
	k, v, _ := pair(parent, key)
	var have []string
	if v != nil {
		if have, err = stringItems(v, path); err != nil {
			return nil, err
		}
	}
	keep, add := diffStrings(have, want)
	final := append(append([]string{}, keep...), add...)
	if len(keep) == len(have) && len(add) == 0 {
		return src, nil // nothing to change
	}
	var out []byte
	switch {
	case v == nil:
		out, err = insertKey(doc, src, parent, key, final)
	case v.Kind == yaml.ScalarNode && v.Tag == "!!null" && v.Value == "":
		out, err = fillEmpty(doc, src, k, final)
	case v.Kind == yaml.SequenceNode && v.Style&yaml.FlowStyle != 0:
		out, err = rewriteFlow(doc, src, k, v, final)
	default: // a block list
		out, err = rewriteBlock(doc, src, k, v, final)
	}
	if err != nil {
		return nil, err
	}
	return verifyList(src, out, path, func([]any) []any {
		l := make([]any, len(final))
		for i, s := range final {
			l[i] = s
		}
		return l
	})
}

// stringItems returns the strings of a list node, or ErrUnsupported when the
// node is not a list of plain strings that the splicer can handle.
func stringItems(v *yaml.Node, path string) ([]string, error) {
	switch {
	case v.Kind == yaml.ScalarNode && v.Tag == "!!null" && v.Value == "":
		return nil, nil // `key:` with nothing after it
	case v.Kind == yaml.ScalarNode && v.Tag == "!!null":
		return nil, fmt.Errorf("%w: %s is written as %q; make it a list by hand", ErrUnsupported, displayPath(path), v.Value)
	case v.Kind != yaml.SequenceNode:
		return nil, fmt.Errorf("%w: %s is not a list", ErrUnsupported, displayPath(path))
	}
	out := make([]string, 0, len(v.Content))
	for _, it := range v.Content {
		if it.Kind != yaml.ScalarNode || it.Tag != "!!str" || it.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || maxLine(it) != it.Line {
			return nil, fmt.Errorf("%w: an item of %s is not a plain one-line string; edit the list by hand", ErrUnsupported, displayPath(path))
		}
		out = append(out, it.Value)
	}
	return out, nil
}

// diffStrings splits want against have: keep is the part of have that stays (in
// have's order), add is what want has that have lacks (in want's order). Repeats
// are counted: a string listed twice in have and once in want keeps one.
func diffStrings(have, want []string) (keep, add []string) {
	left := map[string]int{}
	for _, s := range want {
		left[s]++
	}
	for _, s := range have {
		if left[s] > 0 {
			left[s]--
			keep = append(keep, s)
		}
	}
	for _, s := range want { // what is left of want is new, in want's order
		if left[s] > 0 {
			left[s]--
			add = append(add, s)
		}
	}
	return keep, add
}

// flowList renders strings as `[a, b]`; styles gives the quoting hint of each
// one that was in the file (by position in items), 0 for a new one.
func flowList(items []string, styles map[int]yaml.Style) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = scalar(s, true, styles[i])
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// insertKey adds `key: [..]` at the end of the block mapping parent.
func insertKey(doc *Doc, src []byte, parent *yaml.Node, key string, final []string) ([]byte, error) {
	if len(parent.Content) == 0 {
		return nil, fmt.Errorf("%w: cannot add %s to an empty mapping; add it by hand", ErrUnsupported, key)
	}
	indent := parent.Content[0].Column - 1
	at := doc.offset(doc.spanEnd(parent.Content[len(parent.Content)-1]))
	text := pad(indent) + keyScalar(key, false) + ": " + flowList(final, nil) + "\n"
	return splice(src, at, at, ensureNL(src[:at], text)), nil
}

// fillEmpty writes the list after a `key:` that has no value.
func fillEmpty(doc *Doc, src []byte, k *yaml.Node, final []string) ([]byte, error) {
	line := doc.line(k.Line - 1)
	colon, ok := keyColon(line, byteCol(line, k.Column-1))
	if !ok {
		return nil, fmt.Errorf("%w: cannot find the colon of %s", ErrUnsupported, k.Value)
	}
	at := doc.offset(k.Line-1) + colon + 1
	return splice(src, at, at, " "+flowList(final, nil)), nil
}

// keyColon finds the colon that ends the key starting at byte offset from.
func keyColon(line []byte, from int) (int, bool) {
	for i := from; i < len(line); i++ {
		switch line[i] {
		case '"', '\'':
			end, ok := closeQuote(line, i)
			if !ok {
				return 0, false
			}
			i = end
		case ':':
			return i, true
		}
	}
	return 0, false
}

// closeQuote returns the index of the quote that closes the one at i.
func closeQuote(line []byte, i int) (int, bool) {
	q := line[i]
	for j := i + 1; j < len(line); j++ {
		switch {
		case q == '"' && line[j] == '\\':
			j++
		case line[j] == q && q == '\'' && j+1 < len(line) && line[j+1] == '\'':
			j++
		case line[j] == q:
			return j, true
		}
	}
	return 0, false
}

// rewriteFlow replaces the `[...]` of a one-line flow list.
func rewriteFlow(doc *Doc, src []byte, k, v *yaml.Node, final []string) ([]byte, error) {
	if maxLine(v) != v.Line {
		return nil, fmt.Errorf("%w: %s is a list over several lines in flow style; edit it by hand", ErrUnsupported, k.Value)
	}
	line := doc.line(v.Line - 1)
	open := byteCol(line, v.Column-1)
	if open >= len(line) || line[open] != '[' {
		return nil, fmt.Errorf("%w: cannot find the list of %s on its line", ErrUnsupported, k.Value)
	}
	end := -1
	depth := 0
scan:
	for i := open; i < len(line); i++ {
		switch line[i] {
		case '"', '\'':
			c, ok := closeQuote(line, i)
			if !ok {
				break scan
			}
			i = c
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				end = i
				break scan
			}
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("%w: the list of %s is not closed on its line; edit it by hand", ErrUnsupported, k.Value)
	}
	// keep the quoting of an item that stays: items are matched in file order
	var have []string
	for _, it := range v.Content {
		have = append(have, it.Value)
	}
	styles := map[int]yaml.Style{}
	used := make([]bool, len(have))
	for i, s := range final {
		for j, h := range have {
			if !used[j] && h == s {
				used[j] = true
				styles[i] = v.Content[j].Style
				break
			}
		}
	}
	base := doc.offset(v.Line - 1)
	return splice(src, base+open, base+end+1, flowList(final, styles)), nil
}

// rewriteBlock edits a block list line by line, or turns it into `key: []`.
func rewriteBlock(doc *Doc, src []byte, k, v *yaml.Node, final []string) ([]byte, error) {
	if v.Kind != yaml.SequenceNode || len(v.Content) == 0 {
		return nil, fmt.Errorf("%w: %s is not a list of items one to a line; edit it by hand", ErrUnsupported, k.Value)
	}
	if len(final) == 0 {
		// the whole list goes; the key stays, with an empty list, and so does a comment on its line
		line := doc.line(k.Line - 1)
		colon, ok := keyColon(line, byteCol(line, k.Column-1))
		if !ok {
			return nil, fmt.Errorf("%w: cannot find the colon of %s", ErrUnsupported, k.Value)
		}
		head := string(line[:colon+1]) + " []"
		if rest := bytes.TrimSpace(line[colon+1:]); len(rest) > 0 && rest[0] == '#' {
			head += "  " + string(rest)
		}
		start, end := doc.offset(k.Line-1), doc.offset(doc.spanEnd(v))
		return splice(src, start, end, head+"\n"), nil
	}
	// which items stay: file order, first occurrences first, as diffStrings counted them
	left := map[string]int{}
	for _, s := range final {
		left[s]++
	}
	var drop []int
	for i, it := range v.Content {
		if left[it.Value] > 0 {
			left[it.Value]--
		} else {
			drop = append(drop, i)
		}
	}
	// new items come after the last item of the list; the text is spliced from the bottom up
	keepCount := len(v.Content) - len(drop)
	added := final[keepCount:]
	out := src
	if len(added) > 0 {
		dash := indentOfItem(doc, v.Content[0])
		var text strings.Builder
		for _, s := range added {
			text.WriteString(pad(dash) + "- " + scalar(s, false, 0) + "\n")
		}
		at := doc.offset(doc.spanEnd(v.Content[len(v.Content)-1]))
		out = splice(out, at, at, ensureNL(src[:at], text.String()))
	}
	for i := len(drop) - 1; i >= 0; i-- {
		it := v.Content[drop[i]]
		start, end := doc.offset(it.Line-1), doc.offset(doc.spanEnd(it))
		out = splice(out, start, end, "")
	}
	return out, nil
}
