// Package yamledit changes single records of a YAML list without
// re-serialising the file: it finds the line span of one record and splices
// only those lines, so every other byte (comments, blank lines, folded text,
// quoting) stays as it was.
package yamledit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Doc is a parsed YAML file together with its line index.
type Doc struct {
	Src    []byte
	Root   *yaml.Node // top-level content node; nil for an empty document
	Dups   []Dup      // duplicate mapping keys (the last one wins when decoded)
	starts []int      // byte offset of each line start
}

// Dup is a mapping key that appears twice in the same mapping.
type Dup struct {
	Key  string
	Line int // 1-based line of the second occurrence
}

// ErrMultiDocument is returned for files with more than one YAML document.
var ErrMultiDocument = errors.New("multiple YAML documents (---) in one file are not supported")

// ErrPath means the dotted path of a collection or note does not lead to a list.
var ErrPath = errors.New("bad path")

// Parse parses src. An empty or comment-only file is a valid empty Doc.
func Parse(src []byte) (*Doc, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var n yaml.Node
	if err := dec.Decode(&n); err != nil && err != io.EOF {
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, ErrMultiDocument
	} else if err != io.EOF {
		return nil, err
	}
	d := &Doc{Src: src}
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		d.Root = n.Content[0]
		d.Dups = findDups(d.Root, nil)
	}
	d.starts = []int{0}
	for i, b := range src {
		if b == '\n' && i+1 < len(src) {
			d.starts = append(d.starts, i+1)
		}
	}
	if len(src) == 0 {
		d.starts = nil
	}
	return d, nil
}

func findDups(n *yaml.Node, out []Dup) []Dup {
	if n == nil || n.Kind == yaml.AliasNode {
		return out
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Value != "<<" {
				if seen[k.Value] {
					out = append(out, Dup{Key: k.Value, Line: k.Line})
				}
				seen[k.Value] = true
			}
		}
	}
	for _, c := range n.Content {
		out = findDups(c, out)
	}
	return out
}

func (d *Doc) numLines() int { return len(d.starts) }

// line returns line i (0-based) without its newline.
func (d *Doc) line(i int) []byte {
	s := d.starts[i]
	e := len(d.Src)
	if i+1 < len(d.starts) {
		e = d.starts[i+1]
	}
	return bytes.TrimRight(d.Src[s:e], "\r\n")
}

// offset returns the byte offset of the start of line i (len(src) past the last line).
func (d *Doc) offset(i int) int {
	if i >= len(d.starts) {
		return len(d.Src)
	}
	return d.starts[i]
}

// Lookup returns the node at a dotted path ("" is the root).
func (d *Doc) Lookup(path string) (*yaml.Node, bool) {
	n := d.Root
	if n == nil {
		return nil, false
	}
	if path == "" {
		return n, true
	}
	for _, seg := range strings.Split(path, ".") {
		n = resolveAlias(n)
		if n.Kind != yaml.MappingNode {
			return nil, false
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == seg {
				next = n.Content[i+1]
				break
			}
		}
		if next == nil {
			return nil, false
		}
		n = next
	}
	return n, true
}

func resolveAlias(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// Item is one record (a mapping in a sequence) and its line span.
type Item struct {
	Node       *yaml.Node
	StartLine  int // first line of the record (the "- " line), 0-based
	EndLine    int // one past the last line of the record
	DashCol    int // column of "-"
	KeyCol     int // column where the record content starts
	Prefix     string
	Flow       bool
	Start, End int // byte offsets of the span
}

// List is the sequence at a path.
type List struct {
	Doc    *Doc
	Path   string
	Exists bool // false when the path is absent or the value is null
	Seq    *yaml.Node
	Items  []Item
}

// Records locates the list at path. A missing path or null value is an empty list.
func (d *Doc) Records(path string) (*List, error) {
	l := &List{Doc: d, Path: path}
	n, ok := d.Lookup(path)
	if !ok {
		if path == "" && d.Root == nil {
			return l, nil // an empty file is an empty top-level list
		}
		return nil, fmt.Errorf("%w: %s does not exist in the file", ErrPath, displayPath(path))
	}
	n = resolveAlias(n)
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return l, nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%w: %s is not a list", ErrPath, displayPath(path))
	}
	l.Exists, l.Seq = true, n
	for i, it := range n.Content {
		it = resolveAlias(it)
		item := Item{Node: it}
		if it.Kind != yaml.MappingNode {
			// Scalars and nested lists have no editable span; keep a slot so indexes match.
			l.Items = append(l.Items, item)
			continue
		}
		if err := d.locate(&item, n.Content, i); err != nil {
			return nil, err
		}
		l.Items = append(l.Items, item)
	}
	return l, nil
}

func displayPath(p string) string {
	if p == "" {
		return "the document root"
	}
	return "path " + p
}

// locate fills the span of item i of a sequence.
func (d *Doc) locate(item *Item, siblings []*yaml.Node, i int) error {
	n := item.Node
	item.StartLine = n.Line - 1
	line := d.line(item.StartLine)
	col := byteCol(line, n.Column-1)
	prefix := string(line[:col])
	trim := strings.TrimLeft(prefix, " ")
	if !strings.HasPrefix(trim, "-") || strings.TrimSpace(strings.TrimPrefix(trim, "-")) != "" {
		return fmt.Errorf("line %d: unsupported record layout (expected \"- \" before the record)", n.Line)
	}
	item.Prefix = prefix
	item.DashCol = len(prefix) - len(trim)
	item.KeyCol = col
	item.Flow = n.Style&yaml.FlowStyle != 0
	last := maxLine(n) // 1-based
	boundary := d.numLines()
	if i+1 < len(siblings) {
		boundary = resolveAlias(siblings[i+1]).Line - 1
	} else if nl := nextNodeLine(d.Root, last); nl > 0 {
		boundary = nl - 1
	}
	end := boundary
	for end > last && d.trimmable(end-1, item.DashCol) {
		end--
	}
	if end < last {
		end = last
	}
	item.EndLine = end
	item.Start, item.End = d.offset(item.StartLine), d.offset(end)
	return nil
}

// trimmable reports whether line i is a blank line or a comment that sits at
// or left of the record's dash, i.e. does not belong to the record.
func (d *Doc) trimmable(i, dashCol int) bool {
	l := d.line(i)
	if bytes.HasPrefix(l, []byte("---")) || bytes.HasPrefix(l, []byte("...")) {
		return true // document markers never belong to a record
	}
	t := bytes.TrimLeft(l, " \t")
	if len(t) == 0 {
		return true
	}
	return t[0] == '#' && len(l)-len(t) <= dashCol
}

func maxLine(n *yaml.Node) int {
	m := n.Line
	if n.Kind == yaml.AliasNode {
		return m
	}
	for _, c := range n.Content {
		if x := maxLine(c); x > m {
			m = x
		}
	}
	return m
}

// nextNodeLine returns the smallest node start line greater than after, or 0.
func nextNodeLine(n *yaml.Node, after int) int {
	best := 0
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Line > after && (best == 0 || n.Line < best) {
			best = n.Line
		}
		if n.Kind == yaml.AliasNode {
			return
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(n)
	return best
}

// byteCol converts a rune column of line to a byte offset.
func byteCol(line []byte, runeCol int) int {
	off := 0
	for i := 0; i < runeCol && off < len(line); i++ {
		_, w := utf8.DecodeRune(line[off:])
		off += w
	}
	return off
}

// Value converts a node to plain Go data (map[string]any, []any, string,
// bool, int, float64, nil). Timestamps stay strings, as written.
func Value(n *yaml.Node) any {
	n = resolveAlias(n)
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = Value(n.Content[i+1])
		}
		return m
	case yaml.SequenceNode:
		s := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			s = append(s, Value(c))
		}
		return s
	case yaml.ScalarNode:
		if n.ShortTag() == "!!timestamp" {
			return n.Value
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return n.Value
		}
		return v
	}
	return nil
}

// Item value helpers ---------------------------------------------------------

// Value decodes item i of the list.
func (l *List) Value(i int) any { return Value(l.Items[i].Node) }

// ErrUnsupported marks layouts the splicer refuses to touch.
var ErrUnsupported = errors.New("unsupported layout")
