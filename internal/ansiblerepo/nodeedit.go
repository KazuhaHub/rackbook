package ansiblerepo

// Edits of one node of a YAML file, for the editors that are not the raw
// editor: the settings of one feature in a host's variables, and which hosts
// a group lists in the inventory.
//
// The edit is made twice. First on the yaml.v3 node tree, which keeps every
// comment but re-lays the whole file (blank lines go); that result is the
// reference. Then as a splice into the original text, which keeps every byte
// outside the edited block. The splice is used only when it decodes to the same
// data as the reference; otherwise the reference is used.

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Setting is one setting of a feature, in the order it is written.
type Setting struct {
	Name  string
	Value any
}

// MembershipChange adds a host to a group or removes it.
type MembershipChange struct {
	Host   string `json:"host"`
	Group  string `json:"group"`
	Member bool   `json:"member"`
}

func parseDoc(b []byte) (*yaml.Node, *yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, nil, err
	}
	if doc.Kind == 0 {
		return &doc, nil, nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, nil, fmt.Errorf("not one YAML document")
	}
	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return &doc, nil, nil
	}
	if root.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("the top level is not a mapping")
	}
	return &doc, root, nil
}

func encodeNode(n *yaml.Node, indent int) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(indent)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mapKeyIndex(m *yaml.Node, key string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

func newMapping() *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"} }

func scalarKey(k string) *yaml.Node {
	var n yaml.Node
	_ = n.Encode(k)
	return &n
}

func valueNode(v any) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return &n, nil
}

func decodeAny(n *yaml.Node) any {
	var v any
	if n == nil {
		return nil
	}
	_ = n.Decode(&v)
	return v
}

// mergeSettings builds the new settings mapping of a feature from the old node
// (comments and unknown keys kept) and the wanted settings.
func mergeSettings(old *yaml.Node, want []Setting) (*yaml.Node, error) {
	out := newMapping()
	wanted := map[string]any{}
	for _, s := range want {
		wanted[s.Name] = s.Value
	}
	if old != nil && old.Kind == yaml.MappingNode {
		out.HeadComment, out.LineComment, out.FootComment = old.HeadComment, old.LineComment, old.FootComment
		for i := 0; i+1 < len(old.Content); i += 2 {
			k, v := old.Content[i], old.Content[i+1]
			w, isWanted := wanted[k.Value]
			if _, known := knownIn(want, k.Value); !known {
				out.Content = append(out.Content, k, v) // not ours to touch
				continue
			}
			if !isWanted || w == nil {
				continue // reset to the default: the key goes
			}
			if reflect.DeepEqual(normalize(decodeAny(v)), normalize(w)) {
				out.Content = append(out.Content, k, v)
				continue
			}
			nv, err := valueNode(w)
			if err != nil {
				return nil, err
			}
			nv.HeadComment, nv.LineComment, nv.FootComment = v.HeadComment, v.LineComment, v.FootComment
			out.Content = append(out.Content, k, nv)
		}
	}
	for _, s := range want {
		if s.Value == nil || mapKeyIndex(out, s.Name) >= 0 {
			continue
		}
		nv, err := valueNode(s.Value)
		if err != nil {
			return nil, err
		}
		out.Content = append(out.Content, scalarKey(s.Name), nv)
	}
	return out, nil
}

// knownIn reports whether name is one the caller is editing: every name in the
// list, whatever its value (a nil value resets it).
func knownIn(want []Setting, name string) (Setting, bool) {
	for _, s := range want {
		if s.Name == name {
			return s, true
		}
	}
	return Setting{}, false
}

// SetFeature sets features.<name> of a host_vars file: removes the entry when
// !enabled, else gives it these settings (keys the caller does not list are
// kept as they are). It returns the new file.
func SetFeature(content []byte, name string, enabled bool, settings []Setting, known []string) ([]byte, error) {
	// settings the form knows but did not set are reset: list them with nil
	have := map[string]bool{}
	for _, s := range settings {
		have[s.Name] = true
	}
	for _, k := range known {
		if !have[k] {
			settings = append(settings, Setting{Name: k})
		}
	}
	doc, root, err := parseDoc(content)
	if err != nil {
		return nil, err
	}
	if root == nil {
		root = newMapping()
		if doc.Kind == 0 {
			*doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
		} else {
			doc.Content[0] = root
		}
	}
	if err := nodeSetFeature(root, name, enabled, settings); err != nil {
		return nil, err
	}
	reference, err := encodeNode(doc, 2)
	if err != nil {
		return nil, err
	}
	if spliced, ok := spliceFeature(content, name, enabled, settings); ok && sameData(spliced, reference) {
		return spliced, nil
	}
	return reference, nil
}

func nodeSetFeature(root *yaml.Node, name string, enabled bool, settings []Setting) error {
	fi := mapKeyIndex(root, "features")
	if !enabled {
		if fi < 0 || root.Content[fi+1].Kind != yaml.MappingNode {
			return nil
		}
		f := root.Content[fi+1]
		if i := mapKeyIndex(f, name); i >= 0 {
			f.Content = append(f.Content[:i], f.Content[i+2:]...)
		}
		if len(f.Content) == 0 {
			root.Content = append(root.Content[:fi], root.Content[fi+2:]...)
		}
		return nil
	}
	if fi >= 0 && root.Content[fi+1].Kind != yaml.MappingNode && !isNull(root.Content[fi+1]) {
		return fmt.Errorf("features is not a mapping")
	}
	var f *yaml.Node
	if fi < 0 {
		f = newMapping()
		root.Content = append(root.Content, scalarKey("features"), f)
	} else {
		f = root.Content[fi+1]
		if f.Kind != yaml.MappingNode {
			f = newMapping()
			root.Content[fi+1] = f
		}
	}
	i := mapKeyIndex(f, name)
	var old *yaml.Node
	if i >= 0 {
		old = f.Content[i+1]
	}
	merged, err := mergeSettings(old, settings)
	if err != nil {
		return err
	}
	if i >= 0 {
		f.Content[i+1] = merged
	} else {
		f.Content = append(f.Content, scalarKey(name), merged)
	}
	return nil
}

// sameData reports whether two YAML texts decode to the same data (an empty
// mapping and null count as the same).
func sameData(a, b []byte) bool {
	var x, y any
	if yaml.Unmarshal(a, &x) != nil || yaml.Unmarshal(b, &y) != nil {
		return false
	}
	if _, iss := parseMapFile("", a); len(iss) > 0 {
		return false
	}
	return reflect.DeepEqual(normalize(x), normalize(y))
}

func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			return nil
		}
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = normalize(e)
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, e := range t {
			l[i] = normalize(e)
		}
		return l
	case float64:
		if t == float64(int(t)) {
			return int(t)
		}
	case int64:
		return int(t)
	}
	return v
}

// Text splicing ------------------------------------------------------------

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

func blank(l string) bool { return strings.TrimSpace(l) == "" }

// blockEnd is the index of the last line of the block that starts at line
// `from` (a key at column col): the following lines that are blank or indented
// deeper, minus trailing blank lines.
func blockEnd(lines []string, from, col int) int {
	end := from
	for i := from + 1; i < len(lines); i++ {
		if blank(lines[i]) {
			continue
		}
		if indentOf(lines[i]) > col {
			end = i
			continue
		}
		break
	}
	return end
}

// headStart moves `from` up over the comment lines that sit directly above it
// at the same column.
func headStart(lines []string, from, col int) int {
	for from > 0 {
		p := lines[from-1]
		if strings.HasPrefix(strings.TrimLeft(p, " "), "#") && indentOf(p) == col {
			from--
			continue
		}
		break
	}
	return from
}

func splitKeepLines(b []byte) []string {
	s := string(b)
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func joinLines(l []string) []byte {
	if len(l) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(l, "\n") + "\n")
}

func indentBlock(text []byte, n int) []string {
	pad := strings.Repeat(" ", n)
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(string(text), "\n"), "\n") {
		if l == "" {
			out = append(out, "")
		} else {
			out = append(out, pad+l)
		}
	}
	return out
}

func splice(lines []string, lo, hi int, with []string) []string {
	out := append([]string{}, lines[:lo]...)
	out = append(out, with...)
	return append(out, lines[hi+1:]...)
}

func flowOrAlias(n *yaml.Node) bool { return n.Style&yaml.FlowStyle != 0 || n.Kind == yaml.AliasNode }

func spliceFeature(content []byte, name string, enabled bool, settings []Setting) ([]byte, bool) {
	_, root, err := parseDoc(content)
	if err != nil {
		return nil, false
	}
	lines := splitKeepLines(content)
	section := func(old *yaml.Node, unit int) ([]string, bool) {
		merged, err := mergeSettings(old, settings)
		if err != nil {
			return nil, false
		}
		f := newMapping()
		f.Content = append(f.Content, scalarKey(name), merged)
		m := newMapping()
		m.Content = append(m.Content, scalarKey("features"), f)
		b, err := encodeNode(m, unit)
		if err != nil {
			return nil, false
		}
		return splitKeepLines(b), true
	}
	appendSection := func() ([]byte, bool) {
		sec, ok := section(nil, 2)
		if !ok {
			return nil, false
		}
		out := append([]string{}, lines...)
		if len(out) > 0 && !blank(out[len(out)-1]) {
			out = append(out, "")
		}
		return joinLines(append(out, sec...)), true
	}
	if root == nil {
		if len(lines) > 0 && !onlyComments(lines) {
			return nil, false
		}
		if !enabled {
			return append([]byte{}, content...), true
		}
		return appendSection()
	}
	if flowOrAlias(root) {
		return nil, false
	}
	fi := mapKeyIndex(root, "features")
	if fi < 0 {
		if !enabled {
			return append([]byte{}, content...), true
		}
		return appendSection()
	}
	fk, fv := root.Content[fi], root.Content[fi+1]
	if fv.Kind != yaml.MappingNode || flowOrAlias(fv) || len(fv.Content) == 0 {
		return nil, false
	}
	fcol := fk.Column - 1
	childCol := fv.Content[0].Column - 1
	unit := min(8, max(2, childCol-fcol))
	ii := mapKeyIndex(fv, name)
	if ii < 0 {
		if !enabled {
			return append([]byte{}, content...), true
		}
		sec, ok := section(nil, unit)
		if !ok || len(sec) < 2 {
			return nil, false
		}
		at := blockEnd(lines, fk.Line-1, fcol)
		return joinLines(splice(lines, at+1, at, indentBlock([]byte(strings.Join(sec[1:], "\n")+"\n"), childCol-unit))), true
	}
	ik, iv := fv.Content[ii], fv.Content[ii+1]
	col := ik.Column - 1
	start := ik.Line - 1
	end := blockEnd(lines, start, col)
	if !enabled {
		if len(fv.Content) == 2 { // the last feature: the section goes
			fs := headStart(lines, fk.Line-1, fcol)
			return joinLines(splice(lines, fs, blockEnd(lines, fk.Line-1, fcol), nil)), true
		}
		return joinLines(splice(lines, headStart(lines, start, col), end, nil)), true
	}
	sec, ok := section(iv, unit)
	if !ok || len(sec) < 2 {
		return nil, false
	}
	// the item's key keeps its own line comment; the section's lines below "features:" are the item
	item := indentBlock([]byte(strings.Join(sec[1:], "\n")+"\n"), col-unit)
	if ik.LineComment != "" && len(item) > 0 && !strings.Contains(item[0], "#") && !strings.HasSuffix(strings.TrimSpace(item[0]), "|") {
		item[0] += " " + ik.LineComment
	}
	return joinLines(splice(lines, start, end, item)), true
}

func onlyComments(lines []string) bool {
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			return false
		}
	}
	return true
}

// Memberships --------------------------------------------------------------

// Membership is who is listed directly in each group of the inventory.
type Membership struct {
	Groups []string            `json:"groups"`
	Hosts  []string            `json:"hosts"`
	Direct map[string][]string `json:"direct"` // host -> groups listing it
}

// MembershipOf reads the groups of all.children and the hosts they list.
func MembershipOf(inventory []byte) (*Membership, error) {
	g, iss := parseInventoryShape(inventory)
	if len(iss) > 0 {
		return nil, fmt.Errorf("inventory/hosts.yml: %s", iss[0].Message)
	}
	m := &Membership{Groups: append([]string{}, g.order...), Hosts: []string{}, Direct: map[string][]string{}}
	seen := map[string]bool{}
	for _, grp := range g.order {
		for _, h := range g.hosts[grp] {
			if !seen[h] {
				seen[h] = true
				m.Hosts = append(m.Hosts, h)
			}
			m.Direct[h] = append(m.Direct[h], grp)
		}
	}
	sort.Strings(m.Hosts)
	return m, nil
}

// SetMembership applies the changes to inventory/hosts.yml.
func SetMembership(content []byte, changes []MembershipChange) ([]byte, error) {
	cur := content
	for _, c := range changes {
		next, err := setOneMembership(cur, c)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

func groupNode(root *yaml.Node, group string) (*yaml.Node, *yaml.Node) {
	ch := mapGet(mapGet(root, "all"), "children")
	if ch == nil || ch.Kind != yaml.MappingNode {
		return nil, nil
	}
	if i := mapKeyIndex(ch, group); i >= 0 {
		return ch.Content[i], ch.Content[i+1]
	}
	return nil, nil
}

func setOneMembership(content []byte, c MembershipChange) ([]byte, error) {
	if !hostNameRe.MatchString(c.Host) {
		return nil, fmt.Errorf("%q is not a host name", c.Host)
	}
	doc, root, err := parseDoc(content)
	if err != nil || root == nil {
		return nil, fmt.Errorf("inventory/hosts.yml cannot be edited: %v", err)
	}
	gk, gv := groupNode(root, c.Group)
	if gk == nil {
		return nil, fmt.Errorf("no group %q", c.Group)
	}
	if isNull(gv) {
		gv.Kind, gv.Tag, gv.Value = yaml.MappingNode, "!!map", ""
	}
	hostsNode := mapGet(gv, "hosts")
	if isNull(hostsNode) {
		hostsNode = nil
	}
	listed := false
	if hostsNode != nil {
		listed = mapKeyIndex(hostsNode, c.Host) >= 0
	}
	if listed == c.Member {
		return content, nil
	}
	// reference: the node edit
	if c.Member {
		if hi := mapKeyIndex(gv, "hosts"); hi < 0 {
			hostsNode = newMapping()
			gv.Content = append(gv.Content, scalarKey("hosts"), hostsNode)
		} else if hostsNode == nil {
			hostsNode = newMapping()
			gv.Content[hi+1] = hostsNode
		}
		hostsNode.Content = append(hostsNode.Content, scalarKey(c.Host), &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: ""})
	} else {
		i := mapKeyIndex(hostsNode, c.Host)
		hostsNode.Content = append(hostsNode.Content[:i], hostsNode.Content[i+2:]...)
	}
	reference, err := encodeNode(doc, 2)
	if err != nil {
		return nil, err
	}
	if sp, ok := spliceMembership(content, c); ok && sameData(sp, reference) {
		return sp, nil
	}
	return reference, nil
}

func spliceMembership(content []byte, c MembershipChange) ([]byte, bool) {
	_, root, err := parseDoc(content)
	if err != nil || root == nil {
		return nil, false
	}
	lines := splitKeepLines(content)
	gk, gv := groupNode(root, c.Group)
	if gk == nil || gv.Kind != yaml.MappingNode || flowOrAlias(gv) || len(gv.Content) == 0 {
		return nil, false
	}
	gcol := gk.Column - 1
	hi := mapKeyIndex(gv, "hosts")
	if hi < 0 {
		if !c.Member {
			return nil, false
		}
		kcol := gv.Content[0].Column - 1
		unit := max(2, kcol-gcol)
		at := blockEnd(lines, gk.Line-1, gcol)
		return joinLines(splice(lines, at+1, at, []string{strings.Repeat(" ", kcol) + "hosts:", strings.Repeat(" ", kcol+unit) + c.Host + ":"})), true
	}
	hk, hv := gv.Content[hi], gv.Content[hi+1]
	if hv.Kind != yaml.MappingNode || flowOrAlias(hv) || len(hv.Content) == 0 {
		return nil, false
	}
	hcol := hk.Column - 1
	ecol := hv.Content[0].Column - 1
	if c.Member {
		at := blockEnd(lines, hk.Line-1, hcol)
		return joinLines(splice(lines, at+1, at, []string{strings.Repeat(" ", ecol) + c.Host + ":"})), true
	}
	i := mapKeyIndex(hv, c.Host)
	k := hv.Content[i]
	start := k.Line - 1
	end := blockEnd(lines, start, k.Column-1)
	return joinLines(splice(lines, headStart(lines, start, k.Column-1), end, nil)), true
}
