package yamledit

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

var (
	ipv6ish   = regexp.MustCompile(`^[-+]?[0-9a-fA-F:._]+$`) // also YAML 1.1 sexagesimal: "+1:30", "1_0:30"
	hasDigit  = regexp.MustCompile(`[0-9]`)
	dateStart = regexp.MustCompile(`^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}`) // YAML 1.1 timestamps, incl. "2001-12-14 21:59:43.10 -5"
)

// needsQuote reports whether s must be quoted to read back as the same string
// (by this library and by YAML 1.1 readers such as ansible's). Instead of a
// list of special characters it renders the scalar plain in its context and
// parses it back.
func needsQuote(s string, flow bool) bool {
	if s == "" || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == 0xFEFF {
			return true
		}
	}
	if strings.HasPrefix(s, "---") || strings.HasPrefix(s, "...") {
		return true
	}
	switch strings.ToLower(s) {
	case "y", "n", "yes", "no", "on", "off", "true", "false", "null", "~", "<<", "=":
		return true // "=" is the YAML 1.1 value key; PyYAML refuses it
	}
	if dateStart.MatchString(s) {
		return true
	}
	if strings.Contains(s, ":") && ipv6ish.MatchString(s) && hasDigit.MatchString(s) {
		return true // "2001:db8::1", "12:30": sexagesimal / ambiguous
	}
	return !roundTrips(s, flow)
}

// roundTrips renders s as a plain value (followed by a sibling key) and checks
// that it parses back as exactly the same string.
func roundTrips(s string, flow bool) bool {
	doc := "k: " + s + "\nz: 1\n"
	if flow {
		doc = "{k: " + s + ", z: 1}"
	}
	var m map[string]any
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil || len(m) != 2 {
		return false
	}
	v, ok := m["k"].(string)
	return ok && v == s && m["z"] == 1
}

// keyScalar renders a mapping key, quoting it when plain would not read back.
func keyScalar(k string, flow bool) string {
	plain := !needsQuote(k, flow) && !strings.ContainsAny(k, "\x00\n\r\t")
	if plain {
		doc := k + ": 1\nz: 2\n"
		if flow {
			doc = "{" + k + ": 1, z: 2}"
		}
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err == nil && len(m) == 2 && m[k] == 1 {
			return k
		}
	}
	return quoteString(k, false)
}

func isPrintableNoNewline(s string) bool {
	for _, r := range s {
		// U+0085/U+2028/U+2029 are line breaks to YAML; U+FEFF is a BOM. All need escapes.
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == 0xFEFF {
			return false
		}
	}
	return true
}

// quoteString renders s as a quoted YAML scalar. single selects single quotes when allowed.
func quoteString(s string, preferSingle bool) string {
	if preferSingle && isPrintableNoNewline(s) && utf8.ValidString(s) {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		case 0x85:
			b.WriteString(`\N`)
		case 0x2028:
			b.WriteString(`\L`)
		case 0x2029:
			b.WriteString(`\P`)
		case 0xFEFF:
			b.WriteString(`\uFEFF`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// scalar renders a string, quoting only when needed. hint is the style of the
// scalar this value replaces (an unchanged value keeps its quoting).
func scalar(s string, flow bool, hint yaml.Style) string {
	switch {
	case hint&yaml.DoubleQuotedStyle != 0 && !strings.ContainsAny(s, "\n"):
		return quoteString(s, false)
	case hint&yaml.SingleQuotedStyle != 0 && isPrintableNoNewline(s):
		return quoteString(s, true)
	case !needsQuote(s, flow):
		return s
	}
	return quoteString(s, !strings.ContainsAny(s, "'") && strings.ContainsAny(s, `\"`))
}

// inline renders any value on one line (flow context for collections).
func inline(v any, hint yaml.Style) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return scalar(x, true, hint)
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case json.Number:
		return x.String()
	case float64:
		return formatFloat(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = inline(e, 0)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = keyScalar(k, true) + ": " + inline(x[k], 0)
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func formatFloat(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// orderedKeys lists data's keys: those in order first, the rest sorted.
func orderedKeys(data map[string]any, order []string) []string {
	keys := make([]string, 0, len(data))
	seen := map[string]bool{}
	for _, k := range order {
		if _, ok := data[k]; ok && !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range data {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(keys, rest...)
}

// flowRecord renders `{k: v, ...}`. old maps keys to the value nodes being replaced.
func flowRecord(data map[string]any, keys []string, old map[string]*yaml.Node) string {
	if len(keys) == 0 {
		return "{}"
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		var hint yaml.Style
		if n := old[k]; n != nil && n.Kind == yaml.ScalarNode {
			hint = n.Style
		}
		parts[i] = keyScalar(k, true) + ": " + inline(data[k], hint)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// blockPair renders `key: value` lines (without leading indentation on the
// first line; continuation lines are indented by indent spaces).
func blockPair(k string, v any, indent int, hint yaml.Style) []string {
	key := keyScalar(k, false) + ":"
	if s, ok := v.(string); ok && strings.Contains(s, "\n") {
		if lines, ok := literalBlock(s, indent+2); ok {
			return append([]string{key + " " + lines[0]}, lines[1:]...)
		}
	}
	return []string{key + " " + inlineBlock(v, hint)}
}

// inlineBlock is inline() for a value that sits in a block mapping (commas are fine).
func inlineBlock(v any, hint yaml.Style) string {
	if s, ok := v.(string); ok {
		return scalar(s, false, hint)
	}
	return inline(v, hint)
}

// literalBlock renders a multi-line string as a `|` block scalar.
func literalBlock(s string, indent int) ([]string, bool) {
	if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || strings.ContainsAny(s, "\r\t\x00") {
		return nil, false
	}
	if s[0] == ' ' || s[0] == '\n' {
		return nil, false
	}
	chomp := "-"
	body := s
	switch {
	case strings.HasSuffix(s, "\n\n"):
		// keep chomping (|+) would absorb the blank lines that separate records
		return nil, false
	case strings.HasSuffix(s, "\n"):
		chomp = ""
		body = strings.TrimSuffix(s, "\n")
	}
	pad := strings.Repeat(" ", indent)
	out := []string{"|" + chomp}
	for _, l := range strings.Split(body, "\n") {
		if l == "" {
			out = append(out, "")
		} else {
			out = append(out, pad+l)
		}
	}
	return out, true
}
