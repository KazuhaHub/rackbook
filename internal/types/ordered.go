package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// omap is a JSON object that remembers the order of its keys. Schemas are
// edited through it so that a rewrite keeps the key order the file had.
type omap struct {
	keys []string
	vals map[string]any // nested objects are *omap, arrays []any, numbers json.Number
}

func newOmap() *omap { return &omap{vals: map[string]any{}} }

// set replaces the value in place or appends the key.
func (m *omap) set(k string, v any) {
	if _, ok := m.vals[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.vals[k] = v
}

func (m *omap) del(k string) {
	if _, ok := m.vals[k]; !ok {
		return
	}
	delete(m.vals, k)
	for i, x := range m.keys {
		if x == k {
			m.keys = append(m.keys[:i:i], m.keys[i+1:]...)
			break
		}
	}
}

func (m *omap) has(k string) bool { _, ok := m.vals[k]; return ok }

// rename gives the value of key from the name to, in the same place.
func (m *omap) rename(from, to string) {
	for i, k := range m.keys {
		if k == from {
			m.keys[i] = to
			m.vals[to] = m.vals[from]
			delete(m.vals, from)
			return
		}
	}
}

func (m *omap) clone() *omap {
	c := newOmap()
	for _, k := range m.keys {
		c.set(k, m.vals[k])
	}
	return c
}

func parseOrdered(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after the JSON document")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool, nil
	}
	switch d {
	case '{':
		m := newOmap()
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			m.set(kt.(string), v)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return m, nil
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unexpected %v", d)
}

// toOrdered converts plain Go data (as produced by json.Unmarshal with
// UseNumber, or built by hand) into omap form; map keys are sorted.
func toOrdered(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := newOmap()
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			m.set(k, toOrdered(x[k]))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toOrdered(e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	case json.RawMessage:
		o, err := parseOrdered(x)
		if err != nil {
			return nil
		}
		return o
	}
	return v
}

// maxInline is how many characters a one-line object or array may have.
const maxInline = 400

// formatSchema renders the root object the way rackbook schemas are written:
// two-space indentation, one top-level key per line, one property per line
// (a property on one line while it is short), short arrays inline.
func formatSchema(root *omap) []byte {
	var b strings.Builder
	writeExpanded(&b, root, 0)
	b.WriteByte('\n')
	return []byte(b.String())
}

// writeExpanded writes m with one key per line; the values are inline while
// they fit, except the properties of the root, which are one per line too.
func writeExpanded(b *strings.Builder, m *omap, depth int) {
	if len(m.keys) == 0 {
		b.WriteString("{}")
		return
	}
	pad := strings.Repeat("  ", depth+1)
	b.WriteString("{\n")
	for i, k := range m.keys {
		b.WriteString(pad)
		b.WriteString(jsonString(k))
		b.WriteString(": ")
		v := m.vals[k]
		if sub, ok := v.(*omap); ok && (k == "properties" && depth == 0) {
			writeExpanded(b, sub, depth+1)
		} else {
			writeValue(b, v, depth+1)
		}
		if i < len(m.keys)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString(strings.Repeat("  ", depth))
	b.WriteByte('}')
}

// writeValue writes v inline when it fits, expanded otherwise.
func writeValue(b *strings.Builder, v any, depth int) {
	inline := inlineJSON(v)
	if utf8.RuneCountInString(inline) <= maxInline {
		b.WriteString(inline)
		return
	}
	switch x := v.(type) {
	case *omap:
		pad := strings.Repeat("  ", depth+1)
		b.WriteString("{\n")
		for i, k := range x.keys {
			b.WriteString(pad + jsonString(k) + ": ")
			writeValue(b, x.vals[k], depth+1)
			if i < len(x.keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth) + "}")
	case []any:
		pad := strings.Repeat("  ", depth+1)
		b.WriteString("[\n")
		for i, e := range x {
			b.WriteString(pad)
			writeValue(b, e, depth+1)
			if i < len(x)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth) + "]")
	default:
		b.WriteString(inline)
	}
}

func inlineJSON(v any) string {
	switch x := v.(type) {
	case *omap:
		if len(x.keys) == 0 {
			return "{}"
		}
		parts := make([]string, len(x.keys))
		for i, k := range x.keys {
			parts[i] = jsonString(k) + ": " + inlineJSON(x.vals[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = inlineJSON(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case string:
		return jsonString(x)
	case json.Number:
		return x.String()
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func jsonString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimRight(buf.String(), "\n")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
