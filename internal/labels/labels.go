// Package labels reads the display text of a JSON Schema property: the title
// and description in each language, and for an enum-like property its codes
// with their labels and icons.
//
// The default language's text sits in the standard keywords (title,
// description, the title of each oneOf entry). Other languages sit in the
// x-rackbook-i18n extension, keyed by locale tag. The text for language L is
// the L entry of the extension, else the standard text, so it is never empty
// when the standard text exists. Stored values are always the codes.
package labels

import (
	"regexp"
	"strings"

	"github.com/kazuhahub/rackbook/internal/locale"
)

// Extension keywords.
const (
	KeyI18n  = "x-rackbook-i18n"
	KeyIcons = "x-rackbook-enum-icons"
)

// iconRe is the shape of an icon name: lucide's kebab-case names (circle-check,
// clock). The list of known names lives in the console, which shows no icon for
// a name it does not know.
var iconRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ValidIcon reports whether s has the shape of an icon name.
func ValidIcon(s string) bool { return iconRe.MatchString(s) }

// Supported reports whether tag is one of the console's locales (exact tag).
func Supported(tag string) bool {
	for _, s := range locale.Supported {
		if s == tag {
			return true
		}
	}
	return false
}

// Item is one allowed value of an enum-like property.
type Item struct {
	Code string
	// Label is the default-language label (the oneOf title), "" when the
	// property has none (a plain enum).
	Label string
	// Labels are the other languages' labels, by locale tag.
	Labels map[string]string
	Icon   string
}

// Enum is the enum-like view of a property.
type Enum struct {
	Items []Item
	// OneOf is true for the oneOf form, false for a plain enum.
	OneOf bool
}

// Codes lists the allowed values in schema order.
func (e *Enum) Codes() []string {
	out := make([]string, len(e.Items))
	for i, it := range e.Items {
		out[i] = it.Code
	}
	return out
}

// Item returns the item for a code.
func (e *Enum) Item(code string) (Item, bool) {
	for _, it := range e.Items {
		if it.Code == code {
			return it, true
		}
	}
	return Item{}, false
}

// Label is the label of code in language loc: the extension's entry for loc,
// else the oneOf title, else the code itself. An unknown code is returned as it is.
func (e *Enum) Label(loc, code string) string {
	it, ok := e.Item(code)
	if !ok {
		return code
	}
	if l := it.Labels[loc]; l != "" {
		return l
	}
	if it.Label != "" {
		return it.Label
	}
	return code
}

// AllLabels returns every label of code: the default one and one per language.
func (it Item) AllLabels() []string {
	var out []string
	if it.Label != "" {
		out = append(out, it.Label)
	}
	for _, loc := range locale.Supported {
		if l := it.Labels[loc]; l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Match finds the code a value stands for, for a hint: a value that is a label
// of a code in any language, or a code in other letter case. exact is true when
// the value already is a code (then there is nothing to hint).
func (e *Enum) Match(v string) (code string, exact, ok bool) {
	for _, it := range e.Items {
		if it.Code == v {
			return it.Code, true, true
		}
	}
	for _, it := range e.Items {
		for _, l := range it.AllLabels() {
			if l == v {
				return it.Code, false, true
			}
		}
	}
	for _, it := range e.Items {
		if strings.EqualFold(it.Code, v) {
			return it.Code, false, true
		}
	}
	return "", false, false
}

// Parse returns the enum-like view of a decoded schema property (a
// map[string]any as json.Unmarshal builds it), or false when the property is
// not enum-like: a string (or string or null) with either a plain enum of
// strings or a oneOf whose every entry has a string const, an optional string
// title and no other key. The oneOf form wins when both are present and valid.
func Parse(prop map[string]any) (*Enum, bool) {
	if !stringType(prop["type"]) {
		return nil, false
	}
	e := &Enum{}
	if raw, has := prop["oneOf"]; has {
		list, ok := raw.([]any)
		if !ok || len(list) == 0 {
			return nil, false
		}
		for _, el := range list {
			m, ok := el.(map[string]any)
			if !ok {
				return nil, false
			}
			code, ok := m["const"].(string)
			if !ok {
				return nil, false
			}
			it := Item{Code: code}
			for k, v := range m {
				switch k {
				case "const":
				case "title":
					s, ok := v.(string)
					if !ok {
						return nil, false
					}
					it.Label = s
				default:
					return nil, false
				}
			}
			e.Items = append(e.Items, it)
		}
		e.OneOf = true
	} else if raw, has := prop["enum"]; has {
		list, ok := raw.([]any)
		if !ok || len(list) == 0 {
			return nil, false
		}
		for _, el := range list {
			s, ok := el.(string)
			if !ok {
				return nil, false
			}
			e.Items = append(e.Items, Item{Code: s})
		}
	} else {
		return nil, false
	}
	idx := map[string]int{}
	for i, it := range e.Items {
		idx[it.Code] = i
	}
	// Readers ignore translations of unsupported locales and of codes that are
	// not among the enum's codes.
	for loc, v := range i18nOf(prop) {
		m, ok := v["enum"].(map[string]any)
		if !ok {
			continue
		}
		for code, l := range m {
			s, ok := l.(string)
			i, known := idx[code]
			if !ok || !known || s == "" {
				continue
			}
			if e.Items[i].Labels == nil {
				e.Items[i].Labels = map[string]string{}
			}
			e.Items[i].Labels[loc] = s
		}
	}
	if icons, ok := prop[KeyIcons].(map[string]any); ok {
		for code, v := range icons {
			if s, ok := v.(string); ok {
				if i, known := idx[code]; known {
					e.Items[i].Icon = s
				}
			}
		}
	}
	return e, true
}

func stringType(t any) bool {
	switch x := t.(type) {
	case string:
		return x == "string"
	case []any:
		hasString := false
		for _, e := range x {
			switch e {
			case "string":
				hasString = true
			case "null":
			default:
				return false
			}
		}
		return hasString
	}
	return false
}

// i18nOf returns the x-rackbook-i18n entries of the supported locales.
func i18nOf(prop map[string]any) map[string]map[string]any {
	raw, ok := prop[KeyI18n].(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]map[string]any{}
	for loc, v := range raw {
		if m, ok := v.(map[string]any); ok && Supported(loc) {
			out[loc] = m
		}
	}
	return out
}

// Translations returns the title and description of a property per supported
// language, from x-rackbook-i18n. Empty strings are left out.
func Translations(prop map[string]any) map[string]map[string]string {
	out := map[string]map[string]string{}
	for loc, m := range i18nOf(prop) {
		for _, k := range []string{"title", "description"} {
			if s, ok := m[k].(string); ok && s != "" {
				if out[loc] == nil {
					out[loc] = map[string]string{}
				}
				out[loc][k] = s
			}
		}
	}
	return out
}

// Text is the title or description (key) of a property in language loc: the
// extension's entry, else the standard keyword.
func Text(prop map[string]any, loc, key string) string {
	if m := i18nOf(prop)[loc]; m != nil {
		if s, ok := m[key].(string); ok && s != "" {
			return s
		}
	}
	s, _ := prop[key].(string)
	return s
}

// Title is Text for the title, falling back to name when the property has none.
func Title(prop map[string]any, loc, name string) string {
	if s := Text(prop, loc, "title"); s != "" {
		return s
	}
	return name
}

// Property finds the property of a schema (a decoded object) that holds the
// value at an instance path of a record. Tokens are object keys and array
// indexes; it follows properties and items, so array items and the properties
// of row objects resolve too. It returns nil when the path leaves what it can
// follow ($ref, additionalProperties, ...).
func Property(schema map[string]any, path []string) map[string]any {
	cur := schema
	for _, tok := range path {
		if props, ok := cur["properties"].(map[string]any); ok {
			if p, ok := props[tok].(map[string]any); ok {
				cur = p
				continue
			}
		}
		if items, ok := cur["items"].(map[string]any); ok && isIndex(tok) {
			cur = items
			continue
		}
		return nil
	}
	return cur
}

func isIndex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
