package config

import (
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/internal/locale"
)

// Texts is the text of one object in the other languages: locale tag, then key
// (title, description, ...), then the text. The default language's text sits in
// the object's own keys; a reader uses the entry for its language and else that
// standard text, so it is never empty when the standard text exists.
type Texts map[string]map[string]string

// UnmarshalYAML reads a mapping of language to a mapping of key to text, and
// says what is wrong when it is not one.
func (t *Texts) UnmarshalYAML(n *yaml.Node) error {
	out, err := decodeTexts(n, "i18n")
	if err != nil {
		return err
	}
	*t = out
	return nil
}

func deref(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	return n
}

// decodeTexts reads language -> key -> text from a mapping node. at names the
// block for messages.
func decodeTexts(n *yaml.Node, at string) (Texts, error) {
	n = deref(n)
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s must be a mapping of language to text, like {en-US: {title: Devices}}", at)
	}
	out := Texts{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], deref(n.Content[i+1])
		if k.Tag == "!!merge" || k.Value == "<<" {
			return nil, fmt.Errorf("%s: merge keys (<<) are not supported; write each language out", at)
		}
		if _, dup := out[k.Value]; dup {
			return nil, fmt.Errorf("%s.%s is given twice", at, k.Value)
		}
		if v.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s.%s must be a mapping of text, like {title: Devices}, not %s", at, k.Value, kindName(v))
		}
		m := map[string]string{}
		for j := 0; j+1 < len(v.Content); j += 2 {
			kk, vv := v.Content[j], deref(v.Content[j+1])
			if kk.Tag == "!!merge" || kk.Value == "<<" {
				return nil, fmt.Errorf("%s.%s: merge keys (<<) are not supported; write each key out", at, k.Value)
			}
			if _, dup := m[kk.Value]; dup {
				return nil, fmt.Errorf("%s.%s.%s is given twice", at, k.Value, kk.Value)
			}
			if vv.Kind != yaml.ScalarNode || vv.Tag == "!!null" {
				return nil, fmt.Errorf("%s.%s.%s must be text, not %s", at, k.Value, kk.Value, kindName(vv))
			}
			m[kk.Value] = vv.Value
		}
		out[k.Value] = m
	}
	return out, nil
}

func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return "empty"
		}
		return "a plain value"
	}
	return "something else"
}

// Only returns the entries of t for keys, without empty text and empty
// languages, as a new map; nil when nothing is left. It is the shape the API
// sends: locale tag, then key, then text.
func (t Texts) Only(keys ...string) map[string]map[string]string {
	var out map[string]map[string]string
	for loc, m := range t {
		for _, k := range keys {
			if s := m[k]; s != "" {
				if out == nil {
					out = map[string]map[string]string{}
				}
				if out[loc] == nil {
					out[loc] = map[string]string{}
				}
				out[loc][k] = s
			}
		}
	}
	return out
}

// Renamed is Only for one key, renamed: the backref title of a rule is sent
// as "title".
func (t Texts) Renamed(from, to string) map[string]map[string]string {
	var out map[string]map[string]string
	for loc, m := range t {
		if s := m[from]; s != "" {
			if out == nil {
				out = map[string]map[string]string{}
			}
			out[loc] = map[string]string{to: s}
		}
	}
	return out
}

// Clean returns t without empty text and empty languages (nil when nothing is
// left), so that equal content compares equal.
func (t Texts) Clean(keys ...string) Texts { return Texts(t.Only(keys...)) }

// check refuses a locale that is not supported and a key the object does not
// allow. at names the block for the message (collections.devices.i18n).
func (t Texts) check(at string, allowed ...string) error {
	locs := make([]string, 0, len(t))
	for l := range t {
		locs = append(locs, l)
	}
	sort.Strings(locs)
	for _, l := range locs {
		if !supportedLocale(l) {
			return fmt.Errorf("%s.%s: %q is not a supported language (use %s)", at, l, l, strings.Join(locale.Supported, ", "))
		}
		keys := make([]string, 0, len(t[l]))
		for k := range t[l] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ok := false
			for _, a := range allowed {
				ok = ok || a == k
			}
			if !ok {
				return fmt.Errorf("%s.%s: unknown key %q (use %s)", at, l, k, strings.Join(allowed, ", "))
			}
		}
	}
	return nil
}

func supportedLocale(l string) bool {
	for _, s := range locale.Supported {
		if s == l {
			return true
		}
	}
	return false
}

// I18n is the i18n block: `default` is the language of the standard text, and
// every other key is a language with the ledger's title and description in it.
type I18n struct {
	// Default is the language of the text in rackbook.yml and the schemas, and
	// the console language when the browser's Accept-Language matches none of
	// the supported locales and the user has no preference: zh-CN (default),
	// zh-TW or en-US.
	Default string
	// Texts is title and description per language.
	Texts Texts
}

// UnmarshalYAML reads default and the language entries.
func (i *I18n) UnmarshalYAML(n *yaml.Node) error {
	n = deref(n)
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("i18n must be a mapping: default and one entry per language, like {default: zh-CN, en-US: {title: Ledger}}")
	}
	*i = I18n{}
	rest := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	seenDefault := false
	for j := 0; j+1 < len(n.Content); j += 2 {
		k, v := n.Content[j], deref(n.Content[j+1])
		if k.Value == "default" && k.Tag != "!!merge" {
			if seenDefault {
				return fmt.Errorf("i18n.default is given twice")
			}
			seenDefault = true
			if v.Kind != yaml.ScalarNode {
				return fmt.Errorf("i18n.default must be a language tag (zh-CN, zh-TW or en-US), not %s", kindName(v))
			}
			i.Default = v.Value
			continue
		}
		rest.Content = append(rest.Content, k, v)
	}
	t, err := decodeTexts(rest, "i18n")
	if err != nil {
		return err
	}
	if len(t) > 0 {
		i.Texts = t
	}
	return nil
}

func (i I18n) check(at string, allowed ...string) error { return i.Texts.check(at, allowed...) }

// checkI18nShapes reads every i18n block of a config document once, before it
// is decoded, so that a wrong shape is reported where it is: the collection, the
// note or rule number. (The top-level block is read by I18n.UnmarshalYAML.)
func checkI18nShapes(top *yaml.Node) error {
	top = deref(top)
	if top.Kind != yaml.MappingNode {
		return nil
	}
	check := func(m *yaml.Node, at string) error {
		if m = deref(m); m.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == "i18n" {
				if _, err := decodeTexts(m.Content[i+1], at+".i18n"); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for i := 0; i+1 < len(top.Content); i += 2 {
		v := deref(top.Content[i+1])
		switch top.Content[i].Value {
		case "collections":
			if v.Kind == yaml.MappingNode {
				for j := 0; j+1 < len(v.Content); j += 2 {
					if err := check(v.Content[j+1], "collections."+v.Content[j].Value); err != nil {
						return err
					}
				}
			}
		case "notes":
			for j, n := range v.Content {
				if err := check(n, fmt.Sprintf("notes[%d]", j)); err != nil {
					return err
				}
			}
		case "rules":
			for j, r := range v.Content {
				r = deref(r)
				if r.Kind != yaml.MappingNode {
					continue
				}
				for k := 0; k+1 < len(r.Content); k += 2 {
					if key := r.Content[k].Value; key == "ref" || key == "same_set" {
						if err := check(r.Content[k+1], fmt.Sprintf("rules[%d].%s", j, key)); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}
