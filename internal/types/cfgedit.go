package types

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/locale"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

// The rackbook.yml side of a Type: the collection's entry under `collections:`
// and the rules it owns under `rules:`, both spliced in place.

var entryOrder = []string{"title", "description", "group", "icon", "i18n", "file", "path", "schema", "key", "label", "list", "facets"}

// entryValues lists the keys of the collection entry for t, with the empty
// ones as nil.
func entryValues(t *Type) map[string]any {
	str := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	list := func(l []string) any {
		if len(l) == 0 {
			return nil
		}
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out
	}
	// i18n: {en-US: {title: ..., description: ..., group: ...}} in the order of
	// the supported languages, so that equal content renders the same text.
	var i18n any
	var locs []string
	loc := map[string]any{}
	for _, l := range locale.Supported {
		var keys []string
		vals := map[string]any{}
		for _, k := range []string{"title", "description", "group"} {
			if s := t.I18n[l][k]; s != "" {
				keys = append(keys, k)
				vals[k] = s
			}
		}
		if len(keys) > 0 {
			locs = append(locs, l)
			loc[l] = yamledit.Flow{Keys: keys, Values: vals}
		}
	}
	if len(locs) > 0 {
		i18n = yamledit.Flow{Keys: locs, Values: loc}
	}
	var facets any
	if len(t.Facets) > 0 {
		out := make([]any, len(t.Facets))
		for i, f := range t.Facets {
			if (f.Match == "" || f.Match == "exact") && len(f.Values) == 0 {
				out[i] = f.Field
				continue
			}
			vals := make([]any, len(f.Values))
			for j, v := range f.Values {
				vals[j] = v
			}
			m := f.Match
			if m == "" {
				m = "exact"
			}
			out[i] = yamledit.Flow{Keys: []string{"field", "match", "values"}, Values: map[string]any{"field": f.Field, "match": m, "values": vals}}
		}
		facets = out
	}
	return map[string]any{
		"title": str(t.Title), "description": str(t.Description), "group": str(t.Group), "icon": str(t.Icon), "i18n": i18n,
		"file": str(t.File), "path": str(t.Path), "schema": str(t.SchemaFile),
		"key": list(t.Key), "label": str(t.Label), "list": list(t.List), "facets": facets,
	}
}

// entryChanges returns the changes that turn the entry of old into the one of
// nt; keys that are equal are left out.
func entryChanges(old, nt *Type) []yamledit.EntryChange {
	ov, nv := entryValues(old), entryValues(nt)
	var out []yamledit.EntryChange
	for _, k := range entryOrder {
		if reflect.DeepEqual(canonJSON(ov[k]), canonJSON(nv[k])) {
			continue
		}
		if nv[k] == nil {
			out = append(out, yamledit.EntryChange{Key: k, Remove: true})
		} else {
			out = append(out, yamledit.EntryChange{Key: k, Value: nv[k]})
		}
	}
	return out
}

func canonJSON(v any) string {
	b, _ := json.Marshal(norm(v))
	return string(b)
}

func norm(v any) any {
	switch x := v.(type) {
	case yamledit.Flow:
		m := map[string]any{}
		for k, e := range x.Values {
			m[k] = norm(e)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = norm(e)
		}
		return out
	}
	return v
}

// newEntry returns the fields of a new collection entry.
func newEntry(t *Type) []yamledit.EntryChange {
	vals := entryValues(t)
	var out []yamledit.EntryChange
	for _, k := range entryOrder {
		if vals[k] != nil {
			out = append(out, yamledit.EntryChange{Key: k, Value: vals[k]})
		}
	}
	return out
}

func ruleKey(r config.Rule) string {
	b, _ := json.Marshal(struct {
		Ref    *config.RefRule
		Unique *config.UniqueRule
	}{canonRef(r.Ref), r.Unique})
	return string(b)
}

func canonRef(r *config.RefRule) *config.RefRule {
	if r == nil {
		return nil
	}
	c := *r
	if len(c.Allow) == 0 {
		c.Allow = nil
	}
	if len(c.BackrefColumns) == 0 {
		c.BackrefColumns = nil
	}
	c.I18n = c.I18n.Clean("message", "backref_title")
	return &c
}

// owns reports whether the rule belongs to collection name: its ref rules and
// unique rules. same_set rules and rules of other collections are not touched.
func owns(r config.Rule, name string) bool {
	switch {
	case r.Ref != nil:
		c, _, _ := config.SplitRef(r.Ref.From)
		return c == name
	case r.Unique != nil:
		return r.Unique.Collection == name
	}
	return false
}

// ruleItem renders a rule as the text after "- " and the value it parses to.
func ruleItem(r config.Rule) (string, any) {
	strs := func(l []string) []any {
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out
	}
	var key string
	var f yamledit.Flow
	switch {
	case r.Ref != nil:
		key = "ref"
		f = yamledit.Flow{Keys: []string{"from", "to"}, Values: map[string]any{"from": r.Ref.From, "to": r.Ref.To}}
		add := func(k string, v any) {
			f.Keys = append(f.Keys, k)
			f.Values[k] = v
		}
		if len(r.Ref.Allow) > 0 {
			add("allow", strs(r.Ref.Allow))
		}
		if r.Ref.Many {
			add("many", true)
		}
		if r.Ref.BackrefTitle != "" {
			add("backref_title", r.Ref.BackrefTitle)
		}
		if len(r.Ref.BackrefColumns) > 0 {
			add("backref_columns", strs(r.Ref.BackrefColumns))
		}
		if r.Ref.Message != "" {
			add("message", r.Ref.Message)
		}
		var locs []string
		byLoc := map[string]any{}
		for _, l := range locale.Supported {
			var keys []string
			vals := map[string]any{}
			for _, k := range []string{"message", "backref_title"} {
				if s := r.Ref.I18n[l][k]; s != "" {
					keys = append(keys, k)
					vals[k] = s
				}
			}
			if len(keys) > 0 {
				locs = append(locs, l)
				byLoc[l] = yamledit.Flow{Keys: keys, Values: vals}
			}
		}
		if len(locs) > 0 {
			add("i18n", yamledit.Flow{Keys: locs, Values: byLoc})
		}
	case r.Unique != nil:
		key = "unique"
		f = yamledit.Flow{Keys: []string{"collection", "fields"}, Values: map[string]any{"collection": r.Unique.Collection, "fields": strs(r.Unique.Fields)}}
	}
	return key + ": " + f.String(), map[string]any{key: f}
}

// spliceRules makes the rules owned by name equal want: owned rules that are
// not wanted are removed, wanted ones that are missing are appended. Rules
// that stay are not touched.
func spliceRules(src []byte, cfg *config.Config, name string, want []config.Rule) ([]byte, error) {
	wantKeys := map[string]config.Rule{}
	for _, r := range want {
		wantKeys[ruleKey(r)] = r
	}
	have := map[string]bool{}
	var drop []int
	for i, r := range cfg.Rules {
		if !owns(r, name) {
			continue
		}
		k := ruleKey(r)
		if _, keep := wantKeys[k]; keep && !have[k] {
			have[k] = true
			continue
		}
		drop = append(drop, i)
	}
	// add first so that the list is never emptied by the removals, then remove from the end
	var add []string
	for _, r := range want {
		if k := ruleKey(r); !have[k] {
			have[k] = true
			add = append(add, k)
		}
	}
	sort.Strings(add)
	out := src
	for _, k := range orderedAdds(want, add) {
		text, val := ruleItem(wantKeys[k])
		var err error
		if out, err = yamledit.AddItem(out, "rules", text, val); err != nil {
			return nil, fmt.Errorf("rackbook.yml: %w", err)
		}
	}
	for i := len(drop) - 1; i >= 0; i-- {
		var err error
		if out, err = yamledit.RemoveItem(out, "rules", drop[i]); err != nil {
			return nil, fmt.Errorf("rackbook.yml: %w", err)
		}
	}
	return out, nil
}

// orderedAdds returns the keys of add in the order of want (field order).
func orderedAdds(want []config.Rule, add []string) []string {
	isAdd := map[string]bool{}
	for _, k := range add {
		isAdd[k] = true
	}
	var out []string
	for _, r := range want {
		if k := ruleKey(r); isAdd[k] {
			out = append(out, k)
			delete(isAdd, k)
		}
	}
	return out
}

func setEntry(src []byte, name string, ch []yamledit.EntryChange) ([]byte, error) {
	out, err := yamledit.SetEntry(src, "collections", name, ch, entryOrder)
	if err != nil {
		return nil, fmt.Errorf("rackbook.yml: %w", err)
	}
	return out, nil
}
