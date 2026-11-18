package ledger

import "github.com/kazuhahub/rackbook/internal/config"

// RefInfo describes a field of a collection that references another collection.
type RefInfo struct {
	Field   string   `json:"field"`
	To      string   `json:"to"`
	ToField string   `json:"toField"`
	Allow   []string `json:"allow"`
	Many    bool     `json:"many"`
}

// BackRef says that Collection.Field references this collection.
type BackRef struct {
	Collection string `json:"collection"`
	Field      string `json:"field"`
	// Title and Columns come from backref_title / backref_columns of the rule.
	Title   string   `json:"title,omitempty"`
	Columns []string `json:"columns,omitempty"`
}

// Refs lists the ref rules whose source is the collection.
func (l *Ledger) Refs(collection string) []RefInfo {
	out := []RefInfo{}
	for _, r := range l.Config.Rules {
		if r.Ref == nil {
			continue
		}
		fc, ff, _ := config.SplitRef(r.Ref.From)
		tc, tf, _ := config.SplitRef(r.Ref.To)
		if fc == collection {
			allow := r.Ref.Allow
			if allow == nil {
				allow = []string{}
			}
			out = append(out, RefInfo{Field: ff, To: tc, ToField: tf, Allow: allow, Many: r.Ref.Many})
		}
	}
	return out
}

// BackRefs lists the collections that reference the given one.
func (l *Ledger) BackRefs(collection string) []BackRef {
	out := []BackRef{}
	for _, r := range l.Config.Rules {
		if r.Ref == nil {
			continue
		}
		fc, ff, _ := config.SplitRef(r.Ref.From)
		tc, _, _ := config.SplitRef(r.Ref.To)
		if tc == collection {
			out = append(out, BackRef{Collection: fc, Field: ff, Title: r.Ref.BackrefTitle, Columns: r.Ref.BackrefColumns})
		}
	}
	return out
}

// Backrefs returns, per referencing collection, the records that point at rec.
// Records whose field holds an allowed literal (e.g. "all") apply to every record
// and are included.
func (l *Ledger) Backrefs(collection string, rec *Record) map[string][]*Record {
	out := map[string][]*Record{}
	for _, r := range l.Config.Rules {
		if r.Ref == nil {
			continue
		}
		fc, ff, _ := config.SplitRef(r.Ref.From)
		tc, tf, _ := config.SplitRef(r.Ref.To)
		from := l.Collection(fc)
		if tc != collection || from == nil {
			continue
		}
		target := Str(rec.Data[tf])
		for _, cand := range from.Records {
			if refMatches(cand.Data[ff], target, r.Ref) && !containsRec(out[fc], cand) {
				out[fc] = append(out[fc], cand)
			}
		}
	}
	return out
}

func refMatches(v any, target string, r *config.RefRule) bool {
	var vals []any
	if list, ok := v.([]any); ok && r.Many {
		vals = list
	} else {
		vals = []any{v}
	}
	for _, x := range vals {
		s := Str(x)
		if s == target {
			return true
		}
		for _, a := range r.Allow {
			if s == a {
				return true
			}
		}
	}
	return false
}

func containsRec(list []*Record, r *Record) bool {
	for _, x := range list {
		if x == r {
			return true
		}
	}
	return false
}

// Reference is one record that points at another through a ref rule.
type Reference struct {
	Collection string `json:"collection"`
	ID         string `json:"id"`
	Field      string `json:"field"`
	Value      string `json:"value"` // the value that points at the target
}

// ReferencesTo lists the records that hold rec's value in a ref field. Unlike
// Backrefs, allowed literals (such as "all") do not count: they point at every
// record, not at this one. rec itself is never listed.
func (l *Ledger) ReferencesTo(collection string, rec *Record) []Reference {
	out := []Reference{}
	for _, r := range l.Config.Rules {
		if r.Ref == nil {
			continue
		}
		fc, ff, _ := config.SplitRef(r.Ref.From)
		tc, tf, _ := config.SplitRef(r.Ref.To)
		from := l.Collection(fc)
		if tc != collection || from == nil {
			continue
		}
		target := Str(rec.Data[tf])
		if target == "" {
			continue
		}
		for _, cand := range from.Records {
			if fc == collection && cand == rec {
				continue
			}
			if refHolds(cand.Data[ff], target, r.Ref.Many) {
				out = append(out, Reference{Collection: fc, ID: cand.ID, Field: ff, Value: target})
			}
		}
	}
	return out
}

func refHolds(v any, target string, many bool) bool {
	if list, ok := v.([]any); ok && many {
		for _, x := range list {
			if Str(x) == target {
				return true
			}
		}
		return false
	}
	return Str(v) == target
}
