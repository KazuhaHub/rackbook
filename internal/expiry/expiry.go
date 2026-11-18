// Package expiry lists the records that are expired or about to expire. A
// collection opts in with x-rackbook marks on top-level schema properties:
// {"expires": true} names the expiry date, {"revoked": true} a field whose
// non-empty value retires the record (docs/modules.md, section 1).
package expiry

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/ledger"
)

// Statuses of a listed record.
const (
	StatusExpired  = "expired"
	StatusExpiring = "expiring"
	StatusUnknown  = "unknown"
)

// Window limits, in days.
const (
	DefaultDays = 30
	MaxDays     = 3650
)

// ErrUnknownCollection is wrapped by List for a collection that does not exist.
var ErrUnknownCollection = errors.New("unknown collection")

// Options selects what List returns.
type Options struct {
	// Days is the window; callers apply DefaultDays. It is clamped to 0..MaxDays.
	Days int
	// Collections limits the listing; empty means every collection.
	Collections []string
	// Unknown includes records whose date is not a date (for example 待补).
	Unknown bool
	// Today is the reference date (its UTC date counts); zero means now.
	Today time.Time
}

// Item is one listed record.
type Item struct {
	Collection string `json:"collection"`
	ID         string `json:"id"`
	Label      string `json:"label"`
	Expires    string `json:"expires"`
	DaysLeft   *int   `json:"daysLeft"` // nil for unknown
	Status     string `json:"status"`
	Source     string `json:"source"`
}

// Result is the answer of List.
type Result struct {
	Today string `json:"today"`
	Days  int    `json:"days"`
	Items []Item `json:"items"`
}

// ExpiryField is the name of the property marked x-rackbook expires, or "".
func ExpiryField(c *ledger.Collection) string { return markedField(c, "expires") }

// RevokedField is the name of the property marked x-rackbook revoked, or "".
func RevokedField(c *ledger.Collection) string { return markedField(c, "revoked") }

// markedField reads the top-level properties of the schema; with several marked
// properties the first by name wins, so the answer does not depend on map order.
func markedField(c *ledger.Collection, mark string) string {
	if c == nil || len(c.SchemaRaw) == 0 {
		return ""
	}
	var doc struct {
		Properties map[string]struct {
			X map[string]any `json:"x-rackbook"`
		} `json:"properties"`
	}
	if json.Unmarshal(c.SchemaRaw, &doc) != nil {
		return ""
	}
	best := ""
	for name, p := range doc.Properties {
		if v, _ := p.X[mark].(bool); v && (best == "" || name < best) {
			best = name
		}
	}
	return best
}

// ClampDays limits days to 0..MaxDays.
func ClampDays(days int) int { return min(max(days, 0), MaxDays) }

// date reads an expiry value: ok is true for a date. never means empty.
func date(v any) (d time.Time, never, ok bool) {
	if v == nil {
		return d, true, false
	}
	s, isStr := v.(string)
	if !isStr {
		return d, false, false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return d, true, false
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, false, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		t = t.UTC()
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), false, true
	}
	return d, false, false
}

func revoked(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(x) != ""
	case bool:
		return x
	}
	return true
}

// List returns the expired and expiring records of the selected collections,
// most overdue first, unknown dates last (ties by collection, then id).
func List(l *ledger.Ledger, o Options) (*Result, error) {
	now := o.Today
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	days := ClampDays(o.Days)
	cols := l.Collections
	if len(o.Collections) > 0 {
		cols = nil
		for _, name := range o.Collections {
			c := l.Collection(name)
			if c == nil {
				return nil, fmt.Errorf("%w %q", ErrUnknownCollection, name)
			}
			cols = append(cols, c)
		}
	}
	res := &Result{Today: today.Format("2006-01-02"), Days: days, Items: []Item{}}
	seen := map[string]bool{}
	for _, c := range cols {
		field := ExpiryField(c)
		if field == "" || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		rev := RevokedField(c)
		for _, r := range c.Records {
			if rev != "" && revoked(r.Data[rev]) {
				continue
			}
			d, never, ok := date(r.Data[field])
			if never {
				continue
			}
			it := Item{Collection: c.Name, ID: r.ID, Label: r.ID, Expires: ledger.Str(r.Data[field])}
			if c.Label != "" {
				if s := ledger.Str(r.Data[c.Label]); s != "" {
					it.Label = s
				}
			}
			if s, _ := r.Data["source"].(string); s != "" {
				it.Source = s
			}
			if !ok {
				if !o.Unknown {
					continue
				}
				it.Status = StatusUnknown
			} else {
				left := int(d.Sub(today).Hours() / 24)
				switch {
				case left < 0:
					it.Status = StatusExpired
				case left <= days:
					it.Status = StatusExpiring
				default:
					continue
				}
				it.DaysLeft = &left
			}
			res.Items = append(res.Items, it)
		}
	}
	sort.SliceStable(res.Items, func(i, j int) bool {
		a, b := res.Items[i], res.Items[j]
		if (a.DaysLeft == nil) != (b.DaysLeft == nil) {
			return a.DaysLeft != nil
		}
		if a.DaysLeft != nil && *a.DaysLeft != *b.DaysLeft {
			return *a.DaysLeft < *b.DaysLeft
		}
		if a.Collection != b.Collection {
			return a.Collection < b.Collection
		}
		return a.ID < b.ID
	})
	return res, nil
}
