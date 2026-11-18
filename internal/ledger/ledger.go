// Package ledger loads the collections declared in rackbook.yml: records,
// ids, hashes, schemas, notes and reverse references.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

// Rule names used in Issue.Rule.
const (
	RuleYAML    = "yaml"
	RuleSchema  = "schema"
	RuleUnique  = "unique"
	RuleRef     = "ref"
	RuleSameSet = "same_set"
	RuleConfig  = "config"
	RuleSecret  = "secret"
)

// Issue is one problem found while loading or checking the ledger.
type Issue struct {
	Collection string `json:"collection"`
	ID         string `json:"id"`
	Path       string `json:"path"` // JSON pointer inside the record, may be empty
	Rule       string `json:"rule"`
	Message    string `json:"message"`
	// Hash identifies the record content the issue was found on. It is not
	// part of the API; validate.Introduced uses it to match issues across
	// edits of keyless collections, whose ids shift.
	Hash string `json:"-"`
}

func (i Issue) String() string {
	var b strings.Builder
	if i.Collection != "" {
		b.WriteString(i.Collection)
		if i.ID != "" {
			b.WriteString("/" + i.ID)
		}
		b.WriteString(": ")
	}
	if i.Path != "" {
		b.WriteString(i.Path + ": ")
	}
	b.WriteString(i.Message + " [" + i.Rule + "]")
	return b.String()
}

// Record is one list item.
type Record struct {
	ID    string         `json:"id"`
	Hash  string         `json:"hash"`
	Data  map[string]any `json:"data"`
	Index int            `json:"-"` // position in the YAML list
}

// Note is free text declared in config.
type Note struct {
	Title      string `json:"title"`
	Text       string `json:"text"`
	Collection string `json:"-"`
}

// Collection is a loaded collection.
type Collection struct {
	*config.Collection
	Records   []*Record
	SchemaRaw json.RawMessage
	Schema    Schema
	byID      map[string]*Record
}

// Get returns the record with the given id.
func (c *Collection) Get(id string) *Record { return c.byID[id] }

// Ledger is the whole loaded ledger.
type Ledger struct {
	Config      *config.Config
	Collections []*Collection
	Notes       []Note
	Issues      []Issue // problems found while loading (yaml, config)
	overlay     map[string][]byte
	byName      map[string]*Collection
}

// Load reads every collection. It never fails outright: problems are
// collected in Issues so that `check` can report them. overlay replaces file
// contents (keyed by config-relative path) without touching the disk.
func Load(cfg *config.Config, overlay map[string][]byte) *Ledger {
	l := &Ledger{Config: cfg, byName: map[string]*Collection{}, overlay: map[string][]byte{}}
	for rel, b := range overlay {
		if abs, err := cfg.Resolve(rel); err == nil {
			l.overlay[abs] = b
		}
	}
	docs := map[string]*yamledit.Doc{}
	docErrs := map[string]error{}
	doc := func(rel string) (*yamledit.Doc, error) {
		if d, ok := docs[rel]; ok {
			return d, docErrs[rel]
		}
		b, err := l.ReadFile(rel)
		var d *yamledit.Doc
		if err == nil {
			d, err = yamledit.Parse(b)
			if err != nil {
				err = fmt.Errorf("%s: %w", rel, err)
			}
		}
		docs[rel], docErrs[rel] = d, err
		return d, err
	}
	reported := map[string]bool{}
	for _, cc := range cfg.Collections {
		c := &Collection{Collection: cc, byID: map[string]*Record{}}
		l.Collections = append(l.Collections, c)
		l.byName[cc.Name] = c
		l.loadSchema(c)
		l.loadRecords(c, doc, reported)
	}
	for _, n := range cfg.Notes {
		d, err := doc(n.File)
		if err != nil {
			l.Issues = append(l.Issues, Issue{Collection: n.Collection, Rule: RuleConfig, Message: "note " + strconv.Quote(n.Title) + ": " + err.Error()})
			continue
		}
		node, ok := d.Lookup(n.Path)
		if !ok || node.Kind != yaml.ScalarNode {
			l.Issues = append(l.Issues, Issue{Collection: n.Collection, Rule: RuleConfig, Message: fmt.Sprintf("note %q: %s has no text at %s", n.Title, n.File, n.Path)})
			continue
		}
		l.Notes = append(l.Notes, Note{Title: n.Title, Text: node.Value, Collection: n.Collection})
	}
	return l
}

// ReadFile reads a config-relative file, honouring the overlay.
func (l *Ledger) ReadFile(rel string) ([]byte, error) {
	abs, err := l.Config.Resolve(rel)
	if err != nil {
		return nil, err
	}
	if b, ok := l.overlay[abs]; ok {
		return b, nil
	}
	return os.ReadFile(abs)
}

func (l *Ledger) loadSchema(c *Collection) {
	raw, err := l.ReadFile(c.Collection.Schema)
	if err != nil {
		l.Issues = append(l.Issues, Issue{Collection: c.Name, Rule: RuleConfig, Message: "schema: " + err.Error()})
		return
	}
	c.SchemaRaw = raw
	s, err := ParseSchema(raw)
	if err != nil {
		l.Issues = append(l.Issues, Issue{Collection: c.Name, Rule: RuleConfig, Message: fmt.Sprintf("schema %s: %v", c.Collection.Schema, err)})
		return
	}
	c.Schema = s
}

func (l *Ledger) loadRecords(c *Collection, doc func(string) (*yamledit.Doc, error), reported map[string]bool) {
	d, err := doc(c.File)
	if err != nil {
		l.Issues = append(l.Issues, Issue{Collection: c.Name, Rule: RuleYAML, Message: err.Error()})
		return
	}
	if !reported[c.File] {
		reported[c.File] = true
		for _, dup := range d.Dups {
			l.Issues = append(l.Issues, Issue{Collection: c.Name, Rule: RuleYAML, Message: fmt.Sprintf("%s: line %d: duplicate mapping key %q", c.File, dup.Line, dup.Key)})
		}
	}
	list, err := d.Records(c.Path)
	if err != nil {
		rule := RuleYAML
		if errors.Is(err, yamledit.ErrPath) {
			rule = RuleConfig
		}
		l.Issues = append(l.Issues, Issue{Collection: c.Name, Rule: rule, Message: fmt.Sprintf("%s: %v", c.File, err)})
		return
	}
	for i := range list.Items {
		data, ok := list.Value(i).(map[string]any)
		if !ok {
			l.Issues = append(l.Issues, Issue{Collection: c.Name, ID: "#" + strconv.Itoa(i), Rule: RuleYAML, Message: "record is not a mapping"})
			continue
		}
		r := &Record{Data: data, Index: i}
		r.ID, r.Hash = ID(c.Collection, i, data), Hash(data)
		c.Records = append(c.Records, r)
		if _, dup := c.byID[r.ID]; !dup {
			c.byID[r.ID] = r
		}
	}
}

// Collection returns a collection by name, or nil.
func (l *Ledger) Collection(name string) *Collection { return l.byName[name] }

// ID computes the record id: the key field values, escaped and joined with
// "/"; "#<index>" when the collection has no key.
func ID(c *config.Collection, index int, data map[string]any) string {
	if len(c.Key) == 0 {
		return "#" + strconv.Itoa(index)
	}
	parts := make([]string, len(c.Key))
	for i, k := range c.Key {
		parts[i] = EscapeIDPart(Str(data[k]))
	}
	return strings.Join(parts, "/")
}

// EscapeIDPart escapes "%" and "/" inside one key value.
func EscapeIDPart(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	return strings.ReplaceAll(s, "/", "%2F")
}

// Hash is the first 16 hex chars of SHA-256 over the canonical JSON of data.
func Hash(data map[string]any) string {
	b, _ := json.Marshal(data) // map keys are sorted, no whitespace
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

// Str renders a value the way it is compared and displayed.
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// Match reports whether every where entry equals the record's field (compared as text).
func Match(r *Record, where map[string]string) bool {
	for k, want := range where {
		if Str(r.Data[k]) != want {
			return false
		}
	}
	return true
}

// AbsFile is the absolute path of the collection's YAML file.
func (l *Ledger) AbsFile(c *Collection) string {
	abs, _ := l.Config.Resolve(c.File)
	return abs
}
